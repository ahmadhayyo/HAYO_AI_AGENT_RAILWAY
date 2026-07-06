/**
 * Self-Deploy Bridge — HAYO AI (owner-only)
 * ─────────────────────────────────────────────────────────────────────────────
 * The Executive AI Agent and System Maintenance can edit the platform's own
 * source files on the running container. But Railway's runtime filesystem is
 * ephemeral (changes vanish on restart) AND has no `.git` (excluded by
 * .dockerignore), and the app serves a *built* bundle — so a local edit never
 * goes live on its own.
 *
 * This module is the GUARDED bridge that makes an edit real: it records which
 * files the owner-only tools changed ("staged"), lets the owner review them,
 * and — only on explicit owner action — commits them to GitHub via the REST API
 * (no local git needed) which triggers Railway's auto-deploy.
 *
 * Safety model:
 *   1. Owner-only (adminProcedure) at the router layer.
 *   2. Path-sandboxed to the project root (no writing outside the repo).
 *   3. Nothing deploys without an explicit owner "Commit & Deploy" action.
 *   4. Railway builds the new commit and only swaps traffic if the build
 *      SUCCEEDS — a broken commit fails to deploy and the live site keeps
 *      running the previous version. The build itself is the final gate.
 */
import fs from "fs";
import path from "path";

const PROJECT_ROOT = path.resolve(process.cwd(), "../..");
const GITHUB_REPO = process.env.GITHUB_REPO || "ahmadhayyo/HAYO_AI_AGENT_RAILWAY";
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || "main";

type StageAction = "write" | "delete";
interface StageMeta { action: StageAction; at: number; description?: string; }

// Session-scoped registry of repo-relative paths the owner tools have changed,
// pending review + deploy. Lives in the api-server process (same process the
// agent/maintenance write from), so staging is synchronous and reliable.
const staged = new Map<string, StageMeta>();

function norm(relPath: string): string {
  return relPath.replace(/\\/g, "/").replace(/^\/+/, "");
}

/** Record that an owner tool wrote or deleted a repo file (pending deploy). */
export function stageChange(relPath: string, action: StageAction, description?: string): void {
  staged.set(norm(relPath), { action, at: Date.now(), description });
}

export function clearStaged(): void {
  staged.clear();
}

function resolveSafe(fp: string): string | null {
  if (fp.startsWith("/")) return null;
  const resolved = path.resolve(path.join(PROJECT_ROOT, fp));
  const rel = path.relative(PROJECT_ROOT, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) return null;
  return resolved;
}

export interface PendingFile {
  filePath: string;
  action: StageAction;
  size: number;
  exists: boolean;
  at: number;
  description?: string;
}

/** The current pending changeset, with on-disk status for each entry. */
export function getPending(): PendingFile[] {
  return [...staged.entries()].map(([filePath, meta]) => {
    const abs = resolveSafe(filePath);
    let size = 0;
    let exists = false;
    if (abs && meta.action === "write") {
      try {
        const st = fs.statSync(abs);
        size = st.size;
        exists = st.isFile();
      } catch { /* vanished */ }
    }
    return { filePath, action: meta.action, size, exists, at: meta.at, description: meta.description };
  }).sort((a, b) => a.filePath.localeCompare(b.filePath));
}

function ghToken(): string {
  const t = process.env.GITHUB_TOKEN;
  if (!t) throw new Error("GITHUB_TOKEN غير مُعرّف في بيئة Railway — أضِفه في Variables أولاً.");
  return t;
}

async function gh(endpoint: string, init?: { method?: string; body?: string }): Promise<any> {
  const url = endpoint.startsWith("http")
    ? endpoint
    : `https://api.github.com/repos/${GITHUB_REPO}${endpoint}`;
  const res = await fetch(url, {
    method: init?.method || "GET",
    body: init?.body,
    headers: {
      "Authorization": `token ${ghToken()}`,
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "HAYO-SelfDeploy",
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status} ${endpoint}: ${body.slice(0, 300)}`);
  }
  return res.json();
}

export interface DeployResult {
  committed: number;
  commitUrl: string;
  sha: string;
  branch: string;
}

/**
 * Commit every staged change to `GITHUB_BRANCH` in one commit via the GitHub
 * REST API (blobs → tree → commit → update ref). Pushing to the deploy branch
 * triggers Railway's rebuild. On success the registry is cleared.
 */
export async function commitAndDeploy(message: string): Promise<DeployResult> {
  const list = [...staged.entries()];
  if (list.length === 0) throw new Error("لا توجد تغييرات مُعلّقة للنشر.");

  // 1. Latest commit on the branch + its base tree.
  const ref = await gh(`/git/ref/heads/${GITHUB_BRANCH}`);
  const latestSha: string = ref.object.sha;
  const latestCommit = await gh(`/git/commits/${latestSha}`);
  const baseTree: string = latestCommit.tree.sha;

  // 2. Build the new tree: a blob per written file, sha:null to delete.
  const treeEntries: Array<{ path: string; mode: "100644"; type: "blob"; sha: string | null }> = [];
  for (const [filePath, meta] of list) {
    if (meta.action === "delete") {
      treeEntries.push({ path: filePath, mode: "100644", type: "blob", sha: null });
      continue;
    }
    const abs = resolveSafe(filePath);
    if (!abs || !fs.existsSync(abs)) continue; // written then removed — skip
    const buf = fs.readFileSync(abs);
    const blob = await gh(`/git/blobs`, {
      method: "POST",
      body: JSON.stringify({ content: buf.toString("base64"), encoding: "base64" }),
    });
    treeEntries.push({ path: filePath, mode: "100644", type: "blob", sha: blob.sha });
  }
  if (treeEntries.length === 0) throw new Error("لا توجد ملفات صالحة للنشر.");

  // 3. Tree → 4. Commit → 5. Move the branch ref forward.
  const tree = await gh(`/git/trees`, {
    method: "POST",
    body: JSON.stringify({ base_tree: baseTree, tree: treeEntries }),
  });
  const commit = await gh(`/git/commits`, {
    method: "POST",
    body: JSON.stringify({ message, tree: tree.sha, parents: [latestSha] }),
  });
  await gh(`/git/refs/heads/${GITHUB_BRANCH}`, {
    method: "PATCH",
    body: JSON.stringify({ sha: commit.sha }),
  });

  clearStaged();
  return {
    committed: treeEntries.length,
    commitUrl: commit.html_url || `https://github.com/${GITHUB_REPO}/commit/${commit.sha}`,
    sha: commit.sha,
    branch: GITHUB_BRANCH,
  };
}
