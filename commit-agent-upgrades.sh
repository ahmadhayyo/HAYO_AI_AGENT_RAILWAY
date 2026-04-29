#!/bin/bash
# Run this script from the HAYO_AI_AGENT_RAILWAY directory to commit the agent upgrades

cd "$(dirname "$0")"

echo "=== Removing stale git lock ==="
rm -f .git/index.lock

echo "=== Resetting APK bypass code (not committing) ==="
git checkout -- artifacts/api-server/src/hayo/services/reverse-engineer.ts
git checkout -- artifacts/api-server/src/routes/reverse.ts

echo "=== Staging agent upgrades ==="
git add artifacts/api-server/src/hayo/services/ai-agent.ts

echo "=== Committing ==="
git commit -m "feat: 5 major upgrades to streaming AI agent

- UPGRADE 1: executeBashInProject uses spawnSync (proper stderr, timeout)
             + buildShellEnv() injects node_modules/.bin from all workspaces
- UPGRADE 2: getTrpcSnapshot() — live tRPC procedure list injected into system prompt
- UPGRADE 3: compressContext() — Haiku-based summarisation when messages > 16
             prevents context window overflow on long tasks
- UPGRADE 4: deterministicReview() — regex-based exit code + pattern reviewer
             replaces unreliable LLM-based review
- UPGRADE 5: trackFileChanges() — Map-based file size snapshots, reports
             created/modified files in done signal

Also: fix duplicate spawnSync import (was mid-file at line 297, moved to top)
      replace unused execSync import with spawnSync"

echo ""
echo "=== Done! Push with: git push origin main ==="
