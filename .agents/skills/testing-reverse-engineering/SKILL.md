---
name: testing-reverse-engineering
description: Test the reverse engineering page tool detection, APK auditor integration, and RE tool panel. Use when verifying changes to tool detection, /check-tools API, or the RE page frontend.
---

# Testing Reverse Engineering Page

## Architecture

- **Frontend**: `artifacts/hayo-ai/src/pages/ReverseEngineer.tsx` (main) and `ReverseEngineer-export.tsx` (export variant)
- **Backend service**: `artifacts/api-server/src/hayo/services/reverse-engineer.ts`
- **Backend routes**: `artifacts/api-server/src/routes/reverse.ts`
- **APK Auditor script**: `scripts/apk_auditor.py`
- **API endpoint**: `/api/reverse/check-tools` — returns tool availability for frontend display

## Critical: Two Response Formats

The backend has TWO tool status functions:
1. `getToolStatus()` — returns structured `{ toolName: { available: boolean, version?: string } }` — used internally
2. `getToolStatusFlat()` — returns flat `{ toolNameAvailable: boolean, toolNameVersion: string|null }` — used by `/check-tools` endpoint for frontend

**The frontend expects the FLAT format.** If someone changes `/check-tools` to call `getToolStatus()` instead of `getToolStatusFlat()`, all tools will show as unavailable in the UI even if they're installed. This was the root cause of a prior bug.

## Build Commands

```bash
# Frontend build
pnpm --filter @workspace/hayo-ai run build

# Backend build  
pnpm --filter @workspace/api-server run build
```

Frontend chunk size warnings are pre-existing and expected.

## Testing Without Full App

The app requires `DATABASE_URL` and AI API keys to fully run. Without these, testing is shell-based:

1. **Replicate tool detection logic** in a standalone `.mjs` script that mirrors `getToolStatusFlat()` logic
2. **Verify key presence**: All keys referenced in frontend tool arrays must exist in the flat response
3. **Verify installed tools**: Java, keytool, jarsigner, strings, objdump, readelf, python3, xxd, nm should return `true` in the dev environment
4. **Cross-reference frontend keys**: Extract keys from `ReverseEngineer.tsx` tool arrays and verify no orphan keys
5. **Check ALLOWED_CMDS**: New tools must be added to the `ALLOWED_CMDS` Set in `reverse.ts` (~line 1034) or SSE execution will reject them

## Tools Installed in Dev Environment vs Docker

**Available in dev env**: java, keytool, jarsigner, xxd, strings, objdump, readelf, python3, unzip, nm, strace

**Only available in Docker (Railway)**: apktool, jadx, zipalign, apksigner, wasm2wat, file, binwalk, ltrace, upx, aapt, dex2jar, radare2

Tools only in Docker will correctly return `false` during local testing — this is expected.

## APK Auditor Script Testing

The Python script (`scripts/apk_auditor.py`) can be tested with mock data:
- Create mock `.smali`, `.xml`, `.json` files with planted secrets
- Test secret discovery (16 regex patterns)
- Test smali patching (guard method modifications)
- Test keystore generation with `keytool`
- apktool/zipalign/apksigner won't work locally — test error handling paths

## Devin Secrets Needed

- `DATABASE_URL` — PostgreSQL connection string (needed for full app testing)
- `EXPO_ACCESS_TOKEN` — for app builder section (not needed for RE page testing)
- AI API keys (various) — for AI features (not needed for RE tool detection testing)

## Key Gotchas

- The `__dirname` in esbuild bundles resolves differently than in source. Backend uses `process.cwd()` for script paths.
- `ReverseEngineer.tsx` and `ReverseEngineer-export.tsx` must stay in sync — same tool keys in both.
- Dockerfile tool downloads use `|| echo "WARNING: ..."` for fault tolerance — a failed download won't break the build.
- The `better-sqlite3` typecheck error exists on `main` and is pre-existing — not caused by RE changes.
