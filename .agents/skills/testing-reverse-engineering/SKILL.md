# Testing: HAYO AI Reverse Engineering — Cloner Tab

## Overview
The Cloner tab in the Reverse Engineering page (`/reverse`) provides automated APK modification and security analysis. Testing requires running both frontend and backend servers locally with a test APK.

## Environment Setup

### Prerequisites
- Node.js 22+ (via nvm)
- pnpm (install via `npm i -g pnpm`)
- APK tools: `apktool`, `zipalign`, `apksigner`, `keytool` (install via `sudo apt install -y apktool zipalign apksigner default-jdk`)

### Starting Servers
```bash
# Backend (Express + tRPC on port 8080)
cd /home/ubuntu/repos/HAYO_AI_AGENT_RAILWAY/artifacts/api-server
pnpm install
pnpm dev  # runs on port 8080

# Frontend (Vite on port 23836)
cd /home/ubuntu/repos/HAYO_AI_AGENT_RAILWAY/artifacts/hayo-ai
pnpm install
pnpm dev  # runs on port 23836
```

### Database
- When `DATABASE_URL` is not set, the backend falls back to SQLite at `artifacts/api-server/hayo-ai.db`
- The SQLite fallback may cause issues with some Drizzle ORM functions (e.g., `now()` not available in SQLite)
- For testing, SQLite fallback is sufficient

### Authentication
- Create a test user via the SQLite DB or registration endpoint
- Login: POST to `/api/auth/login` with `{email, password}`
- Password hash: `sha256(password + sha256(password + "hayo-salt"))`
- Auth cookie: `app_session_id` (JWT)
- For browser testing, log in via the UI at `/` before navigating to `/reverse`

## Creating a Test APK

A minimal test APK can be built with apktool. The APK should contain:

1. **AndroidManifest.xml** with a valid package name (e.g., `com.example.testapp`)
2. **Smali files** with patchable methods:
   - Boolean methods: `isPremium()`, `isSubscribed()`, `isTrialExpired()`, `checkLicense()` returning 0x0 or 0x1
   - Integer methods: `getCoins()`, `getDailyLimit()` returning small values
3. **Test secrets** embedded in resource files:
   - Firebase key (`AIzaSy...`) in strings.xml
   - AWS key (`AKIA...`) in strings.xml
   - Stripe key (`sk_live_...`) in strings.xml
   - GitHub token (`ghp_...`) in assets/config.json
   - JWT token (`eyJ...`) in assets/config.json
4. **Test endpoints** in resource files:
   - HTTP(S) URLs for endpoint discovery testing

Build with: `apktool b <dir> -o test-app.apk`

## Test Procedure

1. Navigate to `http://localhost:23836/reverse`
2. Click the "استنساخ" (Clone) tab
3. Upload the test APK via drag-drop or file picker
4. Configure toggle options (removeAds, unlockPremium, bypassTrial, extractSecrets, etc.)
5. Click "استنساخ الآن" (Clone Now)
6. Verify SSE streaming shows all 7 phases
7. Check result panels: modifications log, verification cards, secrets, endpoints, audit report, Frida script
8. Test download button for modified APK

## Common Issues & Workarounds

- **File upload in automated testing:** Use Playwright CDP connection (`chromium.connectOverCDP('http://localhost:29229')`) to interact with file input elements programmatically. Use ES module syntax (`.mjs`) with full path to playwright module.
- **ZIP integrity verification:** The `unzip -t` quality gate may fail for minimal test APKs rebuilt by apktool. This might not occur with real-world APKs. `apksigner verify` should still pass.
- **Chrome APK download blocking:** Chrome flags APK downloads as "Unverified download blocked" — this is expected browser security behavior, not a bug.
- **Toggle state detection:** Toggle buttons use CSS classes to indicate state. Active (ON) = `bg-violet-500/10 border-violet-500/40`, Inactive (OFF) = `bg-card/70 border-border`. Check via `element.className.includes('violet')`.
- **Pre-existing build errors:** The project may have TypeScript errors in files like `AIAgent.tsx`. These might need temporary fixes (e.g., commenting out problematic imports) to get the dev server running. Only fix what's needed for testing.
- **SQLite `now()` error:** If Drizzle ORM operations fail with `now()` function errors, it's because SQLite doesn't support PostgreSQL's `now()`. The backend has fallback handling for this.

## Key UI Elements (Arabic)

| Arabic | English | Function |
|--------|---------|----------|
| استنساخ | Clone | Tab name |
| استنساخ الآن | Clone Now | Start button |
| إزالة الإعلانات | Remove Ads | Toggle |
| فتح المدفوع | Unlock Premium | Toggle |
| تجاوز الرخصة | Bypass License | Toggle |
| تجاوز التجريب | Bypass Trial | Toggle |
| استخراج الأسرار | Extract Secrets | Toggle |
| التحقق من الجودة | Quality Gate | Verification section |
| تقرير التدقيق الأمني | Audit Report | Report panel |
| النقاط النهائية المكتشفة | Discovered Endpoints | Endpoints panel |
| تحميل APK المعدّل | Download Modified APK | Download button |

## Devin Secrets Needed
- No secrets required for local testing with SQLite fallback
- For production testing: `DATABASE_URL` (PostgreSQL connection string)
- For app building features: `EXPO_ACCESS_TOKEN`
