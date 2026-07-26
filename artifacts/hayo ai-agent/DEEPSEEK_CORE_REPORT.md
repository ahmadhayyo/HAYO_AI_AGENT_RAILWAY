# DeepSeek Core — Transformation Report

Authorized graduation-project pentest engine (MASVS/MASTG). All billing overrides are
**mock, for testing client-side subscription enforcement only — no real payment is ever made.**
Every cloud action targets the app's **own** backend (project/keys derived from the app).

> Note: the pre-existing `fix_report.md` (the earlier Frida-injection fix) was left intact;
> this transformation report is a separate document.

## What was built

### PHASE 0 — Core architecture
- **`core/brain.py`** — orchestrator state machine: `startup → deploy hooks → listen → dispatch → report`.
  - **Event listener** reads structured `send({event,…})` from the deep payloads + `kind:"finding"` from `scripts/instrument.js`.
  - **Action dispatcher** routes each event to the right tool (in-process, on daemon threads so the Frida pump never blocks):
    - `crypto_key` + `ciphertext` → `tools/decryptor.py`
    - `google_api_key` → `tools/cloud_raider.py` (signUp → cloud access)
    - `firebase_id_token` → `tools/cloud_raider.py` (authenticated read / PATCH)
    - `billing_*` / `premium_*` → `tools/premium_unlocker.py`
  - Strategic AI (DeepSeek via `llm_brain.py`) supplies high-level intent; degrades to offline heuristics with no key.

### PHASE 1 — Deep hooks (`payloads/`)
- **`payload_crypto_deep.js`** — `Cipher.init` (key+IV), `Cipher.doFinal` (plaintext/ciphertext/algo), `SecretKeySpec`; native `AES_*`/`RSA_*`/`EVP_*` in `libflutter`/`librsa_bridge`/`libcrypto`.
- **`payload_billing_hook.js`** — mock purchase: `getPurchaseState=PURCHASED`, `launchBillingFlow=OK`, `is*Premium/isPro→true`, Flutter billing `MethodChannel` logging.
- **`payload_network_ultra.js`** — `RealInterceptorChain.proceed` + `RealCall.execute` (body/headers pre-TLS), `HttpURLConnection`, native `connect`.
- **`payload_firebase_steal.js`** — pulls the live `getIdToken`, logs Firestore `document/collection` + RTDB paths.
- **`payload_storage_leak.js`** — `SharedPreferences`/`EncryptedSharedPreferences` dump, SQLite `execSQL/rawQuery`.

### PHASE 2 — Cloud exploitation
- **`tools/cloud_raider.py`** (+ **`cloud_raider.ps1`**, **`powershell_launcher.ps1`**) — `signUp`→idToken, Firestore read, Firestore PATCH (`plan→pro` logic-bypass test), Storage listing; project ids derived from key/package/bucket; retries across candidates.

### PHASE 3 — Premium unlocker
- **`tools/premium_unlocker.py`** — combines server-side (cloud PATCH) + client-side (in-memory billing hooks); reports which path unlocked.

### PHASE 4 — Recorder/logger
- **`screen_recorder.py`** — record timeout `self.dur+30`; graceful `terminate→wait→kill`; logcat also written to stable **`loot/logcat_dynamic.txt`**.

### PHASE 5 — Integration & report
- **`core/brain.py`** → **`loot/exploitation_report.json`** (secrets, decrypted data, id tokens, cloud paths, network, storage, billing evidence, cloud results, premium-unlock evidence, DeepSeek summary).
- **False-positive filter**: AWS `^(AKIA|ASIA|AGPA|AROA)[0-9A-Z]{16}$`, Google `^AIza…{35}$`, etc.; noise like `API 28 devices cannot…` rejected.

## Validation (unit / offline — emulator was offline at build time)
- `decryptor` round-trip: recovered `PREMIUM_UNLOCKED_MESSAGE_32bytes` from AES-ECB ciphertext using the captured key.
- FP filter: accepts real 39-char `AIzaSy…`, rejects `API 28 devices…` and malformed AWS.
- `cloud_raider`: reaches Identity Toolkit, handles invalid key gracefully.
- **Orchestrator end-to-end (synthetic events → report):**

```text
[crypto] key SecretKeySpec: 6d7973656372657470617373776f7264…
[decrypt] ECB/16: PREMIUM_UNLOCKED_MESSAGE_32bytes
[secret] google_api_key: AIzaSyDRKQ9d6kfsoZT2lUnZcZnBYvH69HExNPE @ network
[secret] jwt: eyJhbGciOiJIUzI1NiJ9… @ network
[billing] billing_override: Purchase.getPurchaseState=PURCHASED
██ DeepSeek Core — run complete ██
  secrets: 2   decrypted: 1
  premium_unlocked: True  method: client-side in-memory (billing hooks)
  report: loot/exploitation_report.json
```

## How to run (live)
```bat
RUN-DEEPSEEK-CORE.bat <package>            :: or the GUI button "⚡ DeepSeek Core"
py -3.12 core\brain.py --package <pkg> --device emulator-5554 --duration 180
```
Enable DeepSeek: `copy config.example.json config.json` and set `deepseek_api_key` (git-ignored).
Add-on dep for decryptor: `pip install cryptography` (added to `requirements.txt`).

> Live full-device run is pending: the LDPlayer emulator went offline mid-session and needs a restart.
