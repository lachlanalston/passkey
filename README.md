# Passkey Lab

A static web app for seeing how WebAuthn passkeys actually work. Make one, use one, try to
steal one, and watch the challenge, signature and verification underneath every time.

Two ways in, chosen on first visit and remembered:

- **Guided lab** — six steps, one at a time: create, sign in, do it from a phone, break it on
  purpose, run a real phishing attempt against yourself, clean up. Each step ends in a
  **Ceremony X-ray** of what just happened, and a note on where the same thing shows up in
  Microsoft Entra.
- **The bench** — free-form testing. Every WebAuthn option exposed, a live trace, real
  signature verification, a raw inspector, and five demos of why passkeys hold.

No backend. No build step. Nothing leaves the browser.

## Run locally

```bash
python3 -m http.server 8000   # or: npm run serve
# open http://localhost:8000
```

WebAuthn needs HTTPS or `localhost`.

## Deploy (GitHub Pages)

Push to a repo, then Settings → Pages → Source: `main` / root. Passkeys bind to the site's
domain, so a passkey made on `localhost` will not work on the live site — make a fresh one
after deploying.

## How it fits together

The site ships as authored ES modules. There is no bundler and no framework, and the strict
CSP (`script-src 'self'`, `connect-src 'none'`) means no CDNs and no network calls at all.

| File | What it is |
|---|---|
| `core.js` | Pure helpers: base64url, `parseAuthData`, CBOR/COSE decoding, DER↔raw ECDSA, and `verifyBytes`. No DOM, no storage, no `navigator.credentials` — this is the unit-tested layer. |
| `ceremonies.js` | The WebAuthn calls, parameterised: `registerPasskey`, `signIn`, `getAssertion`, `runPhishing`. Touches storage, never the DOM. |
| `xray.js` | The Ceremony X-ray — presentation over the decoders in `core.js`. |
| `training.js` | The six-step guided rail. |
| `ui.js` | Shared pieces: error translation, the record card, the per-OS cleanup list, modal and inspector builders. |
| `mode.js` | Which way in, and remembering it. |
| `app.js` | The bench, and the wiring. |
| `config.js` | `TWIN_URL` — set it only if the phishing twin is deployed. |
| `phishing-twin/` | An optional fake site for the attacker's-eye view. Needs its own domain; **not deployed by default**. See its README. |

Stored in `localStorage`, and nowhere else:

- `passkey-lab-creds` — credential IDs, public keys and metadata. Never private keys.
- `passkey-lab-mode` — bench or guided lab.
- `passkey-lab-training` — progress through the six steps.

## Tests

Dev-only. Nothing in `package.json` touches the files that ship.

```bash
npm install
npx playwright install chromium

npm test          # Vitest — core.js, in Node
npm run test:e2e  # Playwright — Chromium with a CDP virtual authenticator
npm run test:all
```

The unit suites sign with real WebCrypto keys and check the real verification result. The E2E
suites drive the whole app — the rail end to end, the bench, the X-ray, the layout matrix,
capability notices, and the phishing block.

`MANUAL-TESTS.md` covers what a virtual authenticator cannot: a real phone over QR, the
Bluetooth-off failure and recovery, LastPass, the deployed twin, and how it all reads on a
projector. Run it before a training session.

## Notes

- A lab passkey is a real passkey. **Clear list** wipes only this site's records — the passkey
  stays in your device's store until you delete it there. The cleanup footer tells you where.
- Signatures are verified in-browser for teaching. A production relying party verifies
  server-side against the registered public key.
