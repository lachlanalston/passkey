# Passkey Lab

A static web app for testing and demoing WebAuthn passkeys. Create a passkey, save it to a wallet (LastPass, 1Password, Windows Hello, a phone, or a security key), sign in with it, and see how it works.

No backend. Nothing leaves the browser.

## Run locally

```bash
python3 -m http.server 8000
# open http://localhost:8000
```

WebAuthn needs HTTPS or `localhost`.

## Deploy (GitHub Pages)

Push to a repo, then Settings → Pages → Source: `main` / root. Passkeys bind to the site's domain.

## Notes

- Passkeys are tied to the domain that made them, so ones created on `localhost` won't work on your live site — make a fresh one after deploying.
- Data is stored in the browser only. Use **Clear list** to reset.
