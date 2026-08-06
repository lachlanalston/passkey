# Phishing twin — the attacker's-eye view

A deliberately fake copy of Passkey Lab that tries to use your passkey and gets nothing.

The lab's Step 5 already proves the block from inside the real page, by asking with the wrong
`rpId`. This twin adds the other half of the picture: what a phishing site sees when it tries.
Step 5 does **not** depend on it.

## Why it needs its own domain

A passkey is bound to a site's *registrable domain*. `evil.passkey.lrfa.dev` is still
`lrfa.dev`, so it would be treated as the same site and would prove nothing. The twin has to
be served from a genuinely different registrable domain.

The free option that fits the existing GitHub Pages deploy is a **user site**:
`github.io` is on the [Public Suffix List](https://publicsuffix.org/), so
`lachlanalston.github.io` is a different site from `lrfa.dev` as far as every browser is
concerned.

## Deploy

1. Create a public repo named exactly `lachlanalston.github.io`.
2. Copy the three files in this folder (`index.html`, `twin.js`, `twin.css`) to its root.
3. Settings → Pages → Source: `main` / root.
4. It is live at `https://lachlanalston.github.io/`.

Nothing here talks to a server. The CSP is the lab's, unchanged: `script-src 'self'`,
`connect-src 'none'`.

## Wire it into the lab

Set the URL in the lab's `config.js`:

```js
export const TWIN_URL = "https://lachlanalston.github.io/";
```

Step 5 then grows a secondary button, **Open the fake site**, which opens the twin with the
Step-1 credential ID and the lab's hostname in the URL fragment:

```
https://lachlanalston.github.io/#cred=<base64url-credential-id>&rp=passkey.lrfa.dev
```

Leave `TWIN_URL` empty and the button never appears. The in-page demo is unchanged either way.

Passing the credential ID is the point, not a leak: the credential ID is not secret, a real
relying party hands it out in `allowCredentials` on every sign-in, and holding it still gets
an attacker nothing. Demonstrating exactly that is the twin's whole job.

## What it does

Two attempts, the only two moves a phishing page has:

1. **Claim to be the real site** — passes `rpId: passkey.lrfa.dev` from a page that isn't it.
   The browser rejects it synchronously with `SecurityError`, before any prompt is shown.
2. **Ask honestly, as itself** — no `rpId`, so it defaults to the twin's own domain. The
   passkey isn't bound there, so the browser has nothing to offer.

Both fail, and the page says so: **"Nothing. The browser wouldn't even offer the passkey
here."**

## Keep it labelled

The page carries a permanent warning strip saying it is a training fake, and
`<meta name="robots" content="noindex, nofollow">`. Keep both. A convincing lookalike sign-in
page with no such labelling is a phishing page, whoever wrote it.
