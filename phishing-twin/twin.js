// The fake site. Deliberately hostile, deliberately useless.
//
// Two attempts, which are the only two things a phishing page can do:
//   1. Ask honestly, as itself. The passkey isn't bound to this domain, so nothing is offered.
//   2. Lie, and claim to be the real site. The browser blocks it outright, before any prompt.
// Both fail. That is the entire demonstration.

const $ = (id) => document.getElementById(id);
const params = new URLSearchParams(location.hash.slice(1));
const credId = params.get("cred") || "";
const realHost = params.get("rp") || "passkey.lrfa.dev";

const b64urlDecode = (str) => {
  str = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
};
const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

$("fake-origin").textContent = location.origin;
$("real-host").textContent = realHost;
$("back").href = `https://${realHost}/`;
if (credId) $("cred-id").textContent = credId.slice(0, 28) + (credId.length > 28 ? "…" : "");

function row(k, v, mark) {
  return `<div class="row ${mark || ""}"><dt>${esc(k)}</dt><dd>${v}</dd></div>`;
}

function render(attempts, done) {
  $("out").innerHTML = `
    <div class="result">
      ${done ? `<span class="verdict">Nothing. The browser wouldn't even offer the passkey here.</span>` : ""}
      <dl class="rows">${attempts.join("")}</dl>
      ${done ? `<p class="cause">
        A passkey is sealed to the domain it was made on. The browser — not the user, not this
        page — checks that seal on every request, and refuses before anything is displayed.
        So a lookalike site has nothing to steal and nothing to relay: no key, no signature,
        not even a prompt to trick someone through. This is why a passkey cannot be phished,
        and why <strong>${esc(realHost)}</strong> is safe from this page no matter how
        convincing it looks.</p>` : ""}
    </div>`;
}

let allowCredentials = [];
if (credId) {
  try { allowCredentials = [{ type: "public-key", id: b64urlDecode(credId) }]; }
  catch { allowCredentials = []; }
}

async function attemptAsItself() {
  // No rpId given, so it defaults to this page's own domain — the honest version of the ask.
  try {
    await navigator.credentials.get({
      publicKey: { challenge: randomBytes(32), allowCredentials, userVerification: "preferred", timeout: 12000 },
    });
    return { ok: true, detail: "the browser released a credential (this should not happen)" };
  } catch (err) {
    return { ok: false, detail: `${err.name} — nothing offered` };
  }
}

async function attemptAsTheRealSite() {
  // Claiming someone else's rpId: the browser rejects this synchronously, before any UI.
  try {
    await navigator.credentials.get({
      publicKey: { challenge: randomBytes(32), rpId: realHost, allowCredentials, userVerification: "preferred", timeout: 12000 },
    });
    return { ok: true, detail: "the browser released a credential (this should not happen)" };
  } catch (err) {
    return { ok: false, detail: `${err.name} — blocked before any prompt` };
  }
}

$("btn-steal").addEventListener("click", async () => {
  const btn = $("btn-steal");
  btn.disabled = true;
  btn.textContent = "Trying…";

  const attempts = [];
  attempts.push(row("Attempt 1 — claim to be " + realHost, "running…"));
  render(attempts, false);

  const lie = await attemptAsTheRealSite();
  attempts[0] = row(`Attempt 1 — claim to be ${realHost}`, esc(lie.detail), lie.ok ? "bad" : "ok");
  attempts.push(row(`Attempt 2 — ask honestly, as ${location.hostname}`, "running…"));
  render(attempts, false);

  const honest = await attemptAsItself();
  attempts[1] = row(`Attempt 2 — ask honestly, as ${location.hostname}`, esc(honest.detail), honest.ok ? "bad" : "ok");
  attempts.push(row("What this page now holds", "nothing — no key, no signature, no session", "ok"));
  render(attempts, true);

  btn.disabled = false;
  btn.textContent = "Try again";
});
