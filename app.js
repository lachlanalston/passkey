// Passkey Lab — the bench.
// Create passkeys, save to a wallet, test sign-in, verify the signature in-browser,
// and demonstrate WHY it's secure (phishing block, tamper test, plain-English trace).
// Decoding and verification live in core.js; the WebAuthn calls live in ceremonies.js.

import {
  b64urlEncode, b64urlDecode, randomBytes, esc,
  parseAuthData, syncLabel, decodeClientData, spkiToPem, verifyBytes, verifyAssertion,
  cborDecode, derRS, algName,
} from "./core.js";

import {
  STORE_KEY, loadCreds, saveCreds, rpId, credsForSite,
  registerPasskey, signIn, getAssertion, runPhishing,
} from "./ceremonies.js";

import { getMode, setMode, clearMode, showView, refreshLandingPrimary, initialView } from "./mode.js";
import { renderTraining } from "./training.js";
import {
  section, rows, hexPre, buildAuthDataSection, openModal, closeModal, trapModalTab,
  openRecordCard, cleanupListHtml, translateError, isFirefoxOnLinux,
} from "./ui.js";
import { xrayHtml, wireXray } from "./xray.js";

const $ = (id) => document.getElementById(id);

function log(msg, obj) {
  const el = $("log");
  const time = new Date().toLocaleTimeString();
  el.textContent += `[${time}] ${msg}\n`;
  if (obj !== undefined) el.textContent += JSON.stringify(obj, null, 2) + "\n";
  el.textContent += "\n";
  el.scrollTop = el.scrollHeight;
}

// Plain-language summary for the training audience. tone: ok | warn | bad
function explain(text, tone = "ok") {
  const el = $("explain");
  el.hidden = false;
  el.className = "explain explain-" + tone;
  el.textContent = text;
}

// Structured result card for the "Prove it" demos — makes the CAUSE explicit.
// data: { tone, verdict, title, rows:[{k, v, mark}], cause }
function renderProve(data) {
  const el = $("prove-out");
  el.hidden = false;
  el.className = "prove-out prove-" + data.tone;
  const rows = data.rows.map((r) =>
    `<div class="prow ${r.mark || ""}"><dt>${r.k}</dt><dd>${r.v}</dd></div>`).join("");
  el.innerHTML =
    `<span class="verdict verdict-${data.tone}">${data.verdict}</span>` +
    `<h3>${data.title}</h3>` +
    `<dl class="prove-rows">${rows}</dl>` +
    `<p class="cause">${data.cause}</p>`;
}

let lastAssertion = null; // populated on each successful sign-in, for the inspector
let lastCeremony = null;  // { kind, res } — whichever ran most recently, for the X-ray

// ---------- environment ----------
// The gauges say what is and isn't available; the notices say what to do about it, next to
// the control it affects.
async function detectEnv() {
  $("origin").textContent = location.origin;
  $("rpid").textContent = location.hostname || "(none — serve over http/https)";
  $("secure").textContent = window.isSecureContext ? "Yes" : "No (needs HTTPS or localhost)";
  const supported = !!(window.PublicKeyCredential && navigator.credentials);
  $("webauthn").textContent = supported ? "Yes" : "No";

  let platform = null, condui = null;
  if (supported && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    try { platform = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch { platform = null; }
  }
  $("platform").textContent = platform === null ? "Unknown" : platform ? "Available" : "Not available";

  if (supported && PublicKeyCredential.isConditionalMediationAvailable) {
    try { condui = await PublicKeyCredential.isConditionalMediationAvailable(); } catch { condui = null; }
  }
  $("condui").textContent = condui === null ? "Unknown" : condui ? "Available" : "Not available";

  renderNotices({ supported, platform, condui });
}

const noticeHtml = (text, tone = "warn") =>
  `<p class="notice notice-${tone}">${esc(text)}</p>`;

function renderNotices({ supported, platform, condui }) {
  const reg = [], auth = [];

  if (!supported) {
    reg.push(noticeHtml("This browser doesn't support passkeys. Chrome, Edge or Safari will.", "bad"));
    auth.push(noticeHtml("This browser doesn't support passkeys. Chrome, Edge or Safari will.", "bad"));
  } else {
    if (platform === false) {
      reg.push(noticeHtml("No built-in authenticator here — you'll be offered a phone or security key instead."));
    }
    if (isFirefoxOnLinux()) {
      reg.push(noticeHtml("Firefox on Linux can't do the phone/QR flow — a Firefox gap, not you. Chrome or Edge can."));
    }
    if (condui === false) {
      $("btn-autofill").disabled = true;
      auth.push(noticeHtml("Autofill sign-in needs conditional mediation, which this browser doesn't offer — use “Sign in with passkey” instead."));
    }
  }

  $("notice-reg").innerHTML = reg.join("");
  $("notice-auth").innerHTML = auth.join("");
}

// On the bench the raw name is part of what is being taught, so it rides along in brackets.
const benchError = (err) => `${translateError(err)} (${err.name})`;

// ---------- registration (bench wrapper over registerPasskey) ----------
async function createPasskey() {
  try {
    const res = await registerPasskey({
      username: $("username").value,
      displayName: $("displayname").value,
      attachment: $("attachment").value,
      residentKey: $("residentkey").value,
      userVerification: $("userverification").value,
      attestation: $("attestation").value,
      onRequest: (req) => log("navigator.credentials.create() request", req),
    });
    const { record, ms, flags, clientData: cd, echoed } = res;
    lastCeremony = { kind: "registration", res };
    renderTable();

    log(`Passkey created (${ms} ms)`, {
      credentialId: record.id,
      wallet: record.wallet || "(unknown — no attestation AAGUID)",
      aaguid: record.aaguid,
      transports: record.transports,
      authenticatorAttachment: record.authenticatorAttachment,
      sync: flags.aaguid !== undefined ? syncLabel(flags) : "unknown",
      flags: { UP: flags.userPresent, UV: flags.userVerified, BE: flags.backupEligible, BS: flags.backupState },
      signCount: flags.signCount,
      publicKeyStored: !!record.publicKey,
      clientData: { type: cd.type, origin: cd.origin, challengeEchoed: echoed },
    });

    const wallet = record.wallet && !record.wallet.startsWith("Unknown") ? record.wallet : "the authenticator";
    const port = flags.backupEligible
      ? "It is a synced passkey — it backs up and appears on your other signed-in devices."
      : "It is device-bound — it lives only on this authenticator and cannot sync.";
    explain(`Created a passkey for "${record.username}" on ${record.rpId}, stored in ${wallet}. ${port} The public key is now saved here; the private key never left the authenticator.`, "ok");
  } catch (err) {
    if (err.name === "InvalidStateError") {
      log("WARNING — this authenticator already holds a passkey for this account (excludeCredentials blocked a duplicate).");
      explain(benchError(err), "warn");
    } else {
      log("ERROR — registration failed: " + err.name + " — " + err.message);
      explain(benchError(err), "bad");
    }
  }
}

// ---------- authentication (bench wrapper over signIn) ----------
async function authenticate(mediation = "optional") {
  const mode = $("allowmode").value;
  const useStored = mode === "stored" && mediation !== "conditional";

  try {
    const res = await signIn({
      allowIds: useStored ? credsForSite().map((c) => c.id) : null,
      userVerification: $("userverification").value,
      mediation: mediation === "conditional" ? "conditional" : undefined,
      onRequest: (req) => log(`navigator.credentials.get() request (mediation: ${mediation})`, req),
    });

    if (res.none) {
      log("WARNING — no stored passkeys for this site. Create one, or switch Match to 'Any'.");
      explain("No passkeys are stored for this site yet. Create one in step 1 first.", "warn");
      return;
    }

    const { record, ms, flags, clientData: cd, verify, echoed, raw } = res;
    lastAssertion = { record, authData: raw.authData, clientDataJSON: raw.clientDataJSON, signature: raw.signature, id: res.id };
    lastCeremony = { kind: "authentication", res };
    if (record) renderTable();

    log((verify.ok === true ? `OK — sign-in verified (${ms} ms, signature valid)` :
         verify.ok === false ? "FAILED — signature INVALID" :
         `OK — sign-in ceremony completed (${ms} ms, not verified: ${verify.reason})`), {
      credentialId: res.id,
      matchedStored: !!record,
      wallet: record?.wallet || "unknown",
      userHandle: res.userHandle,
      signatureValid: verify.ok,
      verifyAlg: verify.reason,
      sync: syncLabel(flags),
      flags: { UP: flags.userPresent, UV: flags.userVerified, BE: flags.backupEligible, BS: flags.backupState },
      signCount: flags.signCount,
      clientData: { type: cd.type, origin: cd.origin, challengeEchoed: echoed },
    });

    if (flags.signCount === 0 && flags.backupEligible)
      log("Note — signCount is 0 and stays 0: synced passkeys don't keep a per-device counter. Hardware keys (YubiKey) increment it, which lets a server spot a cloned key.");

    if (verify.ok === true)
      explain(`Signed in as ${record?.username || "this credential"}. The authenticator signed a fresh random challenge with the private key; the browser checked it against the stored public key and it matched — so this login is genuine and not a replay.`, "ok");
    else if (verify.ok === false)
      explain("The signature did not verify against the stored public key. A real server would reject this login.", "bad");
    else
      explain("The ceremony completed, but there was no stored public key to check the signature against (this passkey wasn't created here).", "warn");
  } catch (err) {
    log("ERROR — authentication failed: " + err.name + " — " + err.message);
    explain(benchError(err), "warn");
  }
}

// Wipe the previous verdict the moment a new demo starts, so a stale card can never be
// mistaken for the result of the button just pressed.
function clearProve() {
  const el = $("prove-out");
  el.hidden = true;
  el.innerHTML = "";
}

function proveNeedPasskey(test) {
  renderProve({
    tone: "bad", verdict: "Nothing to test yet", title: test || "No passkey on this site",
    rows: [{ k: "Needed", v: "a passkey created here", mark: "bad" }],
    cause: "This demo needs a passkey made on this site to work with. Create one in step 1 first, then run it again.",
  });
}

// A cancelled or failed demo gets a card of its own — every prove button always answers in
// the same place.
function proveStopped(test, err) {
  renderProve({
    tone: "bad", verdict: "Didn't run", title: test,
    rows: [{ k: "What happened", v: esc(translateError(err)), mark: "bad" },
           { k: "Reported as", v: esc(err.name) }],
    cause: "Nothing was proved or disproved — the demo never got its signature. Run it again.",
  });
}

// ---------- phishing demo: ask for a passkey using the WRONG domain ----------
async function phishingTest() {
  clearProve();
  const realHost = rpId() || "(none)";
  const fakeRp = "attacker-" + (rpId() || "example") + ".example";
  log(`Phishing simulation — requesting a passkey with rpId "${fakeRp}" (not this origin)`, {
    realOrigin: location.origin, claimedRpId: fakeRp,
  });
  const res = await runPhishing();
  if (!res.blocked) {
    log("UNEXPECTED — the request was not blocked. Check the environment.");
    renderProve({
      tone: "bad", verdict: "Not blocked", title: "Phishing simulation",
      rows: [{ k: "Requested rpId", v: esc(res.fakeRp), mark: "bad" }, { k: "Real origin", v: esc(res.realOrigin) }],
      cause: "Unexpected: the browser did not block the mismatched domain. Check the environment.",
    });
    return;
  }
  const err = res.err;
  log("BLOCKED (expected) — " + err.name + ": " + err.message);
  renderProve({
    tone: "ok",
    verdict: "Blocked — by the browser, before any prompt",
    title: "Phishing simulation",
    rows: [
      { k: "Fake site asked for (rpId)", v: esc(res.fakeRp), mark: "bad" },
      { k: "Real page origin", v: esc(res.realOrigin) },
      { k: "Passkey is bound to", v: esc(res.realHost), mark: "ok" },
      { k: "What the browser did", v: "Refused to reveal or use the credential — no prompt shown" },
      { k: "Exact error thrown", v: esc(err.name + ": " + err.message) },
    ],
    cause: `The blocker is the mismatch: the request claimed rpId <b>${esc(res.fakeRp)}</b>, but the passkey belongs to <b>${esc(res.realHost)}</b>. WebAuthn only releases a credential when the requested rpId matches the page's own origin, so the browser never even offered the passkey to the fake domain. A phishing page gets nothing — no key, no signature, nothing to relay. This check is in the browser itself; the user cannot be tricked into overriding it.`,
  });
}

// ---------- tamper demo: verify a real assertion, then a corrupted one ----------
async function tamperTest() {
  clearProve();
  const all = loadCreds();
  const allow = credsForSite();
  if (allow.length === 0) {
    log("WARNING — tamper test needs a passkey created here. Make one first.");
    explain("Create a passkey first, then run the tamper test.", "warn");
    proveNeedPasskey("Tamper test");
    return;
  }
  log("Tamper test — obtaining one real signature, then re-checking it with a single flipped byte.");
  try {
    const r = await getAssertion(randomBytes(32), $("userverification").value);
    const assertion = r.assertion;
    const record = all.find((c) => c.id === assertion.id);
    const good = await verifyAssertion(record, assertion.response, false);
    const bad = await verifyAssertion(record, assertion.response, true);
    log("Tamper test result", { realSignature: good.ok, afterFlippingOneByte: bad.ok, algorithm: good.reason });
    const pass = good.ok === true && bad.ok !== true;
    renderProve({
      tone: pass ? "ok" : "bad",
      verdict: pass ? "Integrity verified — tampering rejected" : "Unexpected result",
      title: "Tamper test",
      rows: [
        { k: "Genuine signature", v: good.ok === true ? "VALID — matches the stored public key" : "did not verify", mark: good.ok === true ? "ok" : "bad" },
        { k: "After flipping one byte", v: bad.ok === true ? "still valid (!)" : "INVALID — verification fails", mark: bad.ok === true ? "bad" : "ok" },
        { k: "Bytes that were signed", v: "authenticatorData + SHA-256(clientDataJSON)" },
        { k: "Checked with", v: esc(good.reason) },
      ],
      cause: `The blocker is the math: the authenticator's private key signed those exact bytes, and the browser re-checks them against the stored public key. Flip a single bit and the signature no longer matches, so the check returns <b>false</b> and a real server rejects the login. This is what stops anyone altering a request or replaying a captured one — the signature is verified on every sign-in.`,
    });
  } catch (err) {
    log("ERROR — tamper test aborted: " + err.name + " — " + err.message);
    explain("Tamper test stopped. " + benchError(err), "warn");
    proveStopped("Tamper test", err);
  }
}

// ---------- replay demo: a valid, untampered login still can't be reused ----------
async function replayTest() {
  clearProve();
  const c1 = randomBytes(32);
  log("Replay test — capturing one genuine sign-in, then resending it against a fresh challenge.");
  let r;
  try { r = await getAssertion(c1, $("userverification").value); }
  catch (err) { log("ERROR — replay test aborted: " + err.name + " — " + err.message); explain("Replay test stopped. " + benchError(err), "warn"); proveStopped("Replay test", err); return; }
  if (r.none) { proveNeedPasskey("Replay test"); return; }

  const resp = r.assertion.response;
  const record = r.all.find((c) => c.id === r.assertion.id);
  const sig = await verifyAssertion(record, resp, false);
  const signed = decodeClientData(resp.clientDataJSON).challenge; // b64url of c1
  const expectedNow = b64urlEncode(randomBytes(32));              // server has moved on
  const match = signed === expectedNow;

  log("Replay test result", { signatureValid: sig.ok, challengeInAssertion: signed, serverExpectsNow: expectedNow, challengeMatches: match });
  renderProve({
    tone: (sig.ok === true && !match) ? "ok" : "bad",
    verdict: "Rejected — replay caught",
    title: "Replay test",
    rows: [
      { k: "Signature", v: sig.ok === true ? "VALID — the cryptography is fine" : "did not verify", mark: sig.ok === true ? "ok" : "bad" },
      { k: "Challenge in the assertion", v: esc(signed.slice(0, 22) + "…") },
      { k: "Challenge the server now expects", v: esc(expectedNow.slice(0, 22) + "…"), mark: "ok" },
      { k: "Do they match?", v: "NO", mark: "bad" },
      { k: "Server verdict", v: "Reject — this login was already used" },
    ],
    cause: `The blocker is freshness: every sign-in gets a new random challenge that the authenticator signs. This captured login signed the <b>old</b> challenge, but the server has already issued a new one — so it refuses the request, even though the signature itself is perfectly valid. A recorded or stolen login can never be replayed.`,
  });
}

// ---------- wrong-key demo: signature only verifies against its own public key ----------
async function wrongKeyTest() {
  clearProve();
  const chal = randomBytes(32);
  log("Wrong-key test — verifying one real signature against the correct key, then a different key.");
  let r;
  try { r = await getAssertion(chal, $("userverification").value); }
  catch (err) { log("ERROR — wrong-key test aborted: " + err.name + " — " + err.message); explain("Wrong-key test stopped. " + benchError(err), "warn"); proveStopped("Wrong-key test", err); return; }
  if (r.none) { proveNeedPasskey("Wrong-key test"); return; }

  const resp = r.assertion.response;
  const record = r.all.find((c) => c.id === r.assertion.id);
  const right = await verifyAssertion(record, resp, false);
  // Compare like for like: an RS256 credential deserves an RSA foil, not an EC one, or the
  // "wrong key" is really just "wrong algorithm".
  const alg = record?.publicKeyAlgorithm === -257 ? -257 : -7;
  const params = alg === -257
    ? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }
    : { name: "ECDSA", namedCurve: "P-256" };
  const kp = await crypto.subtle.generateKey(params, true, ["sign", "verify"]);
  const otherSpki = b64urlEncode(await crypto.subtle.exportKey("spki", kp.publicKey));
  const wrong = await verifyAssertion({ publicKey: otherSpki, publicKeyAlgorithm: alg }, resp, false);

  log("Wrong-key test result", { withCorrectKey: right.ok, withDifferentKey: wrong.ok });
  renderProve({
    tone: (right.ok === true && wrong.ok !== true) ? "ok" : "bad",
    verdict: "Only the matching key verifies",
    title: "Wrong-key test",
    rows: [
      { k: "Against the stored public key", v: right.ok === true ? "VALID" : "did not verify", mark: right.ok === true ? "ok" : "bad" },
      { k: "Against a different public key", v: wrong.ok === true ? "valid (!)" : "INVALID — verification fails", mark: wrong.ok === true ? "bad" : "ok" },
      { k: "Checked with", v: esc(right.reason) },
      { k: "The other key", v: `a fresh ${esc(algName(alg))} key — same algorithm, different pair` },
    ],
    cause: `The blocker is identity: a signature only verifies against the one public key whose private half produced it. Swap in any other key and the check fails. The public key isn't secret — a server stores it, anyone can hold it — yet it still can't be used to forge a login, because forging needs the <b>private</b> key, which never leaves the authenticator.`,
  });
}

// ---------- UV demo: presence vs verification (the second factor) ----------
async function uvTest() {
  clearProve();
  const chal = randomBytes(32);
  const requested = $("userverification").value;
  log(`User-verification test — signing in with userVerification="${requested}", then applying a "UV required" server policy.`);
  let r;
  try { r = await getAssertion(chal, requested); }
  catch (err) { log("ERROR — UV test aborted: " + err.name + " — " + err.message); explain("UV test stopped. " + benchError(err), "warn"); proveStopped("User-verification test", err); return; }
  if (r.none) { proveNeedPasskey("User-verification test"); return; }

  const flags = parseAuthData(new Uint8Array(r.assertion.response.authenticatorData));
  const pass = flags.userVerified;
  log("UV test result", { userPresent: flags.userPresent, userVerified: flags.userVerified, serverPolicy: "UV required", accepted: pass });
  renderProve({
    tone: pass ? "ok" : "bad",
    verdict: pass ? "Accepted — user was verified" : "Rejected — presence only, no verification",
    title: "User-verification test",
    rows: [
      { k: "User present (UP)", v: flags.userPresent ? "yes — the authenticator was used" : "no", mark: flags.userPresent ? "ok" : "bad" },
      { k: "User verified (UV)", v: flags.userVerified ? "yes — PIN or biometric checked" : "no — not verified", mark: flags.userVerified ? "ok" : "bad" },
      { k: "Server policy", v: "UV required (phishing-resistant MFA)" },
      { k: "Verdict", v: pass ? "Accept" : "Reject" },
    ],
    cause: `Two different guarantees. <b>Presence</b> (UP) only means someone touched the authenticator. <b>Verification</b> (UV) means they proved who they are with a PIN or biometric — that is the built-in second factor. A server enforcing phishing-resistant MFA (as Entra can) requires the UV bit set; a bare tap is not enough. Set User verification to "Required" above to force it.`,
  });
}

// ---------- table ----------
function renderTable() {
  const tbody = document.querySelector("#cred-table tbody");
  const creds = loadCreds();
  tbody.innerHTML = "";
  if (creds.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" class="muted">No passkeys stored yet.</td></tr>';
    return;
  }
  creds.forEach((c, i) => {
    const sync = c.backupEligible == null ? "—" : c.backupEligible ? (c.backupState ? "Synced" : "Sync-eligible") : "Device-bound";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${new Date(c.created).toLocaleDateString()}</td>
      <td>${esc(c.username)}</td>
      <td>${esc(c.wallet || "—")}</td>
      <td>${sync}</td>
      <td>${c.signIns || 0}</td>
      <td class="actions">
        <button data-raw="${i}" class="link">Raw</button>
        <button data-copy="${i}" class="link">Copy ID</button>
        <button data-key="${i}" class="link">Public key</button>
        <button data-del="${i}" class="link">Remove</button>
      </td>`;
    tbody.appendChild(tr);
  });
  tbody.querySelectorAll("button[data-del]").forEach((b) => b.addEventListener("click", () => {
    const all = loadCreds(); all.splice(+b.dataset.del, 1); saveCreds(all); renderTable();
    log("Removed passkey from local list (not from the wallet/authenticator).");
  }));
  tbody.querySelectorAll("button[data-copy]").forEach((b) => b.addEventListener("click", () => {
    navigator.clipboard.writeText(loadCreds()[+b.dataset.copy].id);
    log("Copied credential ID to clipboard.");
  }));
  tbody.querySelectorAll("button[data-raw]").forEach((b) => b.addEventListener("click", () => {
    openInspectorRecord(loadCreds()[+b.dataset.raw]);
  }));
  tbody.querySelectorAll("button[data-key]").forEach((b) => b.addEventListener("click", () => {
    const c = loadCreds()[+b.dataset.key];
    openRecordCard(c);
    if (c.publicKey) log(`Public key for ${c.username} (${algName(c.publicKeyAlgorithm)})\n` + spkiToPem(c.publicKey));
    explain("Shown is the public half of the key pair — the only part a real server stores. The matching private key stays locked in the authenticator and is never exportable.", "ok");
  }));
}

// ---------- export / import ----------
function exportCreds() {
  const blob = new Blob([JSON.stringify(loadCreds(), null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `passkey-lab-${location.hostname}-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
  log("Exported credential list to JSON.");
}
function importCreds(file) {
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const incoming = JSON.parse(reader.result);
      if (!Array.isArray(incoming)) throw new Error("not an array");
      const existing = loadCreds();
      const ids = new Set(existing.map((c) => c.id));
      const merged = existing.concat(incoming.filter((c) => c.id && !ids.has(c.id)));
      saveCreds(merged); renderTable();
      log(`Imported ${merged.length - existing.length} new record(s).`);
    } catch (e) { log("ERROR — import failed: " + e.message); }
  };
  reader.readAsText(file);
}

// ---------- raw inspector ----------
function openInspectorRecord(rec) {
  const secs = [];
  secs.push(section("Credential ID", rows([["base64url", `<span class="mono">${esc(rec.id)}</span>`]]) + hexPre(b64urlDecode(rec.id))));

  if (rec.clientDataJSON) {
    const cdU8 = b64urlDecode(rec.clientDataJSON);
    const cd = JSON.parse(new TextDecoder().decode(cdU8));
    secs.push(section("clientDataJSON &mdash; the browser's signed statement of context", rows([
      ["type", esc(cd.type)],
      ["challenge", `<span class="mono">${esc(cd.challenge)}</span>`],
      ["origin", esc(cd.origin), "ok"],
      ["crossOrigin", esc(String(cd.crossOrigin))],
    ]) + `<p class="insp-note">Raw bytes:</p>` + hexPre(cdU8)));
  }

  if (rec.attestationObject) {
    const ao = cborDecode(b64urlDecode(rec.attestationObject));
    const attStmt = ao.get("attStmt");
    const stmtKeys = attStmt instanceof Map ? [...attStmt.keys()].join(", ") : "";
    secs.push(section("attestationObject (CBOR-decoded)", rows([
      ["fmt", esc(String(ao.get("fmt")))],
      ["attStmt", attStmt instanceof Map && attStmt.size === 0 ? "{ } &mdash; empty (no attestation requested)" : esc(stmtKeys || "(present)")],
      ["authData", "decoded below"],
    ])));
    secs.push(buildAuthDataSection(new Uint8Array(ao.get("authData")), true));
  } else {
    secs.push(section("Note", `<p class="insp-note">This record predates raw capture. Create a new passkey to inspect the full attestationObject and authenticatorData.</p>`));
  }
  openModal("Raw inspector — registration", secs.join(""));
}

function openInspectorAssertion() {
  if (!lastAssertion) { log("Inspector — do a Test sign-in first, then inspect it."); explain("Do a Test sign-in first, then open the inspector.", "warn"); return; }
  const { record, authData, clientDataJSON, signature } = lastAssertion;
  const cdText = new TextDecoder().decode(clientDataJSON);
  const rs = derRS(signature);
  const secs = [];
  secs.push(buildAuthDataSection(authData, false));
  secs.push(section("Signature", rs
    ? rows([["algorithm", esc(record?.publicKeyAlgorithm === -257 ? "RS256" : "ES256")], ["r", hexPre(rs.r)], ["s", hexPre(rs.s)]])
    : `<p class="insp-note">Raw signature bytes:</p>` + hexPre(signature)));
  secs.push(`<section class="insp-sec"><h3>Tamper &amp; re-verify</h3>
    <p class="insp-note">The private key is sealed and unreadable &mdash; you can only edit the <em>message</em>. Change the origin or challenge below, or flip a signature byte, then re-verify. Any change makes the signature fail.</p>
    <textarea id="insp-cd" class="insp-edit" spellcheck="false"></textarea>
    <label class="insp-flip"><input type="checkbox" id="insp-flip" /> flip one signature byte</label>
    <div class="actions-row"><button id="insp-verify" class="btn btn-primary">Re-verify</button>
      <button id="insp-reset" class="btn btn-quiet">Reset</button></div>
    <div id="insp-result" class="insp-result"></div></section>`);
  openModal("Raw inspector — last sign-in", secs.join(""));

  const ta = document.getElementById("insp-cd"); ta.value = cdText;
  document.getElementById("insp-verify").addEventListener("click", async () => {
    const bytes = new TextEncoder().encode(ta.value);
    const flip = document.getElementById("insp-flip").checked;
    const res = await verifyBytes(record, authData, bytes, signature, flip);
    const tone = res.ok === true ? "ok" : "bad";
    document.getElementById("insp-result").innerHTML =
      `<span class="verdict verdict-${tone}">${res.ok === true ? "VALID" : "INVALID"}</span> ` +
      `<span class="mono">${esc(res.reason)}</span> &mdash; ` +
      (res.ok === true ? "message matches what was signed" : "the signed bytes changed, so the check fails");
  });
  document.getElementById("insp-reset").addEventListener("click", () => {
    ta.value = cdText; document.getElementById("insp-flip").checked = false;
    document.getElementById("insp-result").innerHTML = "";
  });
}

// ---------- ceremony X-ray (bench) ----------
function openXray() {
  if (!lastCeremony) {
    log("X-ray — create a passkey or do a Test sign-in first, then open the X-ray.");
    explain("Create a passkey or do a Test sign-in first, then open the X-ray.", "warn");
    return;
  }
  const { kind, res } = lastCeremony;
  const body = openModal(kind === "registration" ? "Ceremony X-ray — registration" : "Ceremony X-ray — sign-in",
    xrayHtml(kind, res, { open: true, recordLink: true }));
  wireXray(body, (id) => openRecordCard(loadCreds().find((c) => c.id === id)));
}

// ---------- mode switching ----------
function enterMode(mode) {
  setMode(mode);
  showView(mode);
  if (mode === "training") renderTraining();
  window.scrollTo(0, 0);
}

// One entry point for every bit of navigation: the masthead nav, the wordmark, the landing
// buttons and the "guided lab" link under the masthead all come through here.
function goToView(view) {
  if (view === "choice") {
    clearMode();
    refreshLandingPrimary();
    showView("choice");
    window.scrollTo(0, 0);
    return;
  }
  enterMode(view);
}

function wireMode() {
  refreshLandingPrimary();
  document.querySelectorAll("#modenav .modenav-btn").forEach((b) =>
    b.addEventListener("click", () => goToView(b.dataset.view)));
  $("btn-home").addEventListener("click", () => goToView("choice"));
  $("btn-mode-training").addEventListener("click", () => enterMode("training"));
  $("btn-mode-bench").addEventListener("click", () => enterMode("bench"));
  $("btn-tolab").addEventListener("click", () => enterMode("training"));
  // One tooltip open at a time — they overlap the fields beneath them.
  document.addEventListener("click", (e) => {
    document.querySelectorAll("details.tip[open]").forEach((d) => { if (!d.contains(e.target)) d.open = false; });
  });

  const view = initialView();
  showView(view);
  if (view === "training") renderTraining();
}

// ---------- wire up ----------
window.addEventListener("DOMContentLoaded", () => {
  detectEnv();
  renderTable();
  $("cleanup-footer-list").innerHTML = cleanupListHtml();
  wireMode();
  $("btn-create").addEventListener("click", createPasskey);
  $("btn-auth").addEventListener("click", () => authenticate("optional"));
  $("btn-autofill").addEventListener("click", () => authenticate("conditional"));
  $("btn-phish").addEventListener("click", phishingTest);
  $("btn-tamper").addEventListener("click", tamperTest);
  $("btn-replay").addEventListener("click", replayTest);
  $("btn-wrongkey").addEventListener("click", wrongKeyTest);
  $("btn-uv").addEventListener("click", uvTest);
  $("btn-clear").addEventListener("click", () => {
    if (confirm("Clear the local list of passkeys? This does not delete them from your wallet.")) {
      localStorage.removeItem(STORE_KEY); renderTable(); log("Cleared local passkey list.");
    }
  });
  $("btn-export").addEventListener("click", exportCreds);
  $("import-file").addEventListener("change", (e) => { if (e.target.files[0]) importCreds(e.target.files[0]); e.target.value = ""; });
  $("btn-clearlog").addEventListener("click", () => { $("log").textContent = ""; $("explain").hidden = true; });
  $("btn-inspect").addEventListener("click", openInspectorAssertion);
  $("btn-xray").addEventListener("click", openXray);
  $("insp-close").addEventListener("click", closeModal);
  $("inspector").addEventListener("click", (e) => { if (e.target.id === "inspector") closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  document.addEventListener("keydown", trapModalTab);
  // The rail purges the ledger in Step 6; keep the bench's table in step with it.
  document.addEventListener("passkey-lab:ledger-changed", renderTable);
});
