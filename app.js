// Passkey Lab — client-side WebAuthn demo.
// Create passkeys, save to a wallet, test sign-in, verify the signature in-browser,
// and demonstrate WHY it's secure (phishing block, tamper test, plain-English trace).

const $ = (id) => document.getElementById(id);
const STORE_KEY = "passkey-lab-creds";

// ---------- base64url ----------
const b64urlEncode = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

const b64urlDecode = (str) => {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
};

const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

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

const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

const loadCreds = () => JSON.parse(localStorage.getItem(STORE_KEY) || "[]");
const saveCreds = (c) => localStorage.setItem(STORE_KEY, JSON.stringify(c));

// ---------- known authenticator AAGUIDs ----------
// Source: community FIDO AAGUID list (github.com/passkeydeveloper/passkey-authenticator-aaguids).
// Incomplete on purpose — unknown IDs are shown raw. All-zero = privacy-preserving (no ID reported).
const AAGUIDS = {
  "00000000-0000-0000-0000-000000000000": "Privacy (no AAGUID reported)",
  "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
  "adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
  "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "Apple iCloud Keychain",
  "dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "Apple iCloud Keychain (managed)",
  "08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",
  "9ddd1817-af5a-4672-a2b9-3e3dd95000a7": "Windows Hello",
  "6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
  "b84e4048-15dc-4dd0-8640-f4f60813c8af": "NordPass",
  "bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
  "531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",
  "0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6": "Keeper",
  "891494da-2c90-4d31-a9d4-4eb0676e07f1": "Proton Pass",
  "ee882879-721c-4913-9775-3dfcce97072a": "YubiKey 5 Series",
  "fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 NFC",
  "2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 FIPS",
  "d548826e-79b4-db40-a3d8-11116f7e8349": "LastPass",
};
const walletName = (aaguid) => AAGUIDS[aaguid] || `Unknown (${aaguid || "n/a"})`;

// ---------- authenticatorData parsing ----------
function parseAuthData(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const flags = bytes[32];
  const out = {
    userPresent: !!(flags & 0x01),      // UP
    userVerified: !!(flags & 0x04),     // UV
    backupEligible: !!(flags & 0x08),   // BE — CAN be synced/multi-device
    backupState: !!(flags & 0x10),      // BS — currently backed up/synced
    attestedCredentialData: !!(flags & 0x40), // AT (registration)
    extensionData: !!(flags & 0x80),    // ED
    signCount: dv.getUint32(33, false),
  };
  if (out.attestedCredentialData && bytes.length >= 53) {
    const aaguid = bytes.slice(37, 53);
    out.aaguid = [...aaguid].map((b) => b.toString(16).padStart(2, "0")).join("")
      .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");
  }
  return out;
}

const syncLabel = (f) =>
  !f.backupEligible ? "Device-bound (single-device)"
    : f.backupState ? "Synced (multi-device passkey)"
      : "Sync-eligible, not yet backed up";

// clientDataJSON is the browser's signed statement of context (type, challenge, origin).
function decodeClientData(clientDataJSON) {
  return JSON.parse(new TextDecoder().decode(clientDataJSON));
}

// ---------- ECDSA DER signature -> raw r||s (for WebCrypto ES256) ----------
function derToRawEcdsa(der) {
  let o = 0;
  if (der[o++] !== 0x30) throw new Error("bad DER");
  if (der[o] & 0x80) o += (der[o] & 0x7f) + 1; else o++; // seq length
  const readInt = () => {
    if (der[o++] !== 0x02) throw new Error("bad DER int");
    let len = der[o++];
    let val = der.slice(o, o + len);
    o += len;
    while (val.length > 32 && val[0] === 0x00) val = val.slice(1); // strip sign pad
    const out = new Uint8Array(32);
    out.set(val, 32 - val.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(64);
  raw.set(r, 0); raw.set(s, 32);
  return raw;
}

// SPKI (base64url) -> PEM, so people can see the public half a real server keeps.
function spkiToPem(b64url) {
  const b64 = btoa(String.fromCharCode(...b64urlDecode(b64url)));
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

// ---------- signature verification ----------
// Byte-level core: verify a signature over (authData || SHA-256(clientDataJSON)).
// flip: corrupt one signature byte to prove any change breaks verification.
async function verifyBytes(record, authData, clientDataJSON, signature, flip = false) {
  if (!record || !record.publicKey) return { ok: null, reason: "no stored public key to verify against" };
  const alg = record.publicKeyAlgorithm; // -7 ES256, -257 RS256
  const spki = b64urlDecode(record.publicKey);
  const ad = new Uint8Array(authData);
  const cd = new Uint8Array(clientDataJSON);
  const clientHash = new Uint8Array(await crypto.subtle.digest("SHA-256", cd));
  const signed = new Uint8Array(ad.length + clientHash.length);
  signed.set(ad, 0); signed.set(clientHash, ad.length);

  let sig = new Uint8Array(signature);
  if (flip) { sig = sig.slice(); sig[sig.length - 1] ^= 0x01; }

  try {
    if (alg === -7) {
      const key = await crypto.subtle.importKey("spki", spki, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, derToRawEcdsa(sig), signed);
      return { ok, reason: "ES256 / ECDSA P-256" };
    }
    if (alg === -257) {
      const key = await crypto.subtle.importKey("spki", spki, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
      const ok = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, signed);
      return { ok, reason: "RS256 / RSA" };
    }
    return { ok: null, reason: "unsupported alg " + alg };
  } catch (e) {
    // A tampered ECDSA signature usually fails DER decode — that is itself a rejection.
    return { ok: false, reason: "rejected: " + e.message };
  }
}

const verifyAssertion = (record, resp, tamperSig = false) =>
  verifyBytes(record, resp.authenticatorData, resp.clientDataJSON, resp.signature, tamperSig);

// ---------- raw decoders (for the inspector) ----------
// Minimal CBOR decoder: enough for attestationObject and COSE keys.
function cborDecode(bytes) {
  let o = 0;
  function read() {
    const b = bytes[o++], mt = b >> 5, ai = b & 0x1f;
    let len = ai;
    if (ai === 24) len = bytes[o++];
    else if (ai === 25) { len = (bytes[o] << 8) | bytes[o + 1]; o += 2; }
    else if (ai === 26) { len = bytes[o] * 0x1000000 + (bytes[o + 1] << 16) + (bytes[o + 2] << 8) + bytes[o + 3]; o += 4; }
    else if (ai === 27) { const hi = bytes[o] * 0x1000000 + (bytes[o + 1] << 16) + (bytes[o + 2] << 8) + bytes[o + 3]; const lo = bytes[o + 4] * 0x1000000 + (bytes[o + 5] << 16) + (bytes[o + 6] << 8) + bytes[o + 7]; len = hi * 0x100000000 + lo; o += 8; }
    switch (mt) {
      case 0: return len;
      case 1: return -1 - len;
      case 2: { const v = bytes.slice(o, o + len); o += len; return v; }
      case 3: { const v = new TextDecoder().decode(bytes.slice(o, o + len)); o += len; return v; }
      case 4: { const a = []; for (let i = 0; i < len; i++) a.push(read()); return a; }
      case 5: { const m = new Map(); for (let i = 0; i < len; i++) { const k = read(); m.set(k, read()); } return m; }
      case 7: return ai === 20 ? false : ai === 21 ? true : ai === 22 ? null : len;
      default: return null;
    }
  }
  return read();
}

function toHex(u8) {
  const a = [...new Uint8Array(u8)].map((b) => b.toString(16).padStart(2, "0"));
  const lines = [];
  for (let i = 0; i < a.length; i += 16) lines.push(a.slice(i, i + 16).join(" "));
  return lines.join("\n") || "(empty)";
}

// Full parse of authenticatorData for display.
function inspectAuthData(bytes) {
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const flags = bytes[32];
  const out = { rpIdHash: bytes.slice(0, 32), flags, signCount: dv.getUint32(33, false) };
  if (flags & 0x40) {
    out.aaguid = bytes.slice(37, 53);
    const credLen = (bytes[53] << 8) | bytes[54];
    out.credId = bytes.slice(55, 55 + credLen);
    out.cose = cborDecode(bytes.slice(55 + credLen));
  }
  return out;
}

function flagBits(f) {
  const defs = [["UP", 0, "User present"], ["UV", 2, "User verified"], ["BE", 3, "Backup eligible"], ["BS", 4, "Backup state"], ["AT", 6, "Attested credential data"], ["ED", 7, "Extension data"]];
  const bin = "0b" + f.toString(2).padStart(8, "0");
  const set = defs.filter((d) => f & (1 << d[1])).map((d) => `${d[0]} — ${d[2]}`);
  return { bin, set: set.length ? set.join("<br>") : "none set" };
}

function coseInfo(m) {
  if (!(m instanceof Map)) return null;
  const kty = m.get(1), alg = m.get(3);
  if (kty === 2) return { type: "EC2 (elliptic curve)", alg, crv: { 1: "P-256", 2: "P-384", 3: "P-521" }[m.get(-1)] || m.get(-1), x: m.get(-2), y: m.get(-3) };
  if (kty === 3) return { type: "RSA", alg, n: m.get(-1), e: m.get(-2) };
  return { type: "kty " + kty, alg };
}

// ECDSA DER signature -> {r, s} bytes, for display.
function derRS(sig) {
  let o = 0;
  if (sig[o++] !== 0x30) return null;
  if (sig[o] & 0x80) o += (sig[o] & 0x7f) + 1; else o++;
  const readInt = () => { o++; const len = sig[o++]; const v = sig.slice(o, o + len); o += len; return v; };
  return { r: readInt(), s: readInt() };
}

let lastAssertion = null; // populated on each successful sign-in, for the inspector

// ---------- environment ----------
async function detectEnv() {
  $("origin").textContent = location.origin;
  $("rpid").textContent = location.hostname || "(none — serve over http/https)";
  $("secure").textContent = window.isSecureContext ? "Yes" : "No (needs HTTPS or localhost)";
  const supported = !!(window.PublicKeyCredential && navigator.credentials);
  $("webauthn").textContent = supported ? "Yes" : "No";

  if (supported && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
    try { $("platform").textContent = (await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()) ? "Available" : "Not available"; }
    catch { $("platform").textContent = "Unknown"; }
  } else $("platform").textContent = "Unknown";

  if (supported && PublicKeyCredential.isConditionalMediationAvailable) {
    try { $("condui").textContent = (await PublicKeyCredential.isConditionalMediationAvailable()) ? "Available" : "Not available"; }
    catch { $("condui").textContent = "Unknown"; }
  } else $("condui").textContent = "Unknown";
}

// ---------- registration ----------
async function createPasskey() {
  const rpId = location.hostname;
  const username = $("username").value.trim() || "demo.user";
  const displayName = $("displayname").value.trim() || username;
  const attachment = $("attachment").value;

  const challenge = randomBytes(32);
  const authenticatorSelection = {
    residentKey: $("residentkey").value,
    requireResidentKey: $("residentkey").value === "required",
    userVerification: $("userverification").value,
  };
  if (attachment) authenticatorSelection.authenticatorAttachment = attachment;

  const publicKey = {
    challenge,
    rp: { name: "Passkey Test Lab", id: rpId },
    user: { id: randomBytes(16), name: username, displayName },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256
      { type: "public-key", alg: -257 }, // RS256
    ],
    authenticatorSelection,
    attestation: $("attestation").value,
    timeout: 60000,
    excludeCredentials: loadCreds()
      .filter((c) => c.rpId === rpId)
      .map((c) => ({ type: "public-key", id: b64urlDecode(c.id) })),
  };

  log("navigator.credentials.create() request", {
    ...publicKey,
    challenge: b64urlEncode(challenge) + "  (fresh 32 random bytes)",
    user: { ...publicKey.user, id: "(16 random bytes)" },
    excludeCredentials: `${publicKey.excludeCredentials.length} existing`,
  });

  try {
    const t0 = performance.now();
    const cred = await navigator.credentials.create({ publicKey });
    const ms = Math.round(performance.now() - t0);
    const resp = cred.response;

    let flags = {}, pub = null, pubAlg = null;
    if (resp.getAuthenticatorData) { try { flags = parseAuthData(new Uint8Array(resp.getAuthenticatorData())); } catch {} }
    if (resp.getPublicKey) { const pk = resp.getPublicKey(); if (pk) pub = b64urlEncode(pk); }
    if (resp.getPublicKeyAlgorithm) pubAlg = resp.getPublicKeyAlgorithm();

    const cd = decodeClientData(resp.clientDataJSON);
    const echoed = cd.challenge === b64urlEncode(challenge);

    const record = {
      id: cred.id,
      rpId, username, displayName,
      type: cred.type,
      transports: resp.getTransports ? resp.getTransports() : [],
      authenticatorAttachment: cred.authenticatorAttachment || attachment || "unknown",
      aaguid: flags.aaguid || null,
      wallet: flags.aaguid ? walletName(flags.aaguid) : null,
      backupEligible: flags.backupEligible ?? null,
      backupState: flags.backupState ?? null,
      publicKey: pub,
      publicKeyAlgorithm: pubAlg,
      attestationObject: resp.attestationObject ? b64urlEncode(resp.attestationObject) : null,
      clientDataJSON: b64urlEncode(resp.clientDataJSON),
      signIns: 0,
      created: new Date().toISOString(),
    };
    const all = loadCreds(); all.push(record); saveCreds(all);
    renderTable();

    log(`Passkey created (${ms} ms)`, {
      credentialId: cred.id,
      wallet: record.wallet || "(unknown — no attestation AAGUID)",
      aaguid: record.aaguid,
      transports: record.transports,
      authenticatorAttachment: record.authenticatorAttachment,
      sync: flags.aaguid !== undefined ? syncLabel(flags) : "unknown",
      flags: { UP: flags.userPresent, UV: flags.userVerified, BE: flags.backupEligible, BS: flags.backupState },
      signCount: flags.signCount,
      publicKeyStored: !!pub,
      clientData: { type: cd.type, origin: cd.origin, challengeEchoed: echoed },
    });

    const wallet = record.wallet && !record.wallet.startsWith("Unknown") ? record.wallet : "the authenticator";
    const port = flags.backupEligible
      ? "It is a synced passkey — it backs up and appears on your other signed-in devices."
      : "It is device-bound — it lives only on this authenticator and cannot sync.";
    explain(`Created a passkey for "${username}" on ${rpId}, stored in ${wallet}. ${port} The public key is now saved here; the private key never left the authenticator.`, "ok");
  } catch (err) {
    if (err.name === "InvalidStateError") {
      log("WARNING — this authenticator already holds a passkey for this account (excludeCredentials blocked a duplicate).");
      explain("The authenticator already has a passkey for this account, so registration was blocked. This is the 'no duplicate on the same device' rule.", "warn");
    } else {
      log("ERROR — registration failed: " + err.name + " — " + err.message);
      explain("Registration was cancelled or failed: " + err.message, "bad");
    }
  }
}

// ---------- authentication ----------
async function authenticate(mediation = "optional") {
  const rpId = location.hostname;
  const mode = $("allowmode").value;
  const challenge = randomBytes(32);

  const publicKey = { challenge, rpId, userVerification: $("userverification").value, timeout: 60000 };

  if (mode === "stored" && mediation !== "conditional") {
    const allow = loadCreds().filter((c) => c.rpId === rpId)
      .map((c) => ({ type: "public-key", id: b64urlDecode(c.id), transports: c.transports }));
    if (allow.length === 0) {
      log("WARNING — no stored passkeys for this site. Create one, or switch Match to 'Any'.");
      explain("No passkeys are stored for this site yet. Create one in step 1 first.", "warn");
      return;
    }
    publicKey.allowCredentials = allow;
  }

  log(`navigator.credentials.get() request (mediation: ${mediation})`, {
    rpId,
    challenge: b64urlEncode(challenge) + "  (fresh 32 random bytes)",
    userVerification: publicKey.userVerification,
    allowCredentials: publicKey.allowCredentials ? `${publicKey.allowCredentials.length} stored` : "empty → discoverable/any",
  });

  try {
    const opts = { publicKey };
    if (mediation === "conditional") opts.mediation = "conditional";
    const t0 = performance.now();
    const assertion = await navigator.credentials.get(opts);
    const ms = Math.round(performance.now() - t0);
    const resp = assertion.response;
    const flags = parseAuthData(new Uint8Array(resp.authenticatorData));
    const cd = decodeClientData(resp.clientDataJSON);
    const echoed = cd.challenge === b64urlEncode(challenge);

    const all = loadCreds();
    const record = all.find((c) => c.id === assertion.id && c.rpId === rpId);
    const verify = await verifyAssertion(record, resp);

    lastAssertion = {
      record,
      authData: new Uint8Array(resp.authenticatorData),
      clientDataJSON: new Uint8Array(resp.clientDataJSON),
      signature: new Uint8Array(resp.signature),
      id: assertion.id,
    };

    if (record) { record.signIns = (record.signIns || 0) + 1; saveCreds(all); renderTable(); }

    log((verify.ok === true ? `OK — sign-in verified (${ms} ms, signature valid)` :
         verify.ok === false ? "FAILED — signature INVALID" :
         `OK — sign-in ceremony completed (${ms} ms, not verified: ${verify.reason})`), {
      credentialId: assertion.id,
      matchedStored: !!record,
      wallet: record?.wallet || "unknown",
      userHandle: resp.userHandle ? b64urlEncode(resp.userHandle) : null,
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
    explain("Sign-in was cancelled or failed: " + err.message, "warn");
  }
}

// Shared: obtain one assertion from a passkey created on this site.
async function getAssertion(challenge) {
  const all = loadCreds();
  const allow = all.filter((c) => c.rpId === location.hostname)
    .map((c) => ({ type: "public-key", id: b64urlDecode(c.id), transports: c.transports }));
  if (allow.length === 0) return { none: true, all };
  const assertion = await navigator.credentials.get({
    publicKey: { challenge, rpId: location.hostname, userVerification: $("userverification").value, timeout: 60000, allowCredentials: allow },
  });
  return { assertion, all };
}

function proveNeedPasskey() {
  renderProve({
    tone: "bad", verdict: "Nothing to test yet", title: "No passkey on this site",
    rows: [{ k: "Needed", v: "a passkey created here", mark: "bad" }],
    cause: "Create a passkey in step 1 first, then run this test.",
  });
}

// ---------- phishing demo: ask for a passkey using the WRONG domain ----------
async function phishingTest() {
  const realHost = location.hostname || "(none)";
  const fakeRp = "attacker-" + (location.hostname || "example") + ".example";
  log(`Phishing simulation — requesting a passkey with rpId "${fakeRp}" (not this origin)`, {
    realOrigin: location.origin, claimedRpId: fakeRp,
  });
  try {
    await navigator.credentials.get({
      publicKey: { challenge: randomBytes(32), rpId: fakeRp, userVerification: "preferred", timeout: 60000 },
    });
    log("UNEXPECTED — the request was not blocked. Check the environment.");
    renderProve({
      tone: "bad", verdict: "Not blocked", title: "Phishing simulation",
      rows: [{ k: "Requested rpId", v: esc(fakeRp), mark: "bad" }, { k: "Real origin", v: esc(location.origin) }],
      cause: "Unexpected: the browser did not block the mismatched domain. Check the environment.",
    });
  } catch (err) {
    log("BLOCKED (expected) — " + err.name + ": " + err.message);
    renderProve({
      tone: "ok",
      verdict: "Blocked — by the browser, before any prompt",
      title: "Phishing simulation",
      rows: [
        { k: "Fake site asked for (rpId)", v: esc(fakeRp), mark: "bad" },
        { k: "Real page origin", v: esc(location.origin) },
        { k: "Passkey is bound to", v: esc(realHost), mark: "ok" },
        { k: "What the browser did", v: "Refused to reveal or use the credential — no prompt shown" },
        { k: "Exact error thrown", v: esc(err.name + ": " + err.message) },
      ],
      cause: `The blocker is the mismatch: the request claimed rpId <b>${esc(fakeRp)}</b>, but the passkey belongs to <b>${esc(realHost)}</b>. WebAuthn only releases a credential when the requested rpId matches the page's own origin, so the browser never even offered the passkey to the fake domain. A phishing page gets nothing — no key, no signature, nothing to relay. This check is in the browser itself; the user cannot be tricked into overriding it.`,
    });
  }
}

// ---------- tamper demo: verify a real assertion, then a corrupted one ----------
async function tamperTest() {
  const rpId = location.hostname;
  const all = loadCreds();
  const allow = all.filter((c) => c.rpId === rpId)
    .map((c) => ({ type: "public-key", id: b64urlDecode(c.id), transports: c.transports }));
  if (allow.length === 0) {
    log("WARNING — tamper test needs a passkey created here. Make one first.");
    explain("Create a passkey first, then run the tamper test.", "warn");
    return;
  }
  log("Tamper test — obtaining one real signature, then re-checking it with a single flipped byte.");
  try {
    const assertion = await navigator.credentials.get({
      publicKey: { challenge: randomBytes(32), rpId, userVerification: $("userverification").value, timeout: 60000, allowCredentials: allow },
    });
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
    explain("Tamper test cancelled: " + err.message, "warn");
  }
}

// ---------- replay demo: a valid, untampered login still can't be reused ----------
async function replayTest() {
  const c1 = randomBytes(32);
  log("Replay test — capturing one genuine sign-in, then resending it against a fresh challenge.");
  let r;
  try { r = await getAssertion(c1); }
  catch (err) { log("ERROR — replay test aborted: " + err.name + " — " + err.message); explain("Replay test cancelled: " + err.message, "warn"); return; }
  if (r.none) { proveNeedPasskey(); return; }

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
  const chal = randomBytes(32);
  log("Wrong-key test — verifying one real signature against the correct key, then a different key.");
  let r;
  try { r = await getAssertion(chal); }
  catch (err) { log("ERROR — wrong-key test aborted: " + err.name + " — " + err.message); explain("Wrong-key test cancelled: " + err.message, "warn"); return; }
  if (r.none) { proveNeedPasskey(); return; }

  const resp = r.assertion.response;
  const record = r.all.find((c) => c.id === r.assertion.id);
  const right = await verifyAssertion(record, resp, false);
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const otherSpki = b64urlEncode(await crypto.subtle.exportKey("spki", kp.publicKey));
  const wrong = await verifyAssertion({ publicKey: otherSpki, publicKeyAlgorithm: -7 }, resp, false);

  log("Wrong-key test result", { withCorrectKey: right.ok, withDifferentKey: wrong.ok });
  renderProve({
    tone: (right.ok === true && wrong.ok !== true) ? "ok" : "bad",
    verdict: "Only the matching key verifies",
    title: "Wrong-key test",
    rows: [
      { k: "Against the stored public key", v: right.ok === true ? "VALID" : "did not verify", mark: right.ok === true ? "ok" : "bad" },
      { k: "Against a different public key", v: wrong.ok === true ? "valid (!)" : "INVALID — verification fails", mark: wrong.ok === true ? "bad" : "ok" },
      { k: "Checked with", v: esc(right.reason) },
    ],
    cause: `The blocker is identity: a signature only verifies against the one public key whose private half produced it. Swap in any other key and the check fails. The public key isn't secret — a server stores it, anyone can hold it — yet it still can't be used to forge a login, because forging needs the <b>private</b> key, which never leaves the authenticator.`,
  });
}

// ---------- UV demo: presence vs verification (the second factor) ----------
async function uvTest() {
  const chal = randomBytes(32);
  const requested = $("userverification").value;
  log(`User-verification test — signing in with userVerification="${requested}", then applying a "UV required" server policy.`);
  let r;
  try { r = await getAssertion(chal); }
  catch (err) { log("ERROR — UV test aborted: " + err.name + " — " + err.message); explain("UV test cancelled: " + err.message, "warn"); return; }
  if (r.none) { proveNeedPasskey(); return; }

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
    if (!c.publicKey) { log("No stored public key for this record."); return; }
    log(`Public key for ${c.username} (${c.publicKeyAlgorithm === -7 ? "ES256" : c.publicKeyAlgorithm === -257 ? "RS256" : "alg " + c.publicKeyAlgorithm})\n` + spkiToPem(c.publicKey));
    explain("Shown below is the public half of the key pair — the only part a real server stores. The matching private key stays locked in the authenticator and is never exportable.", "ok");
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
const section = (t, inner) => `<section class="insp-sec"><h3>${t}</h3>${inner}</section>`;
const rows = (pairs) => `<dl class="prove-rows">` +
  pairs.map(([k, v, m]) => `<div class="prow ${m || ""}"><dt>${k}</dt><dd>${v}</dd></div>`).join("") + `</dl>`;
const hexPre = (u8) => `<pre class="hex">${toHex(u8)}</pre>`;
const aaguidStr = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("")
  .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");

let modalReturnFocus = null;
function openModal(title, html) {
  modalReturnFocus = document.activeElement;
  $("insp-title").textContent = title;
  $("insp-body").innerHTML = html;
  $("inspector").hidden = false;
  $("insp-close").focus();
}
function closeModal() {
  if ($("inspector").hidden) return;
  $("inspector").hidden = true;
  $("insp-body").innerHTML = "";
  if (modalReturnFocus && modalReturnFocus.focus) modalReturnFocus.focus();
  modalReturnFocus = null;
}
// Keep Tab focus inside the open modal.
function trapModalTab(e) {
  if (e.key !== "Tab" || $("inspector").hidden) return;
  const f = [...$("inspector").querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
    .filter((el) => !el.disabled && el.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

function buildAuthDataSection(ad, includeCose) {
  const p = inspectAuthData(ad);
  const fb = flagBits(p.flags);
  const inner = rows([
    ["rpIdHash", hexPre(p.rpIdHash) + `<span class="insp-note">SHA-256 of the site domain</span>`],
    ["flags byte", `<span class="mono">${fb.bin}</span>`],
    ["flags set", fb.set],
    ["signCount", `<span class="mono">${p.signCount}</span>`],
  ]);
  let out = section("authenticatorData", inner + `<p class="insp-note">Raw bytes (${ad.length}):</p>` + hexPre(ad));
  if (includeCose && p.aaguid) {
    const c = coseInfo(p.cose);
    const idRows = [
      ["AAGUID", `<span class="mono">${aaguidStr(p.aaguid)}</span> &mdash; ${esc(walletName(aaguidStr(p.aaguid)))}`, "ok"],
      ["credentialId", hexPre(p.credId)],
    ];
    let keyRows = [];
    if (c && c.x) keyRows = [["key type", esc(c.type)], ["COSE alg", `<span class="mono">${c.alg}</span> (${c.alg === -7 ? "ES256" : c.alg === -257 ? "RS256" : "?"})`], ["curve", esc(String(c.crv))], ["x coordinate", hexPre(c.x)], ["y coordinate", hexPre(c.y)]];
    else if (c && c.n) keyRows = [["key type", esc(c.type)], ["modulus n", hexPre(c.n)], ["exponent e", hexPre(c.e)]];
    out += section("Attested public key (COSE) &mdash; the public half stored by a server", rows(idRows) + (keyRows.length ? rows(keyRows) : ""));
  }
  return out;
}

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

// ---------- wire up ----------
window.addEventListener("DOMContentLoaded", () => {
  detectEnv();
  renderTable();
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
  $("insp-close").addEventListener("click", closeModal);
  $("inspector").addEventListener("click", (e) => { if (e.target.id === "inspector") closeModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeModal(); });
  document.addEventListener("keydown", trapModalTab);
});
