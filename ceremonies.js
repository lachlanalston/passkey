// Passkey Lab — ceremonies.
// The WebAuthn calls themselves, parameterised and DOM-free, so both the bench and the
// guided rail can drive them. These touch navigator.credentials and localStorage; they
// never touch the document. Callers render.

import {
  b64urlEncode, b64urlDecode, randomBytes,
  parseAuthData, decodeClientData, walletName, verifyAssertion, cborDecode,
} from "./core.js";

export const STORE_KEY = "passkey-lab-creds";
export const loadCreds = () => { try { return JSON.parse(localStorage.getItem(STORE_KEY) || "[]"); } catch { return []; } };
export const saveCreds = (c) => localStorage.setItem(STORE_KEY, JSON.stringify(c));
export const rpId = () => location.hostname;
export const credsForSite = () => loadCreds().filter((c) => c.rpId === rpId());

// The attestationObject carries its own copy of authenticatorData; older browsers lack
// getAuthenticatorData(), so fall back to digging it out of the CBOR.
function authDataFrom(resp) {
  if (resp.getAuthenticatorData) {
    try { return new Uint8Array(resp.getAuthenticatorData()); } catch { /* fall through */ }
  }
  try {
    const ao = cborDecode(new Uint8Array(resp.attestationObject));
    const ad = ao.get("authData");
    if (ad) return new Uint8Array(ad);
  } catch { /* no authData available */ }
  return null;
}

// ---------- registration ----------
// opts: { username, displayName, attachment, residentKey, userVerification, attestation,
//         timeout, onRequest(requestSummary) }
// -> { record, ms, flags, clientData, raw, challenge, echoed, request }
export async function registerPasskey(opts = {}) {
  const id = rpId();
  const username = (opts.username || "").trim() || "demo.user";
  const displayName = (opts.displayName || "").trim() || username;
  const attachment = opts.attachment || "";
  const residentKey = opts.residentKey || "required";

  const challenge = randomBytes(32);
  const authenticatorSelection = {
    residentKey,
    requireResidentKey: residentKey === "required",
    userVerification: opts.userVerification || "preferred",
  };
  if (attachment) authenticatorSelection.authenticatorAttachment = attachment;

  const publicKey = {
    challenge,
    rp: { name: "Passkey Test Lab", id },
    user: { id: randomBytes(16), name: username, displayName },
    pubKeyCredParams: [
      { type: "public-key", alg: -7 },   // ES256
      { type: "public-key", alg: -257 }, // RS256
    ],
    authenticatorSelection,
    attestation: opts.attestation || "none",
    timeout: opts.timeout || 60000,
    excludeCredentials: credsForSite().map((c) => ({ type: "public-key", id: b64urlDecode(c.id) })),
  };

  const request = {
    ...publicKey,
    challenge: b64urlEncode(challenge) + "  (fresh 32 random bytes)",
    user: { ...publicKey.user, id: "(16 random bytes)" },
    excludeCredentials: `${publicKey.excludeCredentials.length} existing`,
  };
  if (opts.onRequest) opts.onRequest(request);

  const t0 = performance.now();
  const cred = await navigator.credentials.create({ publicKey });
  const ms = Math.round(performance.now() - t0);
  const resp = cred.response;

  const authData = authDataFrom(resp);
  let flags = {}, pub = null, pubAlg = null;
  if (authData) { try { flags = parseAuthData(authData); } catch { /* leave empty */ } }
  if (resp.getPublicKey) { const pk = resp.getPublicKey(); if (pk) pub = b64urlEncode(pk); }
  if (resp.getPublicKeyAlgorithm) pubAlg = resp.getPublicKeyAlgorithm();

  const clientData = decodeClientData(resp.clientDataJSON);
  const echoed = clientData.challenge === b64urlEncode(challenge);

  const record = {
    id: cred.id,
    rpId: id, username, displayName,
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

  return {
    record, ms, flags, clientData, echoed, request,
    challenge: b64urlEncode(challenge),
    raw: {
      authData,
      clientDataJSON: new Uint8Array(resp.clientDataJSON),
      attestationObject: resp.attestationObject ? new Uint8Array(resp.attestationObject) : null,
    },
  };
}

// ---------- authentication ----------
// opts: { allowIds (b64url ids; omit/null => discoverable), userVerification, mediation,
//         timeout, onRequest(requestSummary) }
// -> { none: true } when allowIds was requested but the lab holds nothing to offer, else
//    { id, record, ms, flags, clientData, verify, echoed, userHandle, raw, challenge, request }
export async function signIn(opts = {}) {
  const id = rpId();
  const challenge = randomBytes(32);
  const publicKey = {
    challenge, rpId: id,
    userVerification: opts.userVerification || "preferred",
    timeout: opts.timeout || 60000,
  };

  const discoverable = opts.allowIds === undefined || opts.allowIds === null;
  if (!discoverable && opts.mediation !== "conditional") {
    const known = credsForSite();
    const allow = opts.allowIds
      .map((cid) => known.find((c) => c.id === cid) || { id: cid, transports: undefined })
      .map((c) => ({ type: "public-key", id: b64urlDecode(c.id), transports: c.transports }));
    if (allow.length === 0) return { none: true };
    publicKey.allowCredentials = allow;
  }

  const request = {
    rpId: id,
    challenge: b64urlEncode(challenge) + "  (fresh 32 random bytes)",
    userVerification: publicKey.userVerification,
    allowCredentials: publicKey.allowCredentials ? `${publicKey.allowCredentials.length} stored` : "empty → discoverable/any",
  };
  if (opts.onRequest) opts.onRequest(request, opts.mediation || "optional");

  const req = { publicKey };
  if (opts.mediation === "conditional") req.mediation = "conditional";
  if (opts.signal) req.signal = opts.signal;

  const t0 = performance.now();
  const assertion = await navigator.credentials.get(req);
  const ms = Math.round(performance.now() - t0);
  const resp = assertion.response;

  const authData = new Uint8Array(resp.authenticatorData);
  const flags = parseAuthData(authData);
  const clientData = decodeClientData(resp.clientDataJSON);
  const echoed = clientData.challenge === b64urlEncode(challenge);

  const all = loadCreds();
  const record = all.find((c) => c.id === assertion.id && c.rpId === id);
  const verify = await verifyAssertion(record, resp);

  if (record) { record.signIns = (record.signIns || 0) + 1; saveCreds(all); }

  return {
    id: assertion.id, record, ms, flags, clientData, verify, echoed, request,
    challenge: b64urlEncode(challenge),
    userHandle: resp.userHandle ? b64urlEncode(resp.userHandle) : null,
    raw: {
      authData,
      clientDataJSON: new Uint8Array(resp.clientDataJSON),
      signature: new Uint8Array(resp.signature),
    },
  };
}

// Shared: obtain one assertion from any passkey created on this site (prove-it demos).
export async function getAssertion(challenge, userVerification = "preferred") {
  const all = loadCreds();
  const allow = all.filter((c) => c.rpId === rpId())
    .map((c) => ({ type: "public-key", id: b64urlDecode(c.id), transports: c.transports }));
  if (allow.length === 0) return { none: true, all };
  const assertion = await navigator.credentials.get({
    publicKey: { challenge: challenge, rpId: rpId(), userVerification, timeout: 60000, allowCredentials: allow },
  });
  return { assertion, all };
}

// ---------- phishing demo ----------
// Asks the browser for a passkey using the WRONG site identity. The browser refuses before
// any prompt — that refusal is the whole demonstration, so a throw here is the success path.
// -> { blocked, fakeRp, realHost, realOrigin, err } (err null when, unexpectedly, not blocked)
export async function runPhishing() {
  const realHost = rpId() || "(none)";
  const fakeRp = "attacker-" + (rpId() || "example") + ".example";
  const challenge = randomBytes(32);
  const publicKey = { challenge, rpId: fakeRp, userVerification: "preferred", timeout: 60000 };
  // The request is returned so the caller can show it beside a genuine one — the single
  // changed field is the whole lesson.
  const base = {
    fakeRp, realHost, realOrigin: location.origin,
    request: {
      challenge: b64urlEncode(challenge),
      rpId: fakeRp,
      userVerification: publicKey.userVerification,
    },
  };
  try {
    await navigator.credentials.get({ publicKey });
    return { ...base, blocked: false, err: null };
  } catch (err) {
    return { ...base, blocked: true, err };
  }
}
