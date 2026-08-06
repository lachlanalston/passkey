// Passkey Lab — core.
// Pure, DOM-free helpers: encoding, WebAuthn structure decoding, and real signature
// verification. Everything here is unit-testable under Node (WebCrypto, TextDecoder,
// atob/btoa are all built in from Node 20). No DOM, no storage, no navigator.credentials.

// ---------- base64url ----------
export const b64urlEncode = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const b64urlDecode = (str) => {
  str = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
};

export const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

// HTML-escape — used by every builder that writes innerHTML.
export const esc = (s) => String(s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));

// ---------- known authenticator AAGUIDs ----------
// Source: community FIDO AAGUID list (github.com/passkeydeveloper/passkey-authenticator-aaguids).
// Incomplete on purpose — unknown IDs are shown raw. All-zero = privacy-preserving (no ID reported).
export const AAGUIDS = {
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
export const walletName = (aaguid) => AAGUIDS[aaguid] || `Unknown (${aaguid || "n/a"})`;

// 16 raw bytes -> canonical dashed AAGUID string.
export const aaguidStr = (u8) => [...u8].map((b) => b.toString(16).padStart(2, "0")).join("")
  .replace(/^(.{8})(.{4})(.{4})(.{4})(.{12})$/, "$1-$2-$3-$4-$5");

// ---------- authenticatorData parsing ----------
export function parseAuthData(bytes) {
  bytes = new Uint8Array(bytes);
  // A well-formed authenticatorData is at least rpIdHash(32) + flags(1) + signCount(4).
  // Short input can only ever be a partial result — say so rather than reading past the end.
  if (bytes.length < 37) return { truncated: true, byteLength: bytes.length };
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
    out.aaguid = aaguidStr(bytes.slice(37, 53));
  }
  return out;
}

export const syncLabel = (f) =>
  !f.backupEligible ? "Device-bound (single-device)"
    : f.backupState ? "Synced (multi-device passkey)"
      : "Sync-eligible, not yet backed up";

// clientDataJSON is the browser's signed statement of context (type, challenge, origin).
export function decodeClientData(clientDataJSON) {
  return JSON.parse(new TextDecoder().decode(new Uint8Array(clientDataJSON)));
}

// ---------- ECDSA DER signature -> raw r||s (for WebCrypto ES256) ----------
export function derToRawEcdsa(der) {
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
export function spkiToPem(b64url) {
  const b64 = btoa(String.fromCharCode(...b64urlDecode(b64url)));
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN PUBLIC KEY-----\n${lines}\n-----END PUBLIC KEY-----`;
}

// ---------- signature verification ----------
// Byte-level core: verify a signature over (authData || SHA-256(clientDataJSON)).
// flip: corrupt one signature byte to prove any change breaks verification.
export async function verifyBytes(record, authData, clientDataJSON, signature, flip = false) {
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

export const verifyAssertion = (record, resp, tamperSig = false) =>
  verifyBytes(record, resp.authenticatorData, resp.clientDataJSON, resp.signature, tamperSig);

// ---------- raw decoders (for the inspector and the X-ray) ----------
// Minimal CBOR decoder: enough for attestationObject and COSE keys.
export function cborDecode(bytes) {
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

export function toHex(u8) {
  const a = [...new Uint8Array(u8)].map((b) => b.toString(16).padStart(2, "0"));
  const lines = [];
  for (let i = 0; i < a.length; i += 16) lines.push(a.slice(i, i + 16).join(" "));
  return lines.join("\n") || "(empty)";
}

// Full parse of authenticatorData for display.
export function inspectAuthData(bytes) {
  bytes = new Uint8Array(bytes);
  if (bytes.length < 37) return { truncated: true, byteLength: bytes.length };
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const flags = bytes[32];
  const out = { rpIdHash: bytes.slice(0, 32), flags, signCount: dv.getUint32(33, false) };
  if (flags & 0x40 && bytes.length >= 55) {
    out.aaguid = bytes.slice(37, 53);
    const credLen = (bytes[53] << 8) | bytes[54];
    out.credId = bytes.slice(55, 55 + credLen);
    out.cose = cborDecode(bytes.slice(55 + credLen));
  }
  return out;
}

export function flagBits(f) {
  const defs = [["UP", 0, "User present"], ["UV", 2, "User verified"], ["BE", 3, "Backup eligible"], ["BS", 4, "Backup state"], ["AT", 6, "Attested credential data"], ["ED", 7, "Extension data"]];
  const bin = "0b" + f.toString(2).padStart(8, "0");
  const set = defs.filter((d) => f & (1 << d[1])).map((d) => `${d[0]} — ${d[2]}`);
  return { bin, set: set.length ? set.join("<br>") : "none set" };
}

export function coseInfo(m) {
  if (!(m instanceof Map)) return null;
  const kty = m.get(1), alg = m.get(3);
  if (kty === 2) return { type: "EC2 (elliptic curve)", alg, crv: { 1: "P-256", 2: "P-384", 3: "P-521" }[m.get(-1)] || m.get(-1), x: m.get(-2), y: m.get(-3) };
  if (kty === 3) return { type: "RSA", alg, n: m.get(-1), e: m.get(-2) };
  return { type: "kty " + kty, alg };
}

// ECDSA DER signature -> {r, s} bytes, for display.
export function derRS(sig) {
  let o = 0;
  if (sig[o++] !== 0x30) return null;
  if (sig[o] & 0x80) o += (sig[o] & 0x7f) + 1; else o++;
  const readInt = () => { o++; const len = sig[o++]; const v = sig.slice(o, o + len); o += len; return v; };
  return { r: readInt(), s: readInt() };
}

export const algName = (alg) => alg === -7 ? "ES256" : alg === -257 ? "RS256" : "alg " + alg;
