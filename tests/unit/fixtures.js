// Fixture builders for the unit suites.
// core.js only ever decodes, so the tests need the encoding half: a minimal CBOR writer, a
// raw-to-DER ECDSA converter, and an authenticatorData assembler. Keeping them here means the
// fixtures are readable byte-for-byte instead of pasted hex blobs.

export const FLAG = { UP: 0x01, UV: 0x04, BE: 0x08, BS: 0x10, AT: 0x40, ED: 0x80 };

const concat = (...parts) => {
  const arrays = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)));
  const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrays) { out.set(a, o); o += a.length; }
  return out;
};

export const bytes = (...v) => Uint8Array.from(v);
export const fill = (n, v = 0xab) => new Uint8Array(n).fill(v);
export const counting = (n, start = 0) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);

// ---------- minimal CBOR encoder ----------
function head(major, n) {
  if (n < 24) return bytes((major << 5) | n);
  if (n < 0x100) return bytes((major << 5) | 24, n);
  if (n < 0x10000) return bytes((major << 5) | 25, n >> 8, n & 0xff);
  return bytes((major << 5) | 26, (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff);
}

export function cborEncode(v) {
  if (typeof v === "number") {
    return v >= 0 ? head(0, v) : head(1, -1 - v);
  }
  if (typeof v === "boolean") return bytes(v ? 0xf5 : 0xf4);
  if (v === null) return bytes(0xf6);
  if (v instanceof Uint8Array) return concat(head(2, v.length), v);
  if (typeof v === "string") {
    const u = new TextEncoder().encode(v);
    return concat(head(3, u.length), u);
  }
  if (Array.isArray(v)) return concat(head(4, v.length), ...v.map(cborEncode));
  if (v instanceof Map) {
    return concat(head(5, v.size), ...[...v].flatMap(([k, val]) => [cborEncode(k), cborEncode(val)]));
  }
  throw new Error("cborEncode: unsupported " + typeof v);
}

// ---------- COSE keys ----------
export const coseEc2 = ({ alg = -7, crv = 1, x = fill(32, 0x11), y = fill(32, 0x22) } = {}) =>
  new Map([[1, 2], [3, alg], [-1, crv], [-2, x], [-3, y]]);

export const coseRsa = ({ alg = -257, n = fill(256, 0x33), e = bytes(0x01, 0x00, 0x01) } = {}) =>
  new Map([[1, 3], [3, alg], [-1, n], [-2, e]]);

// ---------- authenticatorData ----------
// rpIdHash(32) || flags(1) || signCount(4) [|| aaguid(16) || credIdLen(2) || credId || COSE]
export function buildAuthData({
  rpIdHash = fill(32, 0x01),
  flags = FLAG.UP,
  signCount = 0,
  aaguid = null,
  credId = null,
  cose = null,
} = {}) {
  const counter = bytes((signCount >>> 24) & 0xff, (signCount >>> 16) & 0xff, (signCount >>> 8) & 0xff, signCount & 0xff);
  const base = concat(rpIdHash, bytes(flags), counter);
  if (!(flags & FLAG.AT)) return base;
  const id = credId || counting(32, 0x40);
  return concat(base, aaguid || fill(16, 0x00), bytes(id.length >> 8, id.length & 0xff), id, cborEncode(cose || coseEc2()));
}

export const attestationObject = (authData, { fmt = "none", attStmt = new Map() } = {}) =>
  cborEncode(new Map([["fmt", fmt], ["attStmt", attStmt], ["authData", authData]]));

// ---------- signatures ----------
// core.js converts DER to raw; the tests need the other direction to build a signature the
// way an authenticator emits one.
export function rawToDer(raw) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = concat(bytes(0x00), v);
    return concat(bytes(0x02, v.length), v);
  };
  const body = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(bytes(0x30, body.length), body);
}

// A DER SEQUENCE of two INTEGERs, with r and s given exactly as supplied — used to build the
// leading-zero-padded and short-integer cases derToRawEcdsa has to survive.
export function derFromInts(r, s) {
  const int = (b) => concat(bytes(0x02, b.length), b);
  const body = concat(int(r), int(s));
  return concat(bytes(0x30, body.length), body);
}

export const b64url = (buf) =>
  Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export const utf8 = (s) => new TextEncoder().encode(s);

// ---------- a real, signed assertion ----------
// Generates a key pair, signs authData || SHA-256(clientDataJSON) with it, and returns
// everything verifyBytes needs — so the verification tests check real cryptography rather
// than a stubbed boolean.
export async function signedAssertion({ alg = -7, authData = buildAuthData({ flags: FLAG.UP | FLAG.UV }), clientData = { type: "webauthn.get", challenge: "Y2hhbGxlbmdl", origin: "https://passkey.example", crossOrigin: false } } = {}) {
  const params = alg === -257
    ? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: bytes(1, 0, 1), hash: "SHA-256" }
    : { name: "ECDSA", namedCurve: "P-256" };
  const kp = await crypto.subtle.generateKey(params, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));

  const clientDataJSON = utf8(JSON.stringify(clientData));
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", clientDataJSON));
  const signed = concat(authData, hash);

  let signature;
  if (alg === -257) {
    signature = new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, kp.privateKey, signed));
  } else {
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, signed));
    signature = rawToDer(raw);
  }

  return {
    record: { publicKey: b64url(spki), publicKeyAlgorithm: alg },
    authData, clientDataJSON, signature, clientData, keyPair: kp, spki,
  };
}

export async function otherPublicKey(alg = -7) {
  const params = alg === -257
    ? { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: bytes(1, 0, 1), hash: "SHA-256" }
    : { name: "ECDSA", namedCurve: "P-256" };
  const kp = await crypto.subtle.generateKey(params, true, ["sign", "verify"]);
  return { publicKey: b64url(await crypto.subtle.exportKey("spki", kp.publicKey)), publicKeyAlgorithm: alg };
}
