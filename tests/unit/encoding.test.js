// base64url, the DER/raw ECDSA conversions, clientDataJSON, and PEM. The signature
// conversion is the one with a real trap in it: DER integers are signed, so r and s arrive
// padded or short and have to come out as exactly 32 bytes each.

import { describe, it, expect } from "vitest";
import {
  b64urlEncode, b64urlDecode, randomBytes, esc,
  derToRawEcdsa, derRS, decodeClientData, spkiToPem,
} from "../../core.js";
import { bytes, fill, counting, rawToDer, derFromInts, utf8 } from "./fixtures.js";

describe("base64url", () => {
  it("round-trips arbitrary bytes", () => {
    for (const len of [0, 1, 2, 3, 16, 32, 64, 255]) {
      const b = counting(len, 7);
      expect([...b64urlDecode(b64urlEncode(b))]).toEqual([...b]);
    }
  });

  it("emits no padding and no + or /", () => {
    const s = b64urlEncode(bytes(0xfb, 0xff, 0xbe, 0xef, 0x3e));
    expect(s).not.toMatch(/[+/=]/);
  });

  it("decodes input that is missing its padding", () => {
    expect([...b64urlDecode("AQID")]).toEqual([1, 2, 3]);
    expect([...b64urlDecode("AQIDBA")]).toEqual([1, 2, 3, 4]);
    expect([...b64urlDecode("AQIDBAU")]).toEqual([1, 2, 3, 4, 5]);
  });

  it("decodes the - and _ substitutions back to the right bytes", () => {
    const raw = bytes(0xff, 0xef, 0xbe);
    expect([...b64urlDecode(b64urlEncode(raw))]).toEqual([...raw]);
    expect(b64urlEncode(raw)).toContain("-");
  });

  it("accepts an ArrayBuffer as well as a view", () => {
    expect(b64urlEncode(counting(4).buffer)).toBe(b64urlEncode(counting(4)));
  });
});

describe("randomBytes", () => {
  it("returns the requested length and does not repeat itself", () => {
    const a = randomBytes(32), b = randomBytes(32);
    expect(a).toBeInstanceOf(Uint8Array);
    expect(a.length).toBe(32);
    expect(b64urlEncode(a)).not.toBe(b64urlEncode(b));
  });
});

describe("esc", () => {
  it("neutralises the three characters that could close a tag", () => {
    expect(esc('<script>alert("x")</script>')).toBe('&lt;script&gt;alert("x")&lt;/script&gt;');
    expect(esc("a & b")).toBe("a &amp; b");
  });

  it("stringifies non-strings rather than throwing", () => {
    expect(esc(null)).toBe("null");
    expect(esc(42)).toBe("42");
    expect(esc(undefined)).toBe("undefined");
  });
});

describe("derToRawEcdsa", () => {
  it("converts a plain 32/32 signature", () => {
    const raw = new Uint8Array(64);
    raw.set(fill(32, 0x11), 0);
    raw.set(fill(32, 0x22), 32);
    expect([...derToRawEcdsa(rawToDer(raw))]).toEqual([...raw]);
  });

  it("strips the sign-padding byte from a 33-byte integer", () => {
    // r has its high bit set, so DER prefixes 0x00 — the raw form must not keep it
    const r = fill(32, 0x80);
    const s = fill(32, 0x01);
    const der = derFromInts(Uint8Array.from([0x00, ...r]), s);
    const out = derToRawEcdsa(der);
    expect(out.length).toBe(64);
    expect([...out.slice(0, 32)]).toEqual([...r]);
    expect([...out.slice(32)]).toEqual([...s]);
  });

  it("strips sign-padding from both halves at once", () => {
    const r = fill(32, 0x90), s = fill(32, 0xf0);
    const out = derToRawEcdsa(derFromInts(
      Uint8Array.from([0x00, ...r]), Uint8Array.from([0x00, ...s])));
    expect([...out.slice(0, 32)]).toEqual([...r]);
    expect([...out.slice(32)]).toEqual([...s]);
  });

  it("left-pads a short integer to 32 bytes", () => {
    // a small r encodes in fewer bytes; raw form is fixed-width, so it pads on the left
    const shortR = bytes(0x01, 0x02, 0x03);
    const out = derToRawEcdsa(derFromInts(shortR, fill(32, 0x44)));
    expect(out.length).toBe(64);
    expect([...out.slice(0, 32)]).toEqual([...new Uint8Array(29), 0x01, 0x02, 0x03]);
    expect([...out.slice(32)]).toEqual([...fill(32, 0x44)]);
  });

  it("handles a single-byte integer", () => {
    const out = derToRawEcdsa(derFromInts(bytes(0x07), bytes(0x09)));
    expect(out[31]).toBe(0x07);
    expect(out[63]).toBe(0x09);
    expect(out.slice(0, 31).every((b) => b === 0)).toBe(true);
  });

  it("throws on anything that is not a DER SEQUENCE of two INTEGERs", () => {
    expect(() => derToRawEcdsa(bytes(0x31, 0x02, 0x02, 0x00))).toThrow("bad DER");
    expect(() => derToRawEcdsa(bytes(0x30, 0x04, 0x04, 0x01, 0x00, 0x00))).toThrow("bad DER int");
    expect(() => derToRawEcdsa(new Uint8Array(0))).toThrow();
  });

  it("reads a long-form sequence length", () => {
    const raw = counting(64, 1);
    const der = rawToDer(raw);
    const longForm = Uint8Array.from([0x30, 0x81, der.length - 2, ...der.slice(2)]);
    expect([...derToRawEcdsa(longForm)]).toEqual([...derToRawEcdsa(der)]);
  });
});

describe("derRS — the display split", () => {
  it("returns r and s for a well-formed signature", () => {
    const raw = new Uint8Array(64);
    raw.set(fill(32, 0x33), 0);
    raw.set(fill(32, 0x44), 32);
    const rs = derRS(rawToDer(raw));
    expect(rs.r.length).toBeGreaterThan(0);
    expect(rs.s.length).toBeGreaterThan(0);
  });

  it("returns null rather than throwing on a non-DER signature", () => {
    expect(derRS(bytes(0x01, 0x02, 0x03))).toBe(null);
    expect(derRS(fill(256, 0xaa))).toBe(null);   // an RSA signature is raw, not DER
  });
});

describe("decodeClientData", () => {
  it("parses the browser's signed statement of context", () => {
    const cd = decodeClientData(utf8(JSON.stringify({
      type: "webauthn.get",
      challenge: "Y2hhbGxlbmdl",
      origin: "https://passkey.lrfa.dev",
      crossOrigin: false,
    })));
    expect(cd).toEqual({
      type: "webauthn.get",
      challenge: "Y2hhbGxlbmdl",
      origin: "https://passkey.lrfa.dev",
      crossOrigin: false,
    });
  });

  it("accepts an ArrayBuffer as well as a view", () => {
    const u = utf8('{"type":"webauthn.create","origin":"https://x.example"}');
    expect(decodeClientData(u.buffer).type).toBe("webauthn.create");
  });

  it("decodes multibyte UTF-8 in the origin", () => {
    const cd = decodeClientData(utf8(JSON.stringify({ type: "webauthn.get", origin: "https://xn--rksmrgs-5wao1o.example", note: "café — ok" })));
    expect(cd.note).toBe("café — ok");
  });

  it("throws on bytes that are not JSON, rather than returning junk", () => {
    expect(() => decodeClientData(bytes(0xff, 0xfe, 0x00))).toThrow();
  });
});

describe("spkiToPem", () => {
  it("wraps the key in the header, footer and 64-column body a server would store", () => {
    const pem = spkiToPem(b64urlEncode(counting(91)));
    const lines = pem.split("\n");
    expect(lines[0]).toBe("-----BEGIN PUBLIC KEY-----");
    expect(lines[lines.length - 1]).toBe("-----END PUBLIC KEY-----");
    for (const l of lines.slice(1, -1)) expect(l.length).toBeLessThanOrEqual(64);
  });

  it("round-trips back to the original bytes", () => {
    const original = counting(91, 3);
    const body = spkiToPem(b64urlEncode(original))
      .split("\n").slice(1, -1).join("");
    expect([...Buffer.from(body, "base64")]).toEqual([...original]);
  });
});
