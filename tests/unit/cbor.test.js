// The minimal CBOR decoder and the COSE key reader. Only ever fed attestation objects and
// COSE keys, but it has to survive every length encoding those can legitimately use.

import { describe, it, expect } from "vitest";
import { cborDecode, coseInfo, toHex } from "../../core.js";
import {
  cborEncode, coseEc2, coseRsa, attestationObject, buildAuthData, FLAG, fill, bytes, counting,
} from "./fixtures.js";

describe("cborDecode — primitives", () => {
  it("reads unsigned integers across every length prefix", () => {
    for (const n of [0, 1, 23, 24, 255, 256, 65535, 65536, 1000000]) {
      expect(cborDecode(cborEncode(n))).toBe(n);
    }
  });

  it("reads negative integers", () => {
    for (const n of [-1, -24, -25, -256, -257, -65536]) {
      expect(cborDecode(cborEncode(n))).toBe(n);
    }
  });

  it("reads the COSE algorithm identifiers specifically", () => {
    expect(cborDecode(cborEncode(-7))).toBe(-7);
    expect(cborDecode(cborEncode(-257))).toBe(-257);
  });

  it("reads byte strings, including long ones", () => {
    for (const len of [0, 1, 23, 24, 255, 256, 1024]) {
      const b = counting(len);
      expect([...cborDecode(cborEncode(b))]).toEqual([...b]);
    }
  });

  it("reads text strings, including multibyte", () => {
    expect(cborDecode(cborEncode("none"))).toBe("none");
    expect(cborDecode(cborEncode("packed"))).toBe("packed");
    expect(cborDecode(cborEncode("é — ünicode"))).toBe("é — ünicode");
  });

  it("reads booleans and null", () => {
    expect(cborDecode(cborEncode(true))).toBe(true);
    expect(cborDecode(cborEncode(false))).toBe(false);
    expect(cborDecode(cborEncode(null))).toBe(null);
  });
});

describe("cborDecode — structures", () => {
  it("reads arrays", () => {
    expect(cborDecode(cborEncode([1, 2, 3]))).toEqual([1, 2, 3]);
    expect(cborDecode(cborEncode([]))).toEqual([]);
  });

  it("reads maps as Maps, preserving non-string keys", () => {
    const m = cborDecode(cborEncode(new Map([[1, 2], [-1, "x"], ["k", 9]])));
    expect(m).toBeInstanceOf(Map);
    expect(m.get(1)).toBe(2);
    expect(m.get(-1)).toBe("x");
    expect(m.get("k")).toBe(9);
  });

  it("reads a nested attestationObject the way the inspector does", () => {
    const authData = buildAuthData({ flags: FLAG.UP | FLAG.UV | FLAG.AT, signCount: 3 });
    const ao = cborDecode(attestationObject(authData));
    expect(ao.get("fmt")).toBe("none");
    expect(ao.get("attStmt")).toBeInstanceOf(Map);
    expect(ao.get("attStmt").size).toBe(0);
    expect([...ao.get("authData")]).toEqual([...authData]);
  });

  it("reads a populated attStmt", () => {
    const ao = cborDecode(attestationObject(buildAuthData({ flags: FLAG.AT }), {
      fmt: "packed",
      attStmt: new Map([["alg", -7], ["sig", counting(70)]]),
    }));
    expect(ao.get("fmt")).toBe("packed");
    expect([...ao.get("attStmt").keys()]).toEqual(["alg", "sig"]);
    expect(ao.get("attStmt").get("alg")).toBe(-7);
  });
});

describe("coseInfo", () => {
  it("describes an EC2 P-256 key", () => {
    const c = coseInfo(coseEc2({ x: fill(32, 0x11), y: fill(32, 0x22) }));
    expect(c.type).toBe("EC2 (elliptic curve)");
    expect(c.alg).toBe(-7);
    expect(c.crv).toBe("P-256");
    expect(c.x.length).toBe(32);
    expect(c.y.length).toBe(32);
  });

  it("names the other curves", () => {
    expect(coseInfo(coseEc2({ crv: 2 })).crv).toBe("P-384");
    expect(coseInfo(coseEc2({ crv: 3 })).crv).toBe("P-521");
  });

  it("passes an unrecognised curve through raw rather than guessing", () => {
    expect(coseInfo(coseEc2({ crv: 42 })).crv).toBe(42);
  });

  it("describes an RSA key", () => {
    const c = coseInfo(coseRsa());
    expect(c.type).toBe("RSA");
    expect(c.alg).toBe(-257);
    expect(c.n.length).toBe(256);
    expect([...c.e]).toEqual([0x01, 0x00, 0x01]);
  });

  it("reports an unknown key type without inventing fields", () => {
    const c = coseInfo(new Map([[1, 5], [3, -8]]));
    expect(c).toEqual({ type: "kty 5", alg: -8 });
  });

  it("returns null for anything that is not a Map", () => {
    expect(coseInfo(null)).toBe(null);
    expect(coseInfo(undefined)).toBe(null);
    expect(coseInfo({ 1: 2 })).toBe(null);
    expect(coseInfo([1, 2])).toBe(null);
  });

  it("survives a COSE key round-tripped through an authenticatorData blob", () => {
    const { cose } = cborDecodeAuthData();
    const c = coseInfo(cose);
    expect(c.type).toBe("EC2 (elliptic curve)");
    expect(c.alg).toBe(-7);
  });
});

function cborDecodeAuthData() {
  const ad = buildAuthData({ flags: FLAG.UP | FLAG.AT, cose: coseEc2() });
  const credLen = (ad[53] << 8) | ad[54];
  return { cose: cborDecode(ad.slice(55 + credLen)) };
}

describe("toHex", () => {
  it("formats sixteen bytes to a line", () => {
    expect(toHex(bytes(0x00, 0x0f, 0xff))).toBe("00 0f ff");
    const lines = toHex(counting(35)).split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0].split(" ")).toHaveLength(16);
    expect(lines[2].split(" ")).toHaveLength(3);
  });

  it("says so rather than rendering nothing", () => {
    expect(toHex(new Uint8Array(0))).toBe("(empty)");
  });

  it("accepts an ArrayBuffer", () => {
    expect(toHex(counting(3).buffer)).toBe("00 01 02");
  });
});
