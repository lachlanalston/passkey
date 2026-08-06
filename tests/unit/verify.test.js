// verifyBytes — the one function in the lab whose answer is a claim about reality. Every
// case here signs with a real WebCrypto key and checks the real result: nothing is stubbed,
// because a stubbed tick is exactly the failure mode this guards against.

import { describe, it, expect } from "vitest";
import { verifyBytes, verifyAssertion } from "../../core.js";
import {
  signedAssertion, otherPublicKey, buildAuthData, FLAG, utf8, bytes, b64url,
} from "./fixtures.js";

describe("verifyBytes — ES256", () => {
  it("accepts a genuine signature", async () => {
    const a = await signedAssertion();
    const res = await verifyBytes(a.record, a.authData, a.clientDataJSON, a.signature);
    expect(res.ok).toBe(true);
    expect(res.reason).toBe("ES256 / ECDSA P-256");
  });

  it("rejects the same signature with one byte flipped", async () => {
    const a = await signedAssertion();
    const res = await verifyBytes(a.record, a.authData, a.clientDataJSON, a.signature, true);
    expect(res.ok).toBe(false);
  });

  it("rejects it against a different key of the same algorithm", async () => {
    const a = await signedAssertion();
    const res = await verifyBytes(await otherPublicKey(-7), a.authData, a.clientDataJSON, a.signature);
    expect(res.ok).toBe(false);
  });

  it("rejects an altered clientDataJSON — the origin cannot be swapped after signing", async () => {
    const a = await signedAssertion();
    const tampered = utf8(JSON.stringify({ ...a.clientData, origin: "https://evil.example" }));
    const res = await verifyBytes(a.record, a.authData, tampered, a.signature);
    expect(res.ok).toBe(false);
  });

  it("rejects an altered challenge — a replayed login signs the wrong one", async () => {
    const a = await signedAssertion();
    const tampered = utf8(JSON.stringify({ ...a.clientData, challenge: "ZGlmZmVyZW50" }));
    expect((await verifyBytes(a.record, a.authData, tampered, a.signature)).ok).toBe(false);
  });

  it("rejects altered authenticatorData — the UV bit cannot be forged on", async () => {
    const a = await signedAssertion({ authData: buildAuthData({ flags: FLAG.UP }) });
    const lying = Uint8Array.from(a.authData);
    lying[32] |= FLAG.UV;
    expect((await verifyBytes(a.record, lying, a.clientDataJSON, a.signature)).ok).toBe(false);
  });

  it("rejects a bumped sign counter", async () => {
    const a = await signedAssertion({ authData: buildAuthData({ flags: FLAG.UP | FLAG.UV, signCount: 4 }) });
    const lying = Uint8Array.from(a.authData);
    lying[36] = 99;
    expect((await verifyBytes(a.record, lying, a.clientDataJSON, a.signature)).ok).toBe(false);
  });

  it("reports a rejection rather than throwing when the signature is not decodable DER", async () => {
    const a = await signedAssertion();
    const res = await verifyBytes(a.record, a.authData, a.clientDataJSON, bytes(0x01, 0x02, 0x03));
    expect(res.ok).toBe(false);
    expect(res.reason).toMatch(/^rejected: /);
  });
});

describe("verifyBytes — RS256", () => {
  it("accepts a genuine RSA signature", async () => {
    const a = await signedAssertion({ alg: -257 });
    const res = await verifyBytes(a.record, a.authData, a.clientDataJSON, a.signature);
    expect(res.ok).toBe(true);
    expect(res.reason).toBe("RS256 / RSA");
  });

  it("rejects a flipped byte", async () => {
    const a = await signedAssertion({ alg: -257 });
    expect((await verifyBytes(a.record, a.authData, a.clientDataJSON, a.signature, true)).ok).toBe(false);
  });

  it("rejects a different RSA key", async () => {
    const a = await signedAssertion({ alg: -257 });
    const res = await verifyBytes(await otherPublicKey(-257), a.authData, a.clientDataJSON, a.signature);
    expect(res.ok).toBe(false);
  });
});

describe("verifyBytes — when it cannot answer, it says so", () => {
  it("returns null, not false, with no stored public key", async () => {
    const a = await signedAssertion();
    const res = await verifyBytes({ publicKeyAlgorithm: -7 }, a.authData, a.clientDataJSON, a.signature);
    expect(res.ok).toBe(null);
    expect(res.reason).toBe("no stored public key to verify against");
  });

  it("returns null for a missing record entirely", async () => {
    const a = await signedAssertion();
    for (const rec of [null, undefined]) {
      const res = await verifyBytes(rec, a.authData, a.clientDataJSON, a.signature);
      expect(res.ok).toBe(null);
    }
  });

  it("returns null for an algorithm it does not implement", async () => {
    const a = await signedAssertion();
    const res = await verifyBytes({ ...a.record, publicKeyAlgorithm: -8 }, a.authData, a.clientDataJSON, a.signature);
    expect(res.ok).toBe(null);
    expect(res.reason).toBe("unsupported alg -8");
  });

  it("returns false, not null, when the stored key is corrupt", async () => {
    const a = await signedAssertion();
    const res = await verifyBytes({ publicKey: b64url(bytes(1, 2, 3, 4)), publicKeyAlgorithm: -7 },
      a.authData, a.clientDataJSON, a.signature);
    expect(res.ok).toBe(false);
  });

  it("never returns true for any of the cannot-answer cases", async () => {
    const a = await signedAssertion();
    const results = await Promise.all([
      verifyBytes(null, a.authData, a.clientDataJSON, a.signature),
      verifyBytes({ publicKeyAlgorithm: -7 }, a.authData, a.clientDataJSON, a.signature),
      verifyBytes({ ...a.record, publicKeyAlgorithm: 0 }, a.authData, a.clientDataJSON, a.signature),
    ]);
    for (const r of results) expect(r.ok).not.toBe(true);
  });
});

describe("verifyAssertion — the response-shaped wrapper", () => {
  it("pulls the three fields off an assertion response", async () => {
    const a = await signedAssertion();
    const resp = {
      authenticatorData: a.authData,
      clientDataJSON: a.clientDataJSON,
      signature: a.signature,
    };
    expect((await verifyAssertion(a.record, resp)).ok).toBe(true);
    expect((await verifyAssertion(a.record, resp, true)).ok).toBe(false);
  });

  it("works when the response hands back ArrayBuffers, as a browser does", async () => {
    const a = await signedAssertion();
    const resp = {
      authenticatorData: a.authData.buffer.slice(a.authData.byteOffset, a.authData.byteOffset + a.authData.byteLength),
      clientDataJSON: a.clientDataJSON.buffer.slice(a.clientDataJSON.byteOffset, a.clientDataJSON.byteOffset + a.clientDataJSON.byteLength),
      signature: a.signature.buffer.slice(a.signature.byteOffset, a.signature.byteOffset + a.signature.byteLength),
    };
    expect((await verifyAssertion(a.record, resp)).ok).toBe(true);
  });
});
