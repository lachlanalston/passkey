// parseAuthData / inspectAuthData / flagBits / syncLabel — the flag byte is the thing the
// whole lab reads meaning off, so every combination that changes the story is pinned here.

import { describe, it, expect } from "vitest";
import {
  parseAuthData, inspectAuthData, flagBits, syncLabel, aaguidStr, walletName, AAGUIDS, algName,
} from "../../core.js";
import { buildAuthData, FLAG, fill, counting, coseEc2, coseRsa } from "./fixtures.js";

describe("parseAuthData — flags", () => {
  it("reads nothing set", () => {
    const f = parseAuthData(buildAuthData({ flags: 0 }));
    expect(f).toMatchObject({
      userPresent: false, userVerified: false,
      backupEligible: false, backupState: false,
      attestedCredentialData: false, extensionData: false,
    });
  });

  it("reads UP alone — a touch, with nobody identified", () => {
    const f = parseAuthData(buildAuthData({ flags: FLAG.UP }));
    expect(f.userPresent).toBe(true);
    expect(f.userVerified).toBe(false);
  });

  it("reads UP + UV — a PIN or biometric was checked", () => {
    const f = parseAuthData(buildAuthData({ flags: FLAG.UP | FLAG.UV }));
    expect(f.userPresent).toBe(true);
    expect(f.userVerified).toBe(true);
  });

  it("reads BE without BS — sync-eligible but not yet backed up", () => {
    const f = parseAuthData(buildAuthData({ flags: FLAG.UP | FLAG.UV | FLAG.BE }));
    expect(f.backupEligible).toBe(true);
    expect(f.backupState).toBe(false);
    expect(syncLabel(f)).toBe("Sync-eligible, not yet backed up");
  });

  it("reads BE + BS — a live synced passkey", () => {
    const f = parseAuthData(buildAuthData({ flags: FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS }));
    expect(f.backupEligible).toBe(true);
    expect(f.backupState).toBe(true);
    expect(syncLabel(f)).toBe("Synced (multi-device passkey)");
  });

  it("reads neither BE nor BS — device-bound", () => {
    const f = parseAuthData(buildAuthData({ flags: FLAG.UP | FLAG.UV }));
    expect(syncLabel(f)).toBe("Device-bound (single-device)");
  });

  it("reads ED", () => {
    expect(parseAuthData(buildAuthData({ flags: FLAG.UP | FLAG.ED })).extensionData).toBe(true);
  });
});

describe("parseAuthData — attested credential data", () => {
  it("extracts and dashes the AAGUID when AT is set", () => {
    const aaguid = Uint8Array.from([
      0x08, 0x98, 0x70, 0x58, 0xca, 0xdc, 0x4b, 0x81,
      0xb6, 0xe1, 0x30, 0xde, 0x50, 0xdc, 0xbe, 0x96,
    ]);
    const f = parseAuthData(buildAuthData({ flags: FLAG.UP | FLAG.AT, aaguid }));
    expect(f.attestedCredentialData).toBe(true);
    expect(f.aaguid).toBe("08987058-cadc-4b81-b6e1-30de50dcbe96");
    expect(walletName(f.aaguid)).toBe("Windows Hello");
  });

  it("reports no aaguid when AT is absent", () => {
    const f = parseAuthData(buildAuthData({ flags: FLAG.UP | FLAG.UV }));
    expect(f.attestedCredentialData).toBe(false);
    expect(f.aaguid).toBeUndefined();
  });

  it("leaves aaguid out when AT is set but the bytes are too short to hold one", () => {
    const short = buildAuthData({ flags: FLAG.UP | FLAG.AT }).slice(0, 45);
    const f = parseAuthData(short);
    expect(f.attestedCredentialData).toBe(true);
    expect(f.aaguid).toBeUndefined();
  });
});

describe("parseAuthData — counter and length guard", () => {
  it("reads signCount big-endian", () => {
    expect(parseAuthData(buildAuthData({ signCount: 0 })).signCount).toBe(0);
    expect(parseAuthData(buildAuthData({ signCount: 1 })).signCount).toBe(1);
    expect(parseAuthData(buildAuthData({ signCount: 0x01020304 })).signCount).toBe(16909060);
    expect(parseAuthData(buildAuthData({ signCount: 0xfffffffe })).signCount).toBe(4294967294);
  });

  it("returns a partial result rather than reading past the end", () => {
    expect(parseAuthData(new Uint8Array(36))).toEqual({ truncated: true, byteLength: 36 });
    expect(parseAuthData(new Uint8Array(0))).toEqual({ truncated: true, byteLength: 0 });
    expect(parseAuthData(new Uint8Array(37)).truncated).toBeUndefined();
  });

  it("accepts a view into a larger buffer without reading its neighbours", () => {
    const backing = new Uint8Array(200).fill(0xff);
    const ad = buildAuthData({ flags: FLAG.UP | FLAG.UV, signCount: 7 });
    backing.set(ad, 40);
    const view = new Uint8Array(backing.buffer, 40, ad.length);
    expect(parseAuthData(view)).toMatchObject({ userPresent: true, userVerified: true, signCount: 7 });
  });
});

describe("inspectAuthData", () => {
  it("splits out rpIdHash, flags, counter and the attested key", () => {
    const rpIdHash = counting(32);
    const credId = counting(24, 0x90);
    const p = inspectAuthData(buildAuthData({
      rpIdHash, flags: FLAG.UP | FLAG.UV | FLAG.AT, signCount: 5, credId, cose: coseEc2(),
    }));
    expect([...p.rpIdHash]).toEqual([...rpIdHash]);
    expect(p.flags).toBe(FLAG.UP | FLAG.UV | FLAG.AT);
    expect(p.signCount).toBe(5);
    expect([...p.credId]).toEqual([...credId]);
    expect(p.cose).toBeInstanceOf(Map);
    expect(p.cose.get(1)).toBe(2);
  });

  it("omits the credential block when AT is absent", () => {
    const p = inspectAuthData(buildAuthData({ flags: FLAG.UP }));
    expect(p.credId).toBeUndefined();
    expect(p.cose).toBeUndefined();
  });

  it("guards short input the same way parseAuthData does", () => {
    expect(inspectAuthData(new Uint8Array(10))).toEqual({ truncated: true, byteLength: 10 });
  });
});

describe("flagBits", () => {
  it("renders the byte and names every bit that is set", () => {
    const fb = flagBits(FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS | FLAG.AT);
    expect(fb.bin).toBe("0b01011101");
    expect(fb.set).toBe([
      "UP — User present",
      "UV — User verified",
      "BE — Backup eligible",
      "BS — Backup state",
      "AT — Attested credential data",
    ].join("<br>"));
  });

  it("says so when nothing is set", () => {
    expect(flagBits(0)).toEqual({ bin: "0b00000000", set: "none set" });
  });
});

describe("AAGUID naming", () => {
  it("dashes 16 raw bytes into the canonical form", () => {
    expect(aaguidStr(Uint8Array.from([
      0xfb, 0xfc, 0x30, 0x07, 0x15, 0x4e, 0x4e, 0xcc,
      0x8c, 0x0b, 0x6e, 0x02, 0x05, 0x57, 0xd7, 0xbd,
    ]))).toBe("fbfc3007-154e-4ecc-8c0b-6e020557d7bd");
  });

  it("names known authenticators and shows unknown ones raw", () => {
    expect(walletName("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")).toBe("Apple iCloud Keychain");
    expect(walletName("d548826e-79b4-db40-a3d8-11116f7e8349")).toBe("LastPass");
    expect(walletName("00000000-0000-0000-0000-000000000000")).toBe("Privacy (no AAGUID reported)");
    expect(walletName("11111111-2222-3333-4444-555555555555")).toBe("Unknown (11111111-2222-3333-4444-555555555555)");
    expect(walletName(null)).toBe("Unknown (n/a)");
  });

  it("keeps the all-zero AAGUID in the map, since that is what most platforms report", () => {
    expect(AAGUIDS["00000000-0000-0000-0000-000000000000"]).toBeDefined();
  });
});

describe("algName", () => {
  it("names the two algorithms the lab registers", () => {
    expect(algName(-7)).toBe("ES256");
    expect(algName(-257)).toBe("RS256");
    expect(algName(-8)).toBe("alg -8");
  });
});

describe("a full attested registration blob", () => {
  it("round-trips an RSA credential too", () => {
    const ad = buildAuthData({ flags: FLAG.UP | FLAG.UV | FLAG.AT, cose: coseRsa() });
    const p = inspectAuthData(ad);
    expect(p.cose.get(1)).toBe(3);
    expect(p.cose.get(3)).toBe(-257);
    expect(parseAuthData(ad).attestedCredentialData).toBe(true);
  });

  it("handles a zero-length credential id", () => {
    const p = inspectAuthData(buildAuthData({ flags: FLAG.AT, credId: fill(0) }));
    expect(p.credId.length).toBe(0);
    expect(p.cose).toBeInstanceOf(Map);
  });
});
