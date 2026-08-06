// Passkey Lab — the Ceremony X-ray.
// Presentation only. Every value below is decoded by core.js from the bytes the browser
// actually returned; nothing here is simulated and nothing is hardcoded — least of all the
// verification result.

import {
  esc, b64urlDecode, syncLabel, walletName, coseInfo, inspectAuthData, derRS,
  spkiToPem, algName,
} from "./core.js";
import { section, rows, hexPre, buildAuthDataSection } from "./ui.js";

const LANE_SITE = "site";
const LANE_AUTH = "auth";

// Two things that never move, stated once and kept on screen for the whole ceremony.
const BADGES = `<div class="xray-badges">
  <p class="xray-badge"><span aria-hidden="true">🔒</span> <strong>Private key</strong> — never leaves the authenticator</p>
  <p class="xray-badge"><span aria-hidden="true">🔒</span> <strong>Your fingerprint/face</strong> — checked inside the device, never transmitted</p>
</div>`;

const truncate = (s, n = 44) => (s.length > n ? esc(s.slice(0, n)) + "…" : esc(s));

// A value long enough to need hiding: show the head, keep the whole thing one click away.
function long(value, label = "full value") {
  const full = String(value);
  if (full.length <= 44) return `<span class="mono">${esc(full)}</span>`;
  return `<span class="mono">${truncate(full)}</span>
    <details class="xray-more"><summary>${esc(label)}</summary><p class="mono xray-full">${esc(full)}</p></details>`;
}

const tick = (on) => on
  ? `<span class="xray-tick is-on" aria-hidden="true">✓</span>`
  : `<span class="xray-tick" aria-hidden="true">✗</span>`;

function node({ n, lane, wire, title, rowsHtml = "", caption = "", note = "", raw = "" }) {
  const wireTag = wire === "out"
    ? `<span class="xray-wire">crossed the wire <span aria-hidden="true">→</span></span>`
    : wire === "in"
      ? `<span class="xray-wire"><span aria-hidden="true">←</span> crossed the wire</span>`
      : "";
  return `<article class="xray-node lane-${lane}${wire ? " has-wire wire-" + wire : ""}">
    <p class="xray-n"><span class="xray-num">${n}</span>
      <span class="xray-lane-label">${lane === LANE_SITE ? "This site" : "Your authenticator"}</span>
      ${wireTag}</p>
    <h4 class="xray-title">${title}</h4>
    ${rowsHtml}
    ${caption ? `<p class="xray-caption">${caption}</p>` : ""}
    ${note ? `<p class="xray-note">${note}</p>` : ""}
    ${raw ? `<details class="xray-raw"><summary>expand raw</summary><div class="xray-rawbody">${raw}</div></details>` : ""}
  </article>`;
}

// ---------- registration ----------
function registrationNodes(res, recordLink) {
  const f = res.flags || {};
  const cd = res.clientData || {};
  const ad = res.raw && res.raw.authData;
  const p = ad ? inspectAuthData(ad) : null;
  const cose = p && p.cose ? coseInfo(p.cose) : null;
  const wallet = res.record.aaguid ? walletName(res.record.aaguid) : "not reported";

  const backed = f.backupEligible
    ? (f.backupState
        ? `<strong>backed up: yes</strong> → synced passkey (iCloud / Google / LastPass)`
        : `<strong>backed up: not yet</strong> → sync-eligible, but this copy hasn't left the device`)
    : `<strong>backed up: no</strong> → device-bound`;

  return [
    node({
      n: 1, lane: LANE_SITE,
      title: "This site invented a challenge",
      rowsHtml: rows([
        ["challenge", long(res.challenge, "show all 32 bytes, base64url")],
        ["size", `<span class="mono">32 bytes</span>, freshly random`],
      ]),
      caption: "Thirty-two bytes from the browser's cryptographic random source. They will never be used again.",
      raw: section("challenge — raw bytes", hexPre(b64urlDecode(res.challenge))),
    }),
    node({
      n: 2, lane: LANE_SITE, wire: "out",
      title: "The browser passed the challenge along — with this site's identity attached",
      rowsHtml: rows([
        ["origin", esc(cd.origin || "—"), "ok"],
        ["rp.id", esc(res.record.rpId), "ok"],
        ["type", esc(cd.type || "webauthn.create")],
      ]),
      caption: "The site's identity gets sealed in from the very first moment — the authenticator signs it, so it can never be swapped for a lookalike later.",
      raw: res.raw && res.raw.clientDataJSON
        ? section("clientDataJSON — the browser's signed statement of context",
            rows([
              ["type", esc(cd.type)],
              ["challenge", `<span class="mono">${esc(cd.challenge)}</span>`],
              ["origin", esc(cd.origin), "ok"],
              ["crossOrigin", esc(String(cd.crossOrigin))],
            ]) + `<p class="insp-note">Raw bytes:</p>` + hexPre(res.raw.clientDataJSON))
        : "",
    }),
    node({
      n: 3, lane: LANE_AUTH,
      title: "You proved it was you",
      rowsHtml: rows([
        ["User present (UP)", `${tick(f.userPresent)} ${f.userPresent ? "someone was physically there" : "not set"}`, f.userPresent ? "ok" : "bad"],
        ["User verified (UV)", `${tick(f.userVerified)} ${f.userVerified ? "fingerprint, face or PIN checked" : "not verified"}`, f.userVerified ? "ok" : "bad"],
      ]),
      caption: "🔒 That check happened inside the device. The biometric never became data, never left, and this site was only ever told <em>yes</em>.",
      raw: ad ? buildAuthDataSection(ad, false) : "",
    }),
    node({
      n: 4, lane: LANE_AUTH, wire: "in",
      title: "A key pair was made — and only the public half came back",
      rowsHtml: rows([
        ["credential ID", long(res.record.id, "show the full ID")],
        ["made by", esc(wallet), "ok"],
        ["algorithm", `<span class="mono">${esc(algName(res.record.publicKeyAlgorithm))}</span>${cose ? ` · ${esc(cose.type)}${cose.crv ? " · " + esc(String(cose.crv)) : ""}` : ""}`],
        ["portability", `${backed}<br><span class="xray-sub">${esc(syncLabel(f))}</span>`, f.backupState ? "ok" : ""],
      ]),
      caption: "🔒 The private half was written into the authenticator and cannot be read out of it — not by this site, not by you, not by malware with your password.",
      raw: ad ? buildAuthDataSection(ad, true) : "",
    }),
    node({
      n: 5, lane: LANE_SITE,
      title: "This site stored the public key — and nothing else",
      rowsHtml: rows([
        ["stored", res.record.publicKey ? "public key (SPKI)" : "no public key returned", res.record.publicKey ? "ok" : "bad"],
        ["password stored", "none — there isn't one", "ok"],
        ["sign-in counter", `<span class="mono">${p ? p.signCount : "—"}</span>`],
      ]),
      caption: `This is the entire server-side record.${recordLink
        ? ` <button type="button" class="link" data-xray-record="${esc(res.record.id)}">See everything the site knows about you</button>.`
        : ""}`,
      raw: res.record.publicKey
        ? section("Public key (PEM) — the only half a server keeps", `<pre class="hex">${esc(spkiToPem(res.record.publicKey))}</pre>`)
        : "",
    }),
  ];
}

// ---------- authentication ----------
function authenticationNodes(res) {
  const f = res.flags || {};
  const cd = res.clientData || {};
  const ad = res.raw && res.raw.authData;
  const sig = res.raw && res.raw.signature;
  const rs = sig ? derRS(sig) : null;

  const counterNote = f.signCount === 0
    ? ` <span class="xray-sub">(0 is normal — most modern authenticators deliberately don't count, for privacy)</span>`
    : "";

  // The one node that must never be decorative: whatever verifyBytes actually returned.
  const v = res.verify || { ok: null, reason: "not checked" };
  const verifyRows = v.ok === true
    ? rows([
        ["Result", `${tick(true)} <strong>VALID</strong> — the signature matches the stored public key`, "ok"],
        ["Checked with", esc(v.reason)],
        ["Bytes that were signed", "authenticatorData + SHA-256(clientDataJSON)"],
      ])
    : v.ok === false
      ? rows([
          ["Result", `${tick(false)} <strong>INVALID</strong> — a real server would reject this login`, "bad"],
          ["Checked with", esc(v.reason)],
        ])
      : rows([
          ["Result", "not checked", "bad"],
          ["Why", esc(v.reason)],
        ]);

  const verifyCaption = v.ok === null
    ? "Can't verify this one — it predates the X-ray or isn't in the lab's ledger. Create a fresh passkey to watch verification happen."
    : v.ok === true
      ? "Nothing was trusted on its word. The signature was re-checked here, in this browser, against the public key stored at registration."
      : "The signed bytes and the signature disagree. That is the whole defence: alter anything and the check fails.";

  return [
    node({
      n: 1, lane: LANE_SITE,
      title: "This site invented a new challenge",
      rowsHtml: rows([
        ["challenge", long(res.challenge, "show all 32 bytes, base64url")],
        ["reused?", "never — a fresh 32 bytes every single sign-in", "ok"],
      ]),
      caption: "This is what makes a captured login worthless: the next one is asked a different question.",
      raw: section("challenge — raw bytes", hexPre(b64urlDecode(res.challenge))),
    }),
    node({
      n: 2, lane: LANE_SITE, wire: "out",
      title: "The browser passed it on — with this site's identity attached",
      rowsHtml: rows([
        ["origin", esc(cd.origin || "—"), "ok"],
        ["type", esc(cd.type || "webauthn.get")],
        ["challenge echoed back", res.echoed ? "yes — byte for byte" : "no", res.echoed ? "ok" : "bad"],
      ]),
      caption: "The authenticator will only answer for the site the passkey was made for. A lookalike domain asks and gets nothing.",
      raw: res.raw && res.raw.clientDataJSON
        ? section("clientDataJSON — the browser's signed statement of context",
            rows([
              ["type", esc(cd.type)],
              ["challenge", `<span class="mono">${esc(cd.challenge)}</span>`],
              ["origin", esc(cd.origin), "ok"],
              ["crossOrigin", esc(String(cd.crossOrigin))],
            ]) + `<p class="insp-note">Raw bytes:</p>` + hexPre(res.raw.clientDataJSON))
        : "",
    }),
    node({
      n: 3, lane: LANE_AUTH,
      title: "You proved it was you — again",
      rowsHtml: rows([
        ["User present (UP)", `${tick(f.userPresent)} ${f.userPresent ? "someone was physically there" : "not set"}`, f.userPresent ? "ok" : "bad"],
        ["User verified (UV)", `${tick(f.userVerified)} ${f.userVerified ? "fingerprint, face or PIN checked" : "not verified"}`, f.userVerified ? "ok" : "bad"],
      ]),
      caption: "🔒 Checked inside the device, every time. There is no cached 'trusted for 30 days' here unless a server asks for one.",
      raw: ad ? buildAuthDataSection(ad, false) : "",
    }),
    node({
      n: 4, lane: LANE_AUTH, wire: "in",
      title: "The authenticator signed, and sent back a signature",
      rowsHtml: rows([
        ["signature", sig ? long(Array.from(sig.slice(0, 24)).map((b) => b.toString(16).padStart(2, "0")).join(""), "show the r and s halves") : "—"],
        ["sign counter", `<span class="mono">${f.signCount ?? "—"}</span>${counterNote}`],
        ["what was NOT sent", "the private key, and anything about your fingerprint", "ok"],
      ]),
      caption: "🔒 A signature proves the private key was used without revealing one bit of it. That is the entire trick.",
      raw: sig
        ? (rs
            ? section("Signature", rows([
                ["algorithm", esc(algName(res.record?.publicKeyAlgorithm))],
                ["r", hexPre(rs.r)],
                ["s", hexPre(rs.s)],
              ]))
            : section("Signature", `<p class="insp-note">Raw signature bytes:</p>` + hexPre(sig)))
        : "",
    }),
    node({
      n: 5, lane: LANE_SITE,
      title: "This site checked the signature",
      rowsHtml: verifyRows,
      caption: verifyCaption,
      raw: res.record && res.record.publicKey
        ? section("The public key it was checked against", `<pre class="hex">${esc(spkiToPem(res.record.publicKey))}</pre>`)
        : "",
    }),
  ];
}

// ---------- the component ----------
// kind: "registration" | "authentication"
export function xrayHtml(kind, res, { open = false, recordLink = false } = {}) {
  const nodes = kind === "registration" ? registrationNodes(res, recordLink) : authenticationNodes(res);
  const title = kind === "registration" ? "What just happened, underneath" : "The conversation that just happened";
  const summary = kind === "registration"
    ? "Registration ceremony X-ray: five nodes, from the challenge to the stored public key."
    : `Authentication ceremony X-ray: five nodes, ending in a ${res.verify?.ok === true ? "valid" : res.verify?.ok === false ? "failed" : "unchecked"} signature verification.`;

  return `<details class="xray"${open ? " open" : ""}>
    <summary class="xray-summary"><span class="eyebrow">Ceremony X-ray</span> <span class="xray-h">${esc(title)}</span></summary>
    <div class="xray-body" aria-live="polite">
      <p class="sr-only">${esc(summary)}</p>
      ${BADGES}
      <div class="xray-lanes" aria-hidden="true">
        <p class="xray-lane-head lane-site">This site</p>
        <p class="xray-lane-head lane-auth">Your authenticator</p>
      </div>
      <div class="xray-nodes">${nodes.join("")}</div>
    </div>
  </details>`;
}

// Wire the one interactive thing inside an X-ray: the link to the record card.
export function wireXray(root, onRecord) {
  if (!root || !onRecord) return;
  root.querySelectorAll("button[data-xray-record]").forEach((b) =>
    b.addEventListener("click", () => onRecord(b.dataset.xrayRecord)));
}
