// Passkey Lab — shared UI pieces used by both the bench and the guided rail.
// Error translation, OS detection, and the per-OS cleanup instructions.

import {
  esc, toHex, inspectAuthData, flagBits, coseInfo, walletName, aaguidStr,
  spkiToPem, algName,
} from "./core.js";

// ---------- shared markup builders ----------
// The raw inspector's vocabulary. The X-ray reuses these rather than growing its own, so
// "expand raw" anywhere in the lab shows the same hex and the same COSE breakdown.
export const section = (t, inner) => `<section class="insp-sec"><h3>${t}</h3>${inner}</section>`;
export const rows = (pairs) => `<dl class="prove-rows">` +
  pairs.map(([k, v, m]) => `<div class="prow ${m || ""}"><dt>${k}</dt><dd>${v}</dd></div>`).join("") + `</dl>`;
export const hexPre = (u8) => `<pre class="hex">${toHex(u8)}</pre>`;

export function buildAuthDataSection(ad, includeCose) {
  const p = inspectAuthData(ad);
  if (p.truncated) return section("authenticatorData", `<p class="insp-note">Only ${p.byteLength} bytes — too short to decode.</p>`);
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

// ---------- modal ----------
const $ = (id) => document.getElementById(id);
let modalReturnFocus = null;

export function openModal(title, html) {
  modalReturnFocus = document.activeElement;
  $("insp-title").textContent = title;
  $("insp-body").innerHTML = html;
  $("inspector").hidden = false;
  $("insp-close").focus();
  return $("insp-body");
}

export function closeModal() {
  if ($("inspector").hidden) return;
  $("inspector").hidden = true;
  $("insp-body").innerHTML = "";
  if (modalReturnFocus && modalReturnFocus.focus) modalReturnFocus.focus();
  modalReturnFocus = null;
}

// Keep Tab focus inside the open modal.
export function trapModalTab(e) {
  if (e.key !== "Tab" || $("inspector").hidden) return;
  const f = [...$("inspector").querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
    .filter((el) => !el.disabled && el.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

// ---------- the record card ----------
// What a relying party actually holds after registration. The point of the card is how
// little that is — there is no password row because there is no password.
export function recordCardHtml(rec) {
  if (!rec) return `<p class="insp-note">That record is no longer in the ledger.</p>`;
  const backed = rec.backupEligible == null
    ? "unknown (this record predates the flag)"
    : rec.backupEligible ? (rec.backupState ? "yes — synced to a cloud account" : "eligible, but not yet") : "no — device-bound";

  return `<div class="prove-out record-card">
    <h3>The server's entire database about you</h3>
    ${rows([
      ["Credential ID", `<span class="mono record-id">${esc(rec.id)}</span>`],
      ["Public key", rec.publicKey
        ? `<pre class="hex record-pem">${esc(spkiToPem(rec.publicKey))}</pre><span class="insp-note">${esc(algName(rec.publicKeyAlgorithm))}</span>`
        : "not captured for this record"],
      ["Sign-in counter", `<span class="mono">${Number(rec.signIns || 0)}</span>`],
      ["Created", esc(new Date(rec.created).toLocaleString())],
      ["Backed up", esc(backed), rec.backupState ? "ok" : ""],
    ])}
    <p class="cause record-caption">No password. No password hash. No secret. Steal this and you can verify signatures — you can't make one.</p>
  </div>`;
}

export const openRecordCard = (rec) => openModal("Everything the site knows about you", recordCardHtml(rec));

// ---------- error translation ----------
// WebAuthn's DOMException names mean nothing to an L1 tech. The rail always shows the
// translation; the bench shows the translation plus the raw name, because on the bench the
// raw name is part of what is being taught.
export function translateError(err) {
  if (!err) return "Something unexpected happened. Refresh and try again.";
  switch (err.name) {
    case "NotAllowedError":
      return "You cancelled, or it timed out. No harm done — go again.";
    case "InvalidStateError":
      return "The authenticator already has a passkey for this account, so registration was blocked. This is the 'no duplicate on the same device' rule.";
    case "NotSupportedError":
      return "This browser or device can't do that particular option — see the note near the button.";
    case "SecurityError":
      return "Passkeys only work over HTTPS on the matching domain.";
    case "AbortError":
      return "The request was interrupted — usually two prompts overlapping. Refresh and go again.";
    default:
      return `Something unexpected happened: ${err.name}. Refresh and try again.`;
  }
}

// ---------- host platform ----------
// Only ever used to decide which cleanup instructions to open first, so a UA guess is fine —
// every other platform is one click away.
export function detectOs() {
  const ua = navigator.userAgent || "";
  const plat = navigator.platform || "";
  if (/iPhone|iPad|iPod/.test(ua) || (plat === "MacIntel" && navigator.maxTouchPoints > 1)) return "ios";
  if (/Android/.test(ua)) return "android";
  if (/Win/.test(ua) || /Windows/.test(plat)) return "windows";
  if (/Mac/.test(ua)) return "macos";
  if (/Linux|X11/.test(ua)) return "linux";
  return "unknown";
}

export const isFirefoxOnLinux = () =>
  /Firefox/.test(navigator.userAgent || "") && /Linux|X11/.test(navigator.userAgent || "");

// ---------- cleanup instructions ----------
// A lab passkey is a real passkey: it lives in the device's own store, and clearing the
// lab's list does not touch it. One disclosure per place it might be, with the detected
// platform open by default.
const CLEANUP = [
  { os: "windows", label: "Windows", body: `Settings &rarr; Accounts &rarr; Passkeys &rarr; &ldquo;Passkey Lab&rdquo; &rarr; delete` },
  { os: "ios",     label: "iPhone/iPad", body: `Passwords app &rarr; search this site &rarr; delete` },
  { os: "android", label: "Android", body: `Google Password Manager &rarr; search this site &rarr; delete` },
  { os: "phone",   label: "Phone passkey from Step 3", body: `delete on the phone &mdash; it lives there` },
  { os: "lastpass", label: "LastPass", body: `it&rsquo;s a vault item &mdash; delete it there` },
];

export function cleanupListHtml(os = detectOs()) {
  // macOS keychain passkeys live in the same Passwords app as iOS, so open that one there too.
  const openFor = os === "macos" ? "ios" : os;
  return `<div class="cleanup-list">` + CLEANUP.map((c) =>
    `<details class="cleanup-os"${c.os === openFor ? " open" : ""}>
       <summary><strong>${esc(c.label)}</strong></summary>
       <p>${c.body}</p>
     </details>`).join("") + `</div>`;
}
