// Passkey Lab — shared UI pieces used by both the bench and the guided rail.
// Error translation, OS detection, and the per-OS cleanup instructions.

import { esc } from "./core.js";

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
