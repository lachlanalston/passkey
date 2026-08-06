// Passkey Lab — Training Mode.
// Six steps, one visible at a time, each one a real WebAuthn ceremony followed by the X-ray
// of what actually happened. Every ceremony calls the parameterised functions in
// ceremonies.js with fixed options — the rail never reads a bench select.

import { esc, randomBytes, syncLabel } from "./core.js";
import { registerPasskey, signIn, runPhishing, loadCreds, saveCreds, credsForSite, STORE_KEY } from "./ceremonies.js";
import { translateError, cleanupListHtml, openRecordCard } from "./ui.js";
import { xrayHtml, wireXray } from "./xray.js";
import { TRAINING_KEY, TOTAL_STEPS, setMode, showView } from "./mode.js";
import { TWIN_URL } from "./config.js";

const $ = (id) => document.getElementById(id);

// ---------- state ----------
const blank = () => ({
  step: 1,
  completed: [],
  step1CredId: null,
  step3CredId: null,
  step3Skipped: false,
  step4Failed: false,
  startedAt: new Date().toISOString(),
});

let state = blank();

function load() {
  try {
    const raw = JSON.parse(localStorage.getItem(TRAINING_KEY) || "null");
    state = raw ? { ...blank(), ...raw, completed: raw.completed || [] } : blank();
  } catch { state = blank(); }
}
const save = () => localStorage.setItem(TRAINING_KEY, JSON.stringify(state));

const isDone = (n) => state.completed.includes(n);
const isSettled = (n) => isDone(n) || (n === 3 && state.step3Skipped);
// Completed steps stay revisitable; the step after the last settled one is the frontier;
// everything past that is locked.
const isUnlocked = (n) => n === 1 || isSettled(n - 1) || isDone(n);

function complete(n) {
  if (!isDone(n)) state.completed.push(n);
  save();
}

function goTo(n) {
  state.step = n;
  save();
  render();
  $("training-view").scrollIntoView({ block: "start", behavior: prefersReducedMotion() ? "auto" : "smooth" });
}

const prefersReducedMotion = () =>
  window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const labChars = () => [...randomBytes(4)].map((b) => "abcdefghijkmnpqrstuvwxyz23456789"[b % 32]).join("");

// ---------- copy ----------
// Every string below is the spec's, verbatim.
const STEPS = [
  {
    n: 1, tab: "Create", label: "Make your passkey",
    headline: "Make your first passkey",
    body: `<p>Click the button, then do whatever your computer asks — fingerprint, face, or your device PIN. That's the entire enrolment. Notice what it never asks for: no code, no password, nothing to memorise.</p>`,
    primary: "Create my passkey",
    entra: `In Microsoft 365 this exact operation runs when a user clicks <em>Security info → Add sign-in method → Passkey</em>. Same API, same result — Entra just never shows you what got created. Here, you can see it.`,
  },
  {
    n: 2, tab: "Sign in", label: "Sign in with it",
    headline: "Sign in with it — and watch the clock",
    body: `<p>One click, one gesture. We'll time it — and then show you the conversation that just happened.</p>`,
    primary: "Sign in with my passkey",
    entra: `When a client signs into Microsoft 365 with a passkey, this identical challenge-and-signature exchange runs against login.microsoftonline.com. You never see it there. The X-ray below is that exchange.`,
  },
  {
    n: 3, tab: "Phone", label: "Now from your phone",
    headline: "Do it the way clients will — from a phone",
    body: `<p>This time your computer shows a QR code. Scan it with your phone's <strong>normal camera</strong> — not a camera inside any app — then approve on the phone. Bluetooth must be ON, on both devices.</p>`,
    primary: "Create a phone passkey",
    skip: "No phone on you? Skip — you can come back.",
    entra: `On Microsoft sign-ins this option is labelled <strong>"iPhone, iPad or Android device"</strong>. Same machinery: the QR starts a one-time handshake, Bluetooth only proves the phone is physically near, the real data travels an encrypted internet tunnel. Entra shows none of that — the X-ray does.`,
  },
  {
    n: 4, tab: "Break it", label: "Break it on purpose",
    headline: "Break it — so you recognise the failure",
    body: `<ol class="rail-ol">
      <li>Turn your phone's <strong>Bluetooth OFF</strong>.</li>
      <li>Click "Try the phone sign-in" and scan the QR.</li>
      <li>Read the error — vague, unhelpful, and exactly what clients will describe.</li>
      <li>Bluetooth back <strong>ON</strong>, try again.</li>
    </ol>`,
    primary: "Try the phone sign-in",
    check: "I saw it fail, then fixed it with Bluetooth.",
    entra: `Entra's version of this error is just as vague. The cause and the fix are identical — proximity. Nothing in the Microsoft UI tells you Bluetooth is the reason; now you know it from the inside.`,
  },
  {
    n: 5, tab: "Steal it", label: "Try to steal it",
    headline: "Try to steal your own passkey",
    body: `<p>This runs a real phishing attempt from this page: it asks the browser for your passkey <strong>using the wrong site identity</strong> — exactly what a lookalike domain would do. Watch what happens. Or rather, what doesn't.</p>`,
    primary: "Run the phishing attempt",
    entra: `This is the demonstration Entra can never give you — nobody gets to phish a production identity provider to prove a point. It's the one part of how passkeys work that only a lab can show.`,
  },
  {
    n: 6, tab: "Clean up", label: "Clean up, and prove it",
    headline: "Clean up — lab passkeys are real passkeys",
    body: `<p>Your passkeys live in your real device, not on this website. "Clear list" only wipes the lab's records. Delete the real ones:</p>`,
    primary: "Prove it's gone",
    entra: `Deleting a client's passkey from their Entra sign-in methods is this same operation. And note what you just learned: marking a device "lost" doesn't kill a passkey — deletion does.`,
  },
];

const stepDef = (n) => STEPS.find((s) => s.n === n);

// Step 4 without a phone passkey: there is no QR to fail, so the failure is walked through
// in words instead of run. (Copy authored here — the spec asks for "a short illustrated
// walkthrough" without supplying it.)
const STEP4_NO_PHONE = `<p class="rail-note">You skipped the phone passkey, so there's no QR flow to break here. Read what it looks like instead — this is the call you will take.</p>
  <ol class="rail-ol">
    <li>The client picks <strong>"iPhone, iPad or Android device"</strong> and a QR code appears on their screen.</li>
    <li>They scan it with the phone camera. The phone shows <em>"Signing in to…"</em> and then stalls, or nothing happens at all.</li>
    <li>The computer eventually says something like <em>"Something went wrong"</em> or the request simply times out. No mention of Bluetooth anywhere.</li>
    <li>The cause is proximity: the QR carries a one-time key, but the two devices still have to find each other over <strong>Bluetooth</strong> to agree it's the same person, in the same room.</li>
    <li>The fix is Bluetooth ON, on <strong>both</strong> devices — then rescan. That is the whole ticket.</li>
  </ol>`;

// ---------- rendering ----------
function stepper() {
  return `<ol class="stepper">` + STEPS.map((s) => {
    const done = isDone(s.n);
    const cur = state.step === s.n;
    const open = isUnlocked(s.n);
    const cls = ["stepper-item", done ? "is-done" : "", cur ? "is-current" : "", open ? "" : "is-locked"].filter(Boolean).join(" ");
    return `<li class="${cls}">
      <button type="button" class="stepper-btn" data-goto="${s.n}"${open ? "" : " disabled"}
        ${cur ? ' aria-current="step"' : ""}>
        <span class="stepper-n">${done ? "✓" : s.n}</span>
        <span class="stepper-label">${esc(s.tab)}</span>
      </button></li>`;
  }).join("") + `</ol>`;
}

function actionsFor(s) {
  const bits = [`<button type="button" id="rail-primary" class="btn btn-primary">${esc(s.primary)}</button>`];
  // The in-page demo is the proof; the twin is the attacker's-eye view, and only exists if
  // one has been deployed to a different registrable domain.
  if (s.n === 5 && TWIN_URL) bits.push(`<button type="button" id="rail-twin" class="btn">Open the fake site</button>`);
  if (s.n === 3) bits.push(`<button type="button" id="rail-skip" class="link rail-skip">${esc(s.skip)}</button>`);
  return `<div class="actions-row rail-actions">${bits.join("")}</div>`;
}

function openTwin() {
  const frag = new URLSearchParams();
  if (state.step1CredId) frag.set("cred", state.step1CredId);
  frag.set("rp", location.hostname);
  window.open(`${TWIN_URL}#${frag.toString()}`, "_blank", "noopener");
}

function bodyFor(s) {
  if (s.n === 4 && state.step3Skipped && !state.step3CredId) return STEP4_NO_PHONE;
  if (s.n === 6) return s.body + cleanupListHtml();
  return s.body;
}

function checkboxFor(s) {
  if (s.n !== 4) return "";
  const walkthrough = state.step3Skipped && !state.step3CredId;
  const label = walkthrough ? "I read the failure walkthrough" : s.check;
  // Without this line the checkbox arrives unexplained: running the step completes it on its
  // own, so the box only exists for people who can't run it right now.
  const note = walkthrough
    ? "Tick the box when you've read it — that completes the step."
    : "Running it and watching it fail, then fixing it, completes this step on its own. No phone to hand, or already seen it? Tick the box below instead.";
  return `<p class="rail-check-note">${esc(note)}</p>
    <label class="rail-check"><input type="checkbox" id="rail-check"${isDone(4) ? " checked" : ""} />
    <span>${esc(label)}</span></label>`;
}

function finishScreen() {
  return `<section class="step rail-finish">
    <p class="eyebrow">Guided lab</p>
    <h2>Lab complete.</h2>
    <p class="rail-lede">You made one, used one, broke one, watched a phishing attempt get nothing, and deleted one — and you saw the actual challenge, signature and verification every time. That's the part Entra never shows anyone.</p>
    <h3 class="rail-keep-title">Three things to keep</h3>
    <ol class="rail-ol rail-keep">
      <li>The site's identity is sealed into every signature — that's why fakes get nothing.</li>
      <li>Cross-device = Bluetooth + internet, on <strong>both</strong> devices.</li>
      <li>Only the public key ever leaves the device — the private key and your fingerprint never do.</li>
    </ol>
    <div class="actions-row">
      <button type="button" id="rail-print" class="btn btn-primary">Save/print this page</button>
      <button type="button" id="rail-tobench" class="btn">Explore the bench</button>
      <button type="button" id="rail-again" class="btn btn-quiet">Reset and go again</button>
    </div>
  </section>`;
}

export function renderTraining() {
  load();
  render();
}

function render() {
  const host = $("training-view");
  const showFinish = state.step > TOTAL_STEPS && isDone(6);
  const s = stepDef(Math.min(Math.max(state.step, 1), TOTAL_STEPS));

  host.innerHTML = `
    <div class="rail">
      ${stepper()}
      ${showFinish ? finishScreen() : `
      <section class="step rail-step" aria-labelledby="rail-headline">
        <p class="eyebrow"><span class="idx">0${s.n}</span> Step ${s.n} of ${TOTAL_STEPS} · ${esc(s.label)}</p>
        <h2 id="rail-headline">${esc(s.headline)}</h2>
        <div class="rail-copy">${bodyFor(s)}</div>
        ${actionsFor(s)}
        ${checkboxFor(s)}
        <aside class="entra">
          <p class="entra-title">The Entra connection</p>
          <p class="entra-body">${s.entra}</p>
        </aside>
        <div id="rail-out" class="rail-out" aria-live="polite"></div>
      </section>`}
      <p class="rail-foot">
        <button type="button" id="rail-reset" class="link">Reset lab</button>
      </p>
    </div>`;

  wireStepper();
  $("rail-reset").addEventListener("click", resetLab);

  if (showFinish) {
    $("rail-print").addEventListener("click", () => window.print());
    $("rail-tobench").addEventListener("click", () => { setMode("bench"); showView("bench"); window.scrollTo(0, 0); });
    $("rail-again").addEventListener("click", resetLab);
    return;
  }

  $("rail-primary").addEventListener("click", () => runStep(s.n));
  if ($("rail-twin")) $("rail-twin").addEventListener("click", openTwin);
  if ($("rail-skip")) $("rail-skip").addEventListener("click", skipPhone);
  if ($("rail-check")) $("rail-check").addEventListener("change", (e) => {
    if (e.target.checked) {
      finishStep(4, resultCard({
        tone: "ok", verdict: "Noted",
        headline: "You've seen the failure and the fix.",
        note: "Proximity is the cause and Bluetooth is the fix — on <strong>both</strong> devices.",
      }));
    } else {
      state.completed = state.completed.filter((n) => n !== 4);
      delete lastResults[4];
      save(); render();
    }
  });

  // Re-show the last result when a completed step is revisited.
  if (lastResults[s.n]) { $("rail-out").innerHTML = lastResults[s.n]; wireOut(); }
}

function wireStepper() {
  document.querySelectorAll("#training-view button[data-goto]").forEach((b) =>
    b.addEventListener("click", () => goTo(+b.dataset.goto)));
}

// Tick the stepper in place, without tearing down the result the user is reading.
function refreshStepper() {
  const old = document.querySelector("#training-view .stepper");
  if (!old) return;
  old.outerHTML = stepper();
  wireStepper();
}

function resetLab() {
  if (!confirm("Reset the guided lab? Your progress through the six steps is cleared. Passkeys already on your device are not touched.")) return;
  localStorage.removeItem(TRAINING_KEY);
  for (const k of Object.keys(lastResults)) delete lastResults[k];
  state = blank();
  save();
  render();
  window.scrollTo(0, 0);
}

function skipPhone() {
  state.step3Skipped = true;
  save();
  goTo(4);
}

// ---------- result rendering ----------
// Kept per step so revisiting a finished step shows what happened, not an empty panel.
const lastResults = {};

function out(n, html) {
  lastResults[n] = html;
  const el = $("rail-out");
  if (el) { el.innerHTML = html; wireOut(); }
}

// A finished step ticks the stepper and offers the way on — it never yanks the reader off
// the result they just produced.
function finishStep(n, html) {
  complete(n);
  save();
  out(n, html + nextBar(n));
  refreshStepper();
}

function nextBar(n) {
  const next = stepDef(n + 1);
  const label = next ? `Next — ${esc(next.tab)}` : "See what you learned";
  return `<div class="actions-row rail-next"><button type="button" class="btn btn-primary" data-next="${n + 1}">${label} &rarr;</button></div>`;
}

// Everything inside #rail-out is regenerated HTML, so its buttons are wired here in one place.
function wireOut() {
  const el = $("rail-out");
  if (!el) return;
  el.querySelectorAll("button[data-next]").forEach((b) =>
    b.addEventListener("click", () => goTo(+b.dataset.next)));
  el.querySelectorAll("button[data-goto-inline]").forEach((b) =>
    b.addEventListener("click", () => goTo(+b.dataset.gotoInline)));
  el.querySelectorAll("button[data-skip-inline]").forEach((b) =>
    b.addEventListener("click", skipPhone));
  wireXray(el, (id) => openRecordCard(loadCreds().find((c) => c.id === id)));
}

// tone: ok | warn | bad
function resultCard({ tone = "ok", verdict, headline, rows = [], note = "" }) {
  const rowHtml = rows.length
    ? `<dl class="prove-rows">` + rows.map((r) =>
        `<div class="prow ${r.mark || ""}"><dt>${esc(r.k)}</dt><dd>${r.v}</dd></div>`).join("") + `</dl>`
    : "";
  return `<div class="prove-out prove-${tone} rail-result">
    ${verdict ? `<span class="verdict verdict-${tone}">${esc(verdict)}</span>` : ""}
    ${headline ? `<h3>${headline}</h3>` : ""}
    ${rowHtml}
    ${note ? `<p class="cause">${note}</p>` : ""}
  </div>`;
}

const errorCard = (err, extra = "") => resultCard({
  tone: "warn",
  verdict: "Didn't complete",
  headline: esc(translateError(err)),
  note: extra,
});

function busy(on, labelWhenBusy) {
  const b = $("rail-primary");
  if (!b) return;
  b.disabled = on;
  if (on) { b.dataset.idle = b.textContent; b.textContent = labelWhenBusy; }
  else if (b.dataset.idle) { b.textContent = b.dataset.idle; delete b.dataset.idle; }
}

// ---------- the steps ----------
async function runStep(n) {
  if (n === 1) return stepCreate();
  if (n === 2) return stepSignIn();
  if (n === 3) return stepPhone();
  if (n === 4) return stepBreak();
  if (n === 5) return stepPhish();
  if (n === 6) return stepProveGone();
}

async function platformAvailable() {
  try {
    return !!(window.PublicKeyCredential
      && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable
      && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable());
  } catch { return false; }
}

async function stepCreate() {
  const hasPlatform = await platformAvailable();
  const opts = {
    username: "lab-user-" + labChars(),
    residentKey: "required",
    userVerification: "required",
    attestation: "none",
  };
  // No built-in authenticator? Drop the constraint rather than fail — a phone or key is fine.
  if (hasPlatform) opts.attachment = "platform";
  opts.displayName = opts.username;

  busy(true, "Waiting for your device…");
  try {
    const res = await registerPasskey(opts);
    state.step1CredId = res.record.id;
    save();
    finishStep(1, registrationResult(res, hasPlatform ? "" :
      `<strong>No built-in authenticator here</strong> — your browser will offer a phone or security key instead. That works fine.`));
  } catch (err) {
    if (err.name === "InvalidStateError") {
      out(1, resultCard({
        tone: "warn",
        verdict: "Already exists",
        headline: "<strong>This device already has a passkey for the lab.</strong>",
        note: `In Entra this same collision shows up as "a passkey already exists". <button type="button" class="link" data-goto-inline="6">Jump to Step 6</button>, delete the old one, then come back.`,
      }));
    } else {
      out(1, errorCard(err));
    }
  } finally { busy(false); }
}

function registrationResult(res, extraNote = "") {
  const f = res.flags || {};
  const wallet = res.record.wallet && !res.record.wallet.startsWith("Unknown") ? res.record.wallet : "your device";
  const notes = [`<strong>That's it. Now look underneath.</strong>`];
  if (extraNote) notes.push(extraNote);
  return resultCard({
    tone: "ok",
    verdict: "Passkey created",
    headline: `Made in ${(res.ms / 1000).toFixed(1)} seconds, stored in ${esc(wallet)}`,
    rows: [
      { k: "Stored in", v: esc(res.record.wallet || "the authenticator") },
      { k: "Portability", v: esc(syncLabel(f)), mark: "ok" },
      { k: "Asked you for", v: f.userVerified ? "a fingerprint, face or PIN — nothing typed" : "a touch on the authenticator" },
      { k: "Password created", v: "none — there isn't one", mark: "ok" },
    ],
    note: notes.join(" "),
  }) + xraySlot("registration", res);
}

async function stepSignIn() {
  busy(true, "Waiting for your device…");
  try {
    const res = await signIn({ allowIds: [state.step1CredId].filter(Boolean), userVerification: "required" });
    if (res.none) { out(2, missingPasskeyCard()); return; }
    finishStep(2, resultCard({
      tone: res.verify.ok === false ? "bad" : "ok",
      verdict: res.verify.ok === true ? "Signed in — signature verified" : "Signed in",
      headline: `<strong>${(res.ms / 1000).toFixed(1)} seconds.</strong> A texted code averages over a minute.`,
      rows: [
        { k: "Signature checked", v: res.verify.ok === true ? "VALID — against the stored public key" : res.verify.ok === false ? "INVALID" : esc(res.verify.reason), mark: res.verify.ok === true ? "ok" : "bad" },
        { k: "Challenge echoed back", v: res.echoed ? "yes — the same fresh random bytes we just sent" : "no", mark: res.echoed ? "ok" : "bad" },
        { k: "User verified", v: res.flags.userVerified ? "yes — PIN or biometric checked on the device" : "no", mark: res.flags.userVerified ? "ok" : "" },
      ],
      note: "Below is that exchange, node by node.",
    }) + xraySlot("authentication", res));
  } catch (err) {
    out(2, errorCard(err));
  } finally { busy(false); }
}

async function stepPhone() {
  busy(true, "Scan the QR with your phone…");
  try {
    const res = await registerPasskey({
      username: "lab-phone-" + labChars(),
      displayName: "Lab phone passkey",
      attachment: "cross-platform",
      residentKey: "required",
      userVerification: "required",
      attestation: "none",
    });
    state.step3CredId = res.record.id;
    state.step3Skipped = false;
    save();
    // BS set means the phone has already pushed this key to its cloud account — the single
    // most useful thing to point at in the whole lab, so it gets called out by name.
    const synced = res.flags && res.flags.backupState
      ? `<p class="rail-highlight">See that? The phone synced this passkey to its cloud account — that's a synced passkey, live.</p>`
      : "";
    finishStep(3, registrationResult(res) + synced);
  } catch (err) {
    out(3, errorCard(err, `No phone to hand? <button type="button" class="link" data-skip-inline="1">Skip this step</button> — you can come back.`));
  } finally { busy(false); }
}

async function stepBreak() {
  const id = state.step3CredId || state.step1CredId;
  busy(true, "Waiting for your phone…");
  try {
    const res = await signIn({ allowIds: [id].filter(Boolean) });
    if (res.none) { out(4, missingPasskeyCard()); return; }
    if (state.step4Failed) {
      finishStep(4, resultCard({
        tone: "ok",
        verdict: "Failed, then worked",
        headline: "That's the whole ticket.",
        rows: [
          { k: "First attempt", v: "failed with Bluetooth off", mark: "bad" },
          { k: "This attempt", v: "worked with Bluetooth on", mark: "ok" },
          { k: "What changed", v: "proximity — nothing else" },
        ],
        note: "The two devices have to find each other over Bluetooth before the encrypted tunnel opens. Nothing in the error said so.",
      }) + xraySlot("authentication", res));
    } else {
      out(4, resultCard({
        tone: "ok",
        verdict: "Worked first time",
        headline: "That's the success case — now break it.",
        rows: [{ k: "Bluetooth", v: "on, on both devices", mark: "ok" }],
        note: "Turn your phone's Bluetooth <strong>off</strong> and click the button again to see the failure clients will describe. Or tick the box below if you have already seen it.",
      }) + xraySlot("authentication", res));
    }
  } catch (err) {
    state.step4Failed = true;
    save();
    out(4, resultCard({
      tone: "warn",
      verdict: "Failed — as designed",
      headline: esc(translateError(err)),
      rows: [
        { k: "What the browser said", v: esc(err.name), mark: "bad" },
        { k: "What it did not say", v: "Bluetooth", mark: "bad" },
        { k: "Actual cause", v: "the two devices could not reach each other" },
      ],
      note: "That is exactly what a client will read out to you. Turn Bluetooth back <strong>on</strong>, on both devices, and click the button again.",
    }));
  } finally { busy(false); }
}

async function stepPhish() {
  busy(true, "Asking with the wrong identity…");
  const res = await runPhishing();
  busy(false);
  if (!res.blocked) {
    out(5, resultCard({
      tone: "bad", verdict: "Not blocked", headline: "Unexpected — check the environment",
      rows: [{ k: "Requested rpId", v: esc(res.fakeRp), mark: "bad" }, { k: "Real origin", v: esc(res.realOrigin) }],
      note: "The browser did not block the mismatched domain. That should not happen on a normal browser over HTTPS.",
    }));
    return;
  }
  finishStep(5, resultCard({
    tone: "ok",
    verdict: "Blocked — by the browser, before any prompt",
    headline: "Nothing was offered, nothing was signed, nothing leaked.",
    rows: [
      { k: "Fake site asked for (rpId)", v: esc(res.fakeRp), mark: "bad" },
      { k: "Real page origin", v: esc(res.realOrigin) },
      { k: "Passkey is bound to", v: esc(res.realHost), mark: "ok" },
      { k: "What the browser did", v: "Refused to reveal or use the credential — no prompt shown" },
      { k: "Exact error thrown", v: esc(res.err.name + ": " + res.err.message) },
    ],
    note: `The blocker is the mismatch: the request claimed rpId <b>${esc(res.fakeRp)}</b>, but the passkey belongs to <b>${esc(res.realHost)}</b>. WebAuthn only releases a credential when the requested rpId matches the page's own origin, so the browser never even offered the passkey to the fake domain. A phishing page gets nothing — no key, no signature, nothing to relay. This check is in the browser itself; the user cannot be tricked into overriding it.`,
  }));
}

async function stepProveGone() {
  const ids = credsForSite().map((c) => c.id);
  busy(true, "Looking for anything left…");
  try {
    const res = await signIn({ allowIds: ids, timeout: 30000 });
    if (res.none) { proveGoneSucceeded(); return; }
    // A sign-in that works means a real passkey is still sitting in the device store.
    out(6, resultCard({
      tone: "bad",
      verdict: "Still there",
      headline: "One still exists — the sign-in worked. Check the device store again.",
      rows: [
        { k: "Signed in as", v: esc(res.record?.username || res.id.slice(0, 16) + "…"), mark: "bad" },
        { k: "Stored in", v: esc(res.record?.wallet || "unknown") },
      ],
      note: "Work back through the list above — the passkey is in one of those stores. Delete it there, then run this again.",
    }));
  } catch (err) {
    // The expected path: nothing left to sign with.
    proveGoneSucceeded(err);
  } finally { busy(false); }
}

function proveGoneSucceeded(err) {
  localStorage.removeItem(STORE_KEY);
  document.dispatchEvent(new CustomEvent("passkey-lab:ledger-changed"));
  finishStep(6, resultCard({
    tone: "ok",
    verdict: "Gone",
    headline: "<strong>Gone. Nothing left for anyone to find, either.</strong>",
    rows: [
      { k: "Sign-in attempt", v: "found nothing to sign with", mark: "ok" },
      { k: "Lab records", v: "purged from this browser", mark: "ok" },
      ...(err ? [{ k: "Browser reported", v: esc(err.name) }] : []),
    ],
    note: "There is no server-side account to disable and no shared secret left behind — the private key was only ever in the device you just cleaned.",
  }));
}

const missingPasskeyCard = () => resultCard({
  tone: "warn",
  verdict: "Nothing to use",
  headline: "There's no lab passkey on this browser yet.",
  note: `Go back to <button type="button" class="link" data-goto-inline="1">Step 1</button> and make one first.`,
});

// The X-ray sits under every successful ceremony, open the first time each kind appears so
// nobody has to be told to click it, folded away after that.
const xraySeen = { registration: false, authentication: false };

function xraySlot(kind, res) {
  const open = !xraySeen[kind];
  xraySeen[kind] = true;
  return xrayHtml(kind, res, { open, recordLink: true });
}
