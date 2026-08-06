# Manual test script

The automated suites (`npm test`, `npm run test:e2e`) cover everything a virtual authenticator
can reach. They cannot cover a second physical device, a Bluetooth radio, a browser extension,
a real cross-domain deploy, or how any of it looks on a projector.

Run this before a training session, on the machine you will present from.

- **Time:** about 25 minutes, plus 10 for the layout matrix.
- **You need:** the presenting laptop, a phone (iOS or Android) with Bluetooth, and the
  LastPass extension installed and unlocked.
- **Serve it:** `npm run serve`, then <http://localhost:8000>. Passkeys need HTTPS or
  `localhost`. Test against the deployed site too if you will present from it — passkeys made
  on `localhost` do not work on `passkey.lrfa.dev` and vice versa.

Record the date, browser and OS, and tick as you go. A failed step is worth a note even if you
know the cause.

```
Date:            Browser/version:            OS:            Presenting on:
```

---

## What the automated tests cannot see

The suites drive a Chromium **virtual** authenticator. It only ever reports ES256, an unknown
AAGUID, and `backupEligible: false` — so these four areas have never executed in a real
browser, no matter how green the tests are:

| Unproven | Why it matters | Covered by |
|---|---|---|
| **RS256 verification** | Windows Hello commonly issues RS256, not ES256. The code path is unit-tested but has never run end to end. | Tier 1 |
| **AAGUID → wallet name** | The virtual authenticator always maps to "Unknown". Every entry in the wallet list is unexercised. | Tier 1 |
| **Synced passkeys (BE/BS set)** | `syncLabel`, Step 3's "that's a synced passkey, live" highlight and the X-ray's *backed up: yes* row have never fired. | Tier 2 |
| **Hybrid / QR transport** | Steps 3 and 4 in their entirety — the QR handshake and the Bluetooth failure. | Tier 2 |

**Tier 1 is 10 minutes on your own laptop with no phone, and closes half the risk.** Do that
first even if you never get to the rest.

---

## Tier 1 — 10 minutes, laptop only *(do this first)*

No phone needed. This is the highest value per minute in the whole document.

- [ ] §1 — make a passkey with your real fingerprint/face/PIN
- [ ] **Check the ledger's Wallet column names your authenticator** (Windows Hello, iCloud
      Keychain, Chrome on Mac…) and does **not** say "Unknown". If it says Unknown, note the
      AAGUID here — it needs adding to the list: `________________________________`
- [ ] **Open the record card (Public key) and note the algorithm:** `ES256 / RS256`
      — if RS256, that branch has just run for the first time. Confirm the X-ray's
      verification node still shows **VALID**.
- [ ] §2 — timed sign-in, X-ray node 5 shows VALID
- [ ] §6 — "Prove it's gone" fails while the passkey exists, then succeeds after you delete it
- [ ] §7 — print preview is light and legible
- [ ] §10 — the bench pass

## Tier 2 — needs a phone *(the two steps with no automated cover at all)*

- [ ] §3 — phone passkey over QR, and the **synced** highlight appears
- [ ] §4 — Bluetooth off → fail → on → succeed

## Tier 3 — before the session itself

- [ ] §8 — LastPass
- [ ] §9 — layout matrix on the actual projector

---

## 0 — Before you start

- [ ] Delete any existing "Passkey Lab" passkeys from the device store (see §6), so Step 1
      does not hit the duplicate path unintentionally.
- [ ] Clear site data for the lab's origin, so the mode choice appears.
- [ ] Bluetooth ON, on both the laptop and the phone.

---

## 1 — Mode choice and the guided rail (real authenticator)

- [ ] First load shows the choice screen: **Guided lab** and **Open the bench**. No bench, no rail.
- [ ] Click **Guided lab — make one and see inside**. The rail opens on Step 1 with steps 2–6 greyed out.
- [ ] Click **Create my passkey**. Your real prompt appears — fingerprint, face or PIN.
- [ ] Complete it. The result card says **Passkey created** and **"That's it. Now look underneath."**
- [ ] The X-ray below is **already expanded**, and node 4 names your actual authenticator
      (Windows Hello / iCloud Keychain / etc.), not "Unknown".
- [ ] Node 3 shows a UV tick, since you used a biometric or PIN.
- [ ] Reload the page. The rail comes back on Step 1 with the tick still on it.

**Duplicate path** — worth seeing once, because clients hit it:

- [ ] Still on Step 1, click **Create my passkey** again.
- [ ] You get **"This device already has a passkey for the lab."** and a **Jump to Step 6** link.
      No browser prompt appears at all.

---

## 2 — Timed sign-in

- [ ] Move to Step 2, click **Sign in with my passkey**, complete the gesture.
- [ ] The headline reads **"{X.X} seconds. A texted code averages over a minute."** —
      note the number here, it is the line the room remembers: `______ s`
- [ ] X-ray node 5 shows **VALID — the signature matches the stored public key**.
- [ ] Node 2 shows the challenge echoed back **byte for byte**.

---

## 3 — Phone passkey over QR  *(cannot be virtualised)*

Bluetooth ON, both devices.

- [ ] Move to Step 3, click **Create a phone passkey**.
- [ ] A QR code appears on the laptop.
- [ ] Scan it with the phone's **normal camera app** — not a camera inside a password manager.
- [ ] The phone offers to save a passkey; approve it.
- [ ] The laptop shows **Passkey created**.
- [ ] The X-ray's portability row reads **backed up: yes → synced passkey**, and the
      highlight appears: **"See that? The phone synced this passkey to its cloud account —
      that's a synced passkey, live."**
      - If it says device-bound instead, note which phone/OS — some configurations do not
        back up immediately: `____________________`
- [ ] The phone passkey shows up in the ledger on the bench with the phone's wallet name.

**Skip path:**

- [ ] Reset the lab, run to Step 3, and click **No phone on you? Skip — you can come back.**
- [ ] Step 4 opens with the written walkthrough instead of the QR instructions, and the
      checkbox reads **"I read the failure walkthrough"**.
- [ ] Step 3 is still clickable in the stepper afterwards.

---

## 4 — Break it with Bluetooth  *(cannot be virtualised)*

Re-run Step 3 first if you used the skip path.

- [ ] Turn the phone's **Bluetooth OFF**.
- [ ] On Step 4, click **Try the phone sign-in** and scan the QR.
- [ ] It fails. Write down exactly what the browser said, word for word — this is the sentence
      clients will read to you:

      ________________________________________________________________

- [ ] The lab's card says **Failed — as designed**, and calls out that the error did not
      mention Bluetooth.
- [ ] Turn Bluetooth back **ON**. Click **Try the phone sign-in** again and scan.
- [ ] It succeeds, and the card reads **Failed, then worked** — the step completes on its own,
      without needing the checkbox.

---

## 5 — Phishing  *(the in-page half is automated; confirm it live)*

- [ ] Step 5, click **Run the phishing attempt**.
- [ ] Verdict: **Blocked — by the browser, before any prompt**.
- [ ] **No prompt of any kind appeared.** This is the point — confirm it visually.
- [ ] The exact error row names a real `SecurityError` from your browser.

**The twin** — only if it has been deployed (see `phishing-twin/README.md`):

- [ ] `TWIN_URL` is set in `config.js` and Step 5 shows **Open the fake site**.
- [ ] The twin opens on a **different registrable domain** (check the address bar: it must not
      be a subdomain of the lab's domain).
- [ ] Its warning strip is present and reads as a training fake.
- [ ] Click **Try to use the passkey**. Both attempts fail and it says
      **"Nothing. The browser wouldn't even offer the passkey here."**
- [ ] No prompt appeared there either.

---

## 6 — Cleanup, for real

- [ ] Step 6 shows the per-OS list with **your** platform already expanded.
- [ ] Click **Prove it's gone** *before* deleting anything. It must find the passkey and say
      **"One still exists — the sign-in worked."**
- [ ] Now delete the lab passkeys for real, from every store that has one:
  - [ ] **Windows:** Settings → Accounts → Passkeys → "Passkey Lab" → delete
  - [ ] **iPhone/iPad:** Passwords app → search this site → delete
  - [ ] **Android:** Google Password Manager → search this site → delete
  - [ ] **The phone passkey from Step 3:** delete on the phone
  - [ ] **LastPass:** delete the vault item
- [ ] Click **Prove it's gone** again. Now it must say
      **"Gone. Nothing left for anyone to find, either."**
- [ ] The bench's ledger is empty.
- [ ] The finish screen appears with the three things to keep.

---

## 7 — Print the finish screen

- [ ] Click **Save/print this page**.
- [ ] The preview is **light** — dark text on white, not a black page.
- [ ] The stepper, the buttons and the mode toggle are all gone from the print.
- [ ] The three things to keep are legible and not split across a page break.

---

## 8 — LastPass  *(cannot be virtualised)*

- [ ] Unlock the LastPass extension **first**.
- [ ] On the bench, set Authenticator to **Phone or security key (LastPass, YubiKey…)** and
      click **Create passkey**.
- [ ] LastPass intercepts the prompt and offers to save to the vault. Accept.
- [ ] The ledger's Wallet column reads **LastPass**.
- [ ] Portability reads **Synced**.
- [ ] Click **Sign in with passkey** — LastPass answers it, and the trace says the signature verified.
- [ ] X-ray node 4 names LastPass as the maker.
- [ ] Delete it from the vault when you are done.

---

## 9 — Layout matrix

Check each at the given size. On each: **no sideways scroll**, no panel overlapping another,
nothing cut off at the right edge, and all text legible from the back of a room.

| Size | Expect | OK? |
|---|---|---|
| 1366 × 768 | two columns; trace under the ledger | ☐ |
| 1920 × 1080 | **three** columns; trace pinned in column 3; whole bench on screen without scrolling | ☐ |
| 2560 × 1440 | three columns; no dead space; line lengths still readable | ☐ |
| 1920 × 1080 @ 150% zoom | back to two columns; nothing clipped | ☐ |
| 1920 × 1080 @ 200% zoom | single column is acceptable; still no sideways scroll | ☐ |
| Phone, portrait | single column; ledger table scrolls inside itself | ☐ |

- [ ] At 1920 × 1080, scroll the page: the trace stays pinned and its log scrolls internally.
- [ ] Run a few actions at 1920 × 1080 and confirm the trace is readable **from the back of the
      room** — this is the one thing worth checking on the actual projector.
- [ ] Open a tooltip on the bench: the panel does not jump.
- [ ] Open a wide X-ray on a laptop screen: the two lanes hold, nothing overflows sideways.

---

## 10 — Bench regression by hand

Automated already, but quick to sanity-check on real hardware:

- [ ] Create · Sign in · Autofill (click the dashed field) · all five prove buttons
- [ ] **Raw** and **X-ray** on a ledger row; **Inspect last sign-in (raw)** after a sign-in
- [ ] In the inspector, edit the origin and re-verify → **INVALID**; Reset → **VALID**
- [ ] **Public key** opens the record card with the PEM
- [ ] Export JSON, Clear list, Import the file back
- [ ] Switch to the guided lab and back from the masthead

---

## If something fails live

Worth deciding before you're standing in front of people.

**Step 3 or 4 won't work (no QR, phone won't pair, Bluetooth flaky on the venue's network).**
Use the skip link on Step 3. Step 4 then swaps to the written walkthrough with its own
checkbox, and the lab continues to completion. Nothing downstream depends on the phone
passkey — Step 4 falls back to the Step-1 credential and Step 6 works either way. Talk through
the walkthrough copy instead; it describes the exact ticket.

**The wallet shows "Unknown".** Harmless — the AAGUID list is deliberately incomplete and the
lab says so. Everything else still works; you just lose the "and here's which vault it went
to" line.

**No built-in authenticator on the presenting machine.** Step 1 drops the platform constraint
automatically and says so, then offers a phone or security key. Bring a YubiKey as a backup —
it also gets you a **non-zero sign counter**, which is the one thing a synced passkey can't
demonstrate.

**Nothing works at all.** The bench is independent of the rail. `localhost` works with no
network. Worst case, present from `npm run serve` on the laptop.

---

## Notes / failures

```




```
