// Passkey Lab — which way in.
// Two ways to use the lab: the guided rail, or the free-form bench. The choice is asked once,
// remembered in localStorage, and reversible from the masthead at any time.

export const MODE_KEY = "passkey-lab-mode";
export const TRAINING_KEY = "passkey-lab-training";
export const TOTAL_STEPS = 6;

export const getMode = () => localStorage.getItem(MODE_KEY);
export const setMode = (m) => localStorage.setItem(MODE_KEY, m);
// Forgetting the choice is how the start screen comes back — training progress is untouched,
// so "Continue the guided lab — step N of 6" still knows where you were.
export const clearMode = () => localStorage.removeItem(MODE_KEY);

export function getTraining() {
  try { return JSON.parse(localStorage.getItem(TRAINING_KEY) || "null"); } catch { return null; }
}

// "Progress" means the lab was actually started — not just a state object being present.
export function hasProgress() {
  const t = getTraining();
  return !!t && ((t.completed && t.completed.length > 0) || (t.step && t.step > 1));
}

const $ = (id) => document.getElementById(id);

// Show exactly one of: the landing choice, the bench, the rail.
export function showView(view) {
  $("mode-choice").hidden = view !== "choice";
  $("bench-view").hidden = view !== "bench";
  $("training-view").hidden = view !== "training";

  // All three sections are always reachable; the current one is marked and inert.
  document.querySelectorAll("#modenav .modenav-btn").forEach((b) => {
    const current = b.dataset.view === view;
    b.classList.toggle("is-current", current);
    b.disabled = current;
    if (current) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  });

  // The wordmark is a second way home. On the start screen there is nowhere to go, so it
  // stops behaving like a control.
  const home = $("btn-home");
  if (home) {
    home.disabled = view === "choice";
    home.setAttribute("aria-label", view === "choice" ? "Passkey Lab" : "Passkey Lab — back to the start screen");
  }
}

// The landing's primary button picks up where the lab was left off.
export function refreshLandingPrimary() {
  const btn = $("btn-mode-training");
  const t = getTraining();
  btn.textContent = hasProgress()
    ? `Continue the guided lab — step ${Math.min(t.step || 1, TOTAL_STEPS)} of ${TOTAL_STEPS}`
    : "Guided lab — make one and see inside";
}

// First visit is "no saved mode and nothing started" — anything else goes straight in.
export function initialView() {
  const saved = getMode();
  if (saved === "bench" || saved === "training") return saved;
  return "choice";
}
