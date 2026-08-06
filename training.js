// Passkey Lab — Training Mode.
// The guided rail: six steps, one visible at a time, each one a real WebAuthn ceremony
// followed by the X-ray of what actually happened.

export function renderTraining() {
  const host = document.getElementById("training-view");
  host.innerHTML = `<section class="step"><p class="eyebrow">Guided lab</p>
    <h2>Coming up next</h2>
    <p class="hint">The rail lands in the next phase.</p></section>`;
}
