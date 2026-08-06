// Passkey Lab — deployment configuration.
// The one thing that changes between deployments, kept out of the code that uses it.

// The phishing twin, if one is deployed (see phishing-twin/README.md). It must be on a
// different registrable domain from this site or it proves nothing — a subdomain of the same
// domain is still the same site to a browser.
//
// Empty means no twin: Step 5's "Open the fake site" button simply doesn't appear. The
// in-page phishing demo is the real proof and never depends on this.
export const TWIN_URL = "";
