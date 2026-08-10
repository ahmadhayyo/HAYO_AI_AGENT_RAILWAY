// HAYO PWA service worker — minimal (enables installability, network-first passthrough).
// No caching of API/auth responses to avoid stale/authenticated data.
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (event) => {
  // Default network behavior; presence of a fetch handler is what makes the app installable.
  // We intentionally do not cache anything (keeps trading data & auth always fresh).
  return;
});
