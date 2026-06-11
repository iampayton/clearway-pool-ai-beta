// ClearWay Pool AI — offline shell (sw-v2)
// Keeps the app opening with zero signal. Scans queue on the phone and send when signal returns.
const CACHE = "clearway-v2";

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;
  const url = new URL(request.url);

  // The app page: revalidate with the server (skip the HTTP cache so updates
  // actually land - GitHub Pages caches for ~10 min), fall back to the cached copy offline.
  if (request.mode === "navigate" || url.pathname.endsWith(".html")) {
    event.respondWith(
      fetch(request, { cache: "no-cache" })
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE).then((cache) => cache.put(request, copy));
          return response;
        })
        .catch(async () =>
          (await caches.match(request)) ||
          (await caches.match("./index.html")) ||
          (await caches.match("./clearway-pool-ai-field-app.html")) ||
          new Response("Offline. Open ClearWay once with signal to load it onto this phone.", { status: 503, headers: { "Content-Type": "text/plain" } })
        )
    );
    return;
  }

  // App code from this repo + the Supabase JS module from esm.sh:
  // serve from cache instantly, refresh in the background.
  if (url.origin === self.location.origin || url.hostname === "esm.sh") {
    event.respondWith(
      caches.match(request).then((hit) => {
        const refresh = fetch(request)
          .then((response) => {
            if (response.ok) {
              const copy = response.clone();
              caches.open(CACHE).then((cache) => cache.put(request, copy));
            }
            return response;
          })
          .catch(() => hit);
        return hit || refresh;
      })
    );
  }
  // Everything else (Supabase data/photos, weather) goes straight through untouched.
});
