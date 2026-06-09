/* ============================================================
   QRShield — Service Worker
   ------------------------------------------------------------
   Image mentale : un garde-manger. Au premier passage, on range
   les provisions (le "shell" de l'app). Ensuite, même sans
   réseau, l'app s'ouvre depuis le garde-manger.
   Stratégie :
   - Shell (HTML, manifest, icônes, polices) → cache-first
   - Appels API (VirusTotal, urlscan) → réseau direct, jamais
     mis en cache (les rapports doivent être frais)
   ============================================================ */
const CACHE = 'qrshield-v2';

const SHELL = [
  './',
  './index.html',
  './manifest.json',
  './js/jsQR.js',
  './icons/icon-192.png',
  './icons/icon-512.png'
];

// Installation : on remplit le garde-manger
self.addEventListener('install', (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(SHELL))
  );
  self.skipWaiting();
});

// Activation : on jette les vieux caches (anciennes versions)
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Interception des requêtes
self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);

  // Les API externes (VirusTotal, urlscan, proxy) ne passent
  // JAMAIS par le cache : un rapport de sécurité périmé est
  // pire que pas de rapport du tout.
  const isApi = url.hostname.includes('virustotal.com')
             || url.hostname.includes('urlscan.io')
             || url.pathname.startsWith('/vt/');
  if (isApi || e.request.method !== 'GET') return; // réseau direct

  // Shell + ressources statiques : cache-first avec filet réseau
  e.respondWith(
    caches.match(e.request).then((cached) =>
      cached ||
      fetch(e.request).then((res) => {
        // On met en cache au vol les ressources same-origin + polices
        if (res.ok && (url.origin === self.location.origin
            || url.hostname.includes('fonts.g'))) {
          const clone = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, clone));
        }
        return res;
      }).catch(() =>
        // Hors-ligne et pas en cache → page d'accueil en secours
        caches.match('./index.html')
      )
    )
  );
});
