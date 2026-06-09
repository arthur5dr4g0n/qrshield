/* ============================================================
   QRShield — Proxy CORS pour VirusTotal (Cloudflare Worker)
   ------------------------------------------------------------
   POURQUOI ce fichier existe :
   L'API VirusTotal ne renvoie pas d'en-têtes CORS. Le
   navigateur bloque donc les appels directs depuis une page
   web (Same-Origin Policy). Ce Worker joue le rôle de
   "standardiste" : il reçoit l'appel du navigateur, le
   transmet à VirusTotal côté serveur (pas de CORS là-bas),
   et renvoie la réponse AVEC les bons en-têtes CORS.

   Image mentale : tu ne peux pas appeler le PDG directement,
   mais sa secrétaire (le Worker) transmet ton message et
   te rapporte la réponse.

   SÉCURITÉ :
   - La clé API reste celle de l'utilisateur (transmise dans
     l'en-tête x-apikey), le Worker n'en stocke aucune.
   - ALLOWED_ORIGIN limite qui peut utiliser ton proxy.
     Mets l'URL de TON site GitHub Pages, sinon n'importe qui
     pourrait squatter ton quota Cloudflare.

   DÉPLOIEMENT (5 minutes, gratuit) :
   1. https://dash.cloudflare.com → Workers & Pages
   2. Create Worker → colle ce code → Deploy
   3. Note l'URL (ex: https://qrshield-proxy.tonpseudo.workers.dev)
   4. Dans QRShield → ⚙️ → colle cette URL dans "Proxy CORS"
   ============================================================ */

// ⚠️ Remplace par l'origine de TON déploiement, ex :
// const ALLOWED_ORIGIN = 'https://tonpseudo.github.io';
const ALLOWED_ORIGIN = '*';

const VT_BASE = 'https://www.virustotal.com/api/v3';

// Seuls ces deux chemins sont relayés. Tout le reste → 404.
// (Principe du moindre privilège : le proxy ne sait faire
//  QUE ce dont QRShield a besoin.)
const ROUTES = [
  { method: 'POST', pattern: /^\/vt\/urls$/ },
  { method: 'GET',  pattern: /^\/vt\/analyses\/[A-Za-z0-9\-_=]+$/ }
];

export default {
  async fetch(request) {
    const cors = {
      'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'x-apikey, content-type',
      'Access-Control-Max-Age': '86400'
    };

    // Préflight CORS : le navigateur demande la permission
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: cors });
    }

    const url = new URL(request.url);

    // Vérifie que la route est autorisée
    const allowed = ROUTES.some(
      (r) => r.method === request.method && r.pattern.test(url.pathname)
    );
    if (!allowed) {
      return new Response(JSON.stringify({ error: 'Route non autorisée' }),
        { status: 404, headers: { ...cors, 'content-type': 'application/json' } });
    }

    // La clé API de l'utilisateur DOIT être fournie
    const apiKey = request.headers.get('x-apikey');
    if (!apiKey) {
      return new Response(JSON.stringify({ error: 'En-tête x-apikey manquant' }),
        { status: 401, headers: { ...cors, 'content-type': 'application/json' } });
    }

    // Relais vers VirusTotal : /vt/xxx → /api/v3/xxx
    const target = VT_BASE + url.pathname.replace(/^\/vt/, '');
    const upstream = await fetch(target, {
      method: request.method,
      headers: {
        'x-apikey': apiKey,
        'content-type': request.headers.get('content-type') || 'application/json'
      },
      body: request.method === 'POST' ? await request.text() : undefined
    });

    // On renvoie la réponse telle quelle + en-têtes CORS
    const body = await upstream.text();
    return new Response(body, {
      status: upstream.status,
      headers: { ...cors, 'content-type': 'application/json' }
    });
  }
};
