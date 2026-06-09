# 🛡️ QRShield — Scanner de QR codes sécurisé (PWA)

Analyse les QR codes **avant** de les ouvrir : heuristiques locales
instantanées + VirusTotal + urlscan.io. L'URL n'est **jamais** ouverte
automatiquement.

> Image mentale : un videur de boîte de nuit pour tes QR codes.
> Le QR frappe à la porte → le videur le fouille → il appelle deux
> experts → et c'est **toi** qui décides s'il entre.

---

## 📁 Contenu du dossier

```
qrshield/
├── index.html        ← l'application (HTML + CSS + JS)
├── manifest.json     ← installation sur écran d'accueil
├── sw.js             ← Service Worker (mode offline)
├── icons/
│   ├── icon-192.png
│   └── icon-512.png
└── worker/
    └── vt-proxy.js   ← proxy Cloudflare (débloque VirusTotal)
```

---

## 🚀 Déploiement en 10 minutes (gratuit)

### Étape 1 — Héberger l'app sur GitHub Pages

GitHub Pages = HTTPS automatique → caméra + Service Worker fonctionnent.

```bash
# Depuis le dossier qrshield/
git init
git add .
git commit -m "QRShield v1"
git branch -M main
git remote add origin git@github.com:TON_PSEUDO/qrshield.git
git push -u origin main
```

Puis sur GitHub : **Settings → Pages → Source : main / (root) → Save**.

⏱️ 2 minutes plus tard, l'app est en ligne sur :
`https://TON_PSEUDO.github.io/qrshield/`

### Étape 2 — Déployer le proxy VirusTotal (Cloudflare Worker)

Pourquoi ? L'API VirusTotal n'envoie pas d'en-têtes CORS → le
navigateur bloque les appels directs. Le Worker joue la secrétaire :
il transmet ton appel et rapporte la réponse.

1. Crée un compte gratuit sur https://dash.cloudflare.com
2. **Workers & Pages → Create Worker** → nomme-le `qrshield-proxy`
3. Colle le contenu de `worker/vt-proxy.js` → **Deploy**
4. ⚠️ Recommandé : dans le code, remplace
   `const ALLOWED_ORIGIN = '*'` par
   `const ALLOWED_ORIGIN = 'https://TON_PSEUDO.github.io'`
   (sinon n'importe qui peut utiliser ton quota Cloudflare)
5. Note l'URL : `https://qrshield-proxy.TON_PSEUDO.workers.dev`

### Étape 3 — Configurer l'app sur ton téléphone

1. Ouvre `https://TON_PSEUDO.github.io/qrshield/` sur ton mobile
2. Menu navigateur → **« Ajouter à l'écran d'accueil »**
3. Ouvre ⚙️ et colle :
   - ta **clé VirusTotal** → https://www.virustotal.com/gui/my-apikey
   - ta **clé urlscan.io** → https://urlscan.io/user/profile/ (onglet API)
   - l'**URL du proxy** Cloudflare (étape 2)
4. Scanne un QR. C'est tout. 🎉

---

## 🧪 Test rapide sans téléphone

```bash
cd qrshield/
python3 -m http.server 8000
# → http://localhost:8000 (localhost = caméra et SW autorisés)
```

QR de test sans danger : génère un QR pointant vers
`http://paypa1-secure-login.xyz/verify` sur n'importe quel générateur
→ QRShield doit hurler 🔴 (HTTP + typosquat + TLD suspect + appât).

---

## ⚠️ À savoir (honnêteté technique)

| Point | Détail |
|---|---|
| **urlscan "public"** | Les URL soumises sont **visibles par tous** sur urlscan.io. Jamais d'URL contenant un token/lien privé. |
| **urlscan + CORS** | Non vérifié à 100 % que leur API accepte les appels navigateur. Si ça bloque : le même Worker peut être étendu (ajoute une route `/us/`). |
| **Clés en localStorage** | OK pour un outil perso. Une faille XSS sur la même origine = clés volées. Pour de la prod → backend. |
| **Quota VT gratuit** | 4 requêtes/minute, 500/jour. Le code affiche un message clair si dépassé (429). |
| **Typosquatting** | Détection naïve (Levenshtein sur le 2ᵉ label). Les TLD composés type `.co.uk` ne sont pas gérés. |
| **iOS** | L'installation PWA fonctionne via Safari uniquement. Le mode standalone peut limiter certains accès caméra selon la version d'iOS. |

---

## 🔐 Modèle de sécurité

- L'URL décodée n'est **jamais** ouverte automatiquement
- Ouverture manuelle = **double confirmation** + `noopener,noreferrer`
- Tout contenu externe affiché passe par `escapeHtml()` (anti-XSS)
- Le proxy ne relaie **que** 2 routes VirusTotal (moindre privilège)
- Aucune clé API stockée côté proxy : elles restent sur ton appareil
