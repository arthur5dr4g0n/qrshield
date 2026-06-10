const ALLOWED_ORIGIN = 'https://arthur5dr4g0n.github.io';
const VT_BASE     = 'https://www.virustotal.com/api/v3';
const GSB_URL     = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
const URLHAUS_URL = 'https://urlhaus-api.abuse.ch/v1/url/';

const CORS = {
  'Access-Control-Allow-Origin':  ALLOWED_ORIGIN,
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Access-Control-Allow-Headers': 'content-type',
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS, 'content-type': 'application/json' },
  });
}

async function checkVirusTotal(url, key) {
  const submit = await fetch(VT_BASE + '/urls', {
    method: 'POST',
    headers: { 'x-apikey': key, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'url=' + encodeURIComponent(url),
  });
  if (submit.status === 401) throw new Error('CLE_INVALIDE');
  if (submit.status === 429) throw new Error('RATE_LIMIT');
  if (!submit.ok) throw new Error('HTTP_' + submit.status);

  const { data } = await submit.json();
  const analysisId = data.id;

  // Poll max 8 × 3 s = 24 s (dans la limite des 30 s Cloudflare)
  for (let i = 0; i < 8; i++) {
    await new Promise(r => setTimeout(r, 3000));
    const res = await fetch(VT_BASE + '/analyses/' + analysisId, {
      headers: { 'x-apikey': key },
    });
    if (res.status === 429) throw new Error('RATE_LIMIT');
    if (!res.ok) throw new Error('HTTP_' + res.status);
    const j = await res.json();
    if (j.data.attributes.status === 'completed') {
      const s = j.data.attributes.stats;
      return { malicious: s.malicious, suspicious: s.suspicious,
               harmless: s.harmless, undetected: s.undetected };
    }
  }
  throw new Error('TIMEOUT');
}

async function checkSafeBrowsing(url, key) {
  const res = await fetch(GSB_URL + '?key=' + key, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client: { clientId: 'qrshield', clientVersion: '2.0' },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING',
                      'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    }),
  });
  if (!res.ok) throw new Error('HTTP_' + res.status);
  const j = await res.json();
  const matched = !!(j.matches && j.matches.length > 0);
  return { matched, type: matched ? j.matches[0].threatType : null };
}

async function checkURLhaus(url, key) {
  const res = await fetch(URLHAUS_URL, {
    method: 'POST',
    headers: { 'Auth-Key': key, 'content-type': 'application/x-www-form-urlencoded' },
    body: 'url=' + encodeURIComponent(url),
  });
  if (!res.ok) throw new Error('HTTP_' + res.status);
  const j = await res.json();
  const listed = j.query_status === 'is_listed';
  return { listed, threat: listed ? (j.threat || null) : null, status: j.url_status || null };
}

function aggregateVerdict(sources) {
  let maliciousCount = 0;
  let suspicious = false;

  const vt = sources.virustotal;
  if (vt && !vt.error) {
    if (vt.malicious >= 1) maliciousCount++;
    else if (vt.suspicious >= 1) suspicious = true;
  }
  const gsb = sources.safebrowsing;
  if (gsb && !gsb.error && gsb.matched) maliciousCount++;

  const uh = sources.urlhaus;
  if (uh && !uh.error && uh.listed) maliciousCount++;

  if (maliciousCount >= 2) return 'danger_confirmed';
  if (maliciousCount === 1) return 'danger';
  if (suspicious)           return 'suspicious';
  return 'clean';
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    const url = new URL(request.url);
    if (request.method !== 'POST' || url.pathname !== '/scan') {
      return json({ error: 'Route non autorisée' }, 404);
    }

    let body;
    try { body = await request.json(); }
    catch { return json({ error: 'Corps JSON invalide' }, 400); }

    if (!body.url || typeof body.url !== 'string') {
      return json({ error: 'Champ url manquant' }, 400);
    }

    const [vtR, gsbR, uhR] = await Promise.allSettled([
      checkVirusTotal(body.url, env.VT_KEY),
      checkSafeBrowsing(body.url, env.GSB_KEY),
      checkURLhaus(body.url, env.URLHAUS_KEY),
    ]);

    const sources = {
      virustotal:   vtR.status  === 'fulfilled' ? vtR.value  : { error: vtR.reason?.message  || 'erreur' },
      safebrowsing: gsbR.status === 'fulfilled' ? gsbR.value : { error: gsbR.reason?.message || 'erreur' },
      urlhaus:      uhR.status  === 'fulfilled' ? uhR.value  : { error: uhR.reason?.message  || 'erreur' },
    };

    return json({ verdict: aggregateVerdict(sources), sources });
  },
};
