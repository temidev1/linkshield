// Netlify Function — reputation lookups: GSB + VirusTotal + URLhaus
// env vars required:
//   PHISHDETECT_GSB_KEY     (Google Safe Browsing API key)
//   PHISHDETECT_VT_KEY      (VirusTotal API key)
//   PHISHDETECT_ABUSECH_KEY (URLhaus Auth-Key)

const https = require("https");

const UA = {
  "User-Agent": "phish-detector-web/0.7",
  "Accept": "application/json"
};

function httpsGet(url, headers) {
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers: Object.assign({}, UA, headers) }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error("timeout")); });
  });
}

function httpsPost(url, headers, bodyStr) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request({
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: "POST",
      headers: Object.assign({}, UA, headers, {
        "Content-Length": Buffer.byteLength(bodyStr)
      })
    }, (res) => {
      let data = "";
      res.on("data", (c) => (data += c));
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.setTimeout(8000, () => { req.destroy(); reject(new Error("timeout")); });
    req.write(bodyStr);
    req.end();
  });
}

// ---------- GSB ----------
async function checkGSB(url, key) {
  if (!key) return { service: "Google Safe Browsing", available: false, flagged: null, note: "no key" };
  const payload = JSON.stringify({
    client: { clientId: "phish-detector-web", clientVersion: "0.7" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: url }]
    }
  });
  try {
    const r = await httpsPost(
      "https://safebrowsing.googleapis.com/v4/threatMatches:find",
      { "Content-Type": "application/json", "X-Goog-Api-Key": key },
      payload
    );
    if (r.status === 400) return { service: "Google Safe Browsing", available: true, flagged: null, note: "bad request" };
    if (r.status === 403) return { service: "Google Safe Browsing", available: true, flagged: null, note: "key error" };
    if (r.status !== 200) return { service: "Google Safe Browsing", available: true, flagged: null, note: "HTTP " + r.status };
    const j = JSON.parse(r.body);
    const matches = j.matches || [];
    if (matches.length) {
      const threat = matches[0].threatType || "threat";
      return { service: "Google Safe Browsing", available: true, flagged: true, note: "FLAGGED: " + threat };
    }
    return { service: "Google Safe Browsing", available: true, flagged: false, note: "not flagged" };
  } catch (e) {
    return { service: "Google Safe Browsing", available: false, flagged: null, note: e.name || "error" };
  }
}

// ---------- VirusTotal ----------
async function checkVT(url, key) {
  if (!key) return { service: "VirusTotal", available: false, flagged: null, note: "no key" };
  const urlId = Buffer.from(url, "utf8").toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  try {
    const r = await httpsGet(
      "https://www.virustotal.com/api/v3/urls/" + urlId,
      { "x-apikey": key }
    );
    if (r.status === 404) return { service: "VirusTotal", available: true, flagged: null, note: "not previously scanned" };
    if (r.status === 401) return { service: "VirusTotal", available: true, flagged: null, note: "invalid key" };
    if (r.status === 429) return { service: "VirusTotal", available: true, flagged: null, note: "rate limited" };
    if (r.status !== 200) return { service: "VirusTotal", available: true, flagged: null, note: "HTTP " + r.status };
    const j = JSON.parse(r.body);
    const stats = ((j.data || {}).attributes || {}).last_analysis_stats || {};
    const mal = stats.malicious || 0;
    const susp = stats.suspicious || 0;
    const total = mal + susp + (stats.harmless || 0) + (stats.undetected || 0);
    if (mal > 0) return { service: "VirusTotal", available: true, flagged: true, note: mal + "/" + total + " vendors flagged" };
    if (susp > 0) return { service: "VirusTotal", available: true, flagged: true, note: susp + "/" + total + " vendors suspicious" };
    return { service: "VirusTotal", available: true, flagged: false, note: "0/" + total + " vendors flagged" };
  } catch (e) {
    return { service: "VirusTotal", available: false, flagged: null, note: e.name || "error" };
  }
}

// ---------- URLhaus ----------
async function checkURLhaus(url, key) {
  if (!key) return { service: "URLhaus", available: false, flagged: null, note: "no key" };
  let fullUrl = url;
  if (!fullUrl.startsWith("http://") && !fullUrl.startsWith("https://")) fullUrl = "http://" + fullUrl;
  const body = "url=" + encodeURIComponent(fullUrl);
  try {
    const r = await httpsPost(
      "https://urlhaus-api.abuse.ch/v1/url/",
      { "Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded" },
      body
    );
    if (r.status === 401) return { service: "URLhaus", available: true, flagged: null, note: "invalid key" };
    if (r.status === 429) return { service: "URLhaus", available: true, flagged: null, note: "rate limited" };
    if (r.status !== 200) return { service: "URLhaus", available: true, flagged: null, note: "HTTP " + r.status };
    const j = JSON.parse(r.body);
    const status = j.query_status;
    if (status === "ok") {
      const threat = j.threat || "malware";
      return { service: "URLhaus", available: true, flagged: true, note: "listed as " + threat };
    }
    if (status === "no_results") {
      return { service: "URLhaus", available: true, flagged: false, note: "not listed" };
    }
    return { service: "URLhaus", available: true, flagged: null, note: status || "unknown" };
  } catch (e) {
    return { service: "URLhaus", available: false, flagged: null, note: e.name || "error" };
  }
}

// ---------- handler ----------
exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" }, body: "" };
  }
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers: { "Access-Control-Allow-Origin": "*" }, body: JSON.stringify({ error: "method not allowed" }) };
  }
  let url = "";
  try { url = (JSON.parse(event.body || "{}").url || "").trim(); } catch (e) {}
  if (!url) {
    return { statusCode: 400, headers: { "Access-Control-Allow-Origin": "*" }, body: JSON.stringify({ error: "missing url" }) };
  }

  const gsbKey = (process.env.PHISHDETECT_GSB_KEY || "").trim();
  const vtKey  = (process.env.PHISHDETECT_VT_KEY || "").trim();
  const uhKey  = (process.env.PHISHDETECT_ABUSECH_KEY || "").trim();

  const results = await Promise.all([
    checkGSB(url, gsbKey),
    checkVT(url, vtKey),
    checkURLhaus(url, uhKey)
  ]);

  return {
    statusCode: 200,
    headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
    body: JSON.stringify({ results: results })
  };
};
