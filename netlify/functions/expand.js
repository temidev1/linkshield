// Netlify Function — URL shortener expansion (follows redirects)
const https = require("https");
const http = require("http");

function fetchHead(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith("https") ? https : http;
    const req = lib.get(url, {
      headers: { "User-Agent": "phish-detector-web/0.7" },
      timeout: timeoutMs
    }, (res) => {
      res.resume();
      resolve({ status: res.statusCode, location: res.headers.location || "" });
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs, () => { req.destroy(); reject(new Error("timeout")); });
  });
}

function resolveUrl(base, next) {
  if (!next) return base;
  if (next.startsWith("http://") || next.startsWith("https://")) return next;
  try {
    const u = new URL(base);
    if (next.startsWith("/")) return u.protocol + "//" + u.host + next;
    return new URL(next, base).toString();
  } catch (e) { return next; }
}

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
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = "http://" + url;

  const hops = [url];
  let current = url;
  const MAX = 8;
  for (let i = 0; i < MAX; i++) {
    let res;
    try { res = await fetchHead(current, 8000); }
    catch (e) { return { statusCode: 200, headers: { "Access-Control-Allow-Origin": "*" }, body: JSON.stringify({ final: current, hops: hops, error: e.name || "error" }) }; }
    if ([301, 302, 303, 307, 308].includes(res.status) && res.location) {
      const next = resolveUrl(current, res.location);
      if (next === current) break;
      current = next;
      hops.push(current);
    } else break;
  }
  return {
    statusCode: 200,
    headers: { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" },
    body: JSON.stringify({ final: current, hops: hops, error: null })
  };
};
