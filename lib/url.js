// phish-detector web · url analysis
// ported from modules/url_analysis.py
//
// exposes window.URLAnalysis with:
//   parseURL(raw)          -> { scheme, host, path, query, hasHttps, tld, tldSuspicious, ... }
//   levenshtein(a, b)      -> int
//   hasHomoglyph(host)     -> bool
//   normalizeHomoglyphs(h) -> string
//   typosquatScore(host)   -> { brand, score }
//   scoreFindings(findings) -> { score, reasons }

(function () {
  "use strict";

  const HOMOGLYPHS = {
    "\u0430": "a", "\u0435": "e", "\u043E": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u0455": "s", "\u04BB": "h", "\u04CF": "l",
    "\u0501": "d", "\u03B1": "a", "\u03B2": "b", "\u03B5": "e",
    "\u03BF": "o", "\u03C1": "p", "\u03BD": "v", "\u03C4": "t"
  };

  const SUSPICIOUS_PATH_WORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "confirm", "account", "secure", "update", "validate",
    "auth", "authenticate", "reset", "recover"
  ];

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a) return b.length;
    if (!b) return a.length;
    let prev = [];
    for (let j = 0; j <= b.length; j++) prev[j] = j;
    for (let i = 1; i <= a.length; i++) {
      const curr = [i];
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        curr[j] = Math.min(
          curr[j - 1] + 1,
          prev[j] + 1,
          prev[j - 1] + cost
        );
      }
      prev = curr;
    }
    return prev[b.length];
  }

  function hasHomoglyph(host) {
    for (const ch of host) {
      if (HOMOGLYPHS[ch]) return true;
    }
    return false;
  }

  function normalizeHomoglyphs(host) {
    let out = "";
    for (const ch of host) {
      out += HOMOGLYPHS[ch] || ch;
    }
    return out;
  }

  function normalizeDigits(host) {
    // leetspeak / digit-for-letter substitution used in typosquats
    // paypa1 -> paypal, g00gle -> google, faceb00k -> facebook
    return String(host || "")
      .toLowerCase()
      .replace(/0/g, "o")
      .replace(/1/g, "l")
      .replace(/3/g, "e")
      .replace(/4/g, "a")
      .replace(/5/g, "s")
      .replace(/7/g, "t")
      .replace(/8/g, "b")
      .replace(/@/g, "a")
      .replace(/\$/g, "s");
  }

  function hasAuthLure(label) {
    // v16.6: shared auth-lure word detector — used on both SLD and subdomain paths
    const AUTH_LURE = ["login", "signin", "verify", "verification",
                       "secure", "security", "account", "update",
                       "confirm", "confirming", "authenticate", "validation"];
    if (!label) return false;
    const l = String(label).toLowerCase();
    return AUTH_LURE.some(function (w) { return l.indexOf(w) !== -1; });
  }

  function typosquatScore(host, brands) {
    brands = brands || window.BRANDS || [];
    const parts = host.toLowerCase().split(".");
    let best = { brand: null, score: 0 };
    for (const brand of brands) {
      for (const lbl of parts) {
        if (!lbl) continue;
        // exact match is not typosquatting — it's the brand's real domain.
        if (lbl === brand) continue;
        // skip if the candidate label is itself a known brand.
        // "unitybank" vs "zenithbank" are both real banks, not typosquatting.
        if (brands.indexOf(lbl) !== -1) continue;
        const d = levenshtein(lbl, brand);
        const m = Math.max(lbl.length, brand.length);
        if (m === 0) continue;
        let sim = Math.round((1 - d / m) * 100);
        if (lbl.includes(brand) && lbl !== brand) sim = Math.max(sim, 75);
        if (sim >= 60 && sim > best.score) {
          best = { brand: brand, score: sim };
        }
      }
    }
    return best;
  }



  // brand-owned infrastructure domains — these are legitimate even if they
  // contain the brand name as a subdomain. skip typosquat when host matches.
  const BRAND_INFRA = {
    "google": ["google.com", "googleapis.com", "googleusercontent.com",
               "googlesource.com", "googleusercontent.cn", "googletagmanager.com",
               "google-analytics.com", "gstatic.com", "withgoogle.com"],
    "apple": ["apple.com", "icloud.com", "itunes.com", "apple-cloudkit.com",
              "cdn-apple.com", "mzstatic.com"],
    "microsoft": ["microsoft.com", "microsoftonline.com", "office.com",
                  "live.com", "outlook.com", "windows.net", "azure.com",
                  "sharepoint.com", "onedrive.com", "msn.com", "bing.com"],
    "amazon": ["amazon.com", "amazonaws.com", "aws.amazon.com",
               "amazon.co.uk", "amazon.in", "a2z.com"],
    "facebook": ["facebook.com", "fbcdn.net", "fb.com", "fbsbx.com",
                 "messenger.com"],
    "instagram": ["instagram.com", "cdninstagram.com"],
    "whatsapp": ["whatsapp.com", "whatsapp.net"],
    "twitter": ["twitter.com", "t.co", "twimg.com", "x.com"],
    "linkedin": ["linkedin.com", "licdn.com"],
    "netflix": ["netflix.com", "nflxvideo.net", "nflximg.net"],
    "paypal": ["paypal.com", "paypalobjects.com"],
    "github": ["github.com", "githubusercontent.com", "githubassets.com",
               "github.io"],
    "cloudflare": ["cloudflare.com", "cloudflarestream.com", "cf-dns.com"],
    "tiktok": ["tiktok.com", "tiktokcdn.com", "tiktokv.com"],
    "telegram": ["telegram.org", "t.me", "telesco.pe"],
    "reddit": ["reddit.com", "redd.it", "redditstatic.com"],
    "discord": ["discord.com", "discordapp.com", "discord.gg"],
    "binance": ["binance.com", "binance.us"],
    "coinbase": ["coinbase.com"],
    "opay": ["opayweb.com", "opay.com"],
    "palmpay": ["palmpay.com"],
    "moniepoint": ["moniepoint.com"],
    "kuda": ["kuda.com", "kudabank.com"],
    "gtbank": ["gtbank.com", "gtco.com"],
    "zenithbank": ["zenithbank.com"],
    "accessbank": ["accessbankplc.com"],
    "firstbank": ["firstbanknigeria.com"],
  };

  function isBrandInfra(host, brand) {
    const infra = BRAND_INFRA[brand];
    if (!infra) return false;
    host = host.toLowerCase();
    for (const d of infra) {
      if (host === d || host.endsWith("." + d)) return true;
    }
    return false;
  }

  // v16.7: true if this host belongs to ANY known brand's official infra.
  // Used to suppress typosquat false-positives like chat.whatsapp.com
  // matching "wechat" because the subdomain label is "chat".
  function isAnyBrandInfra(host) {
    if (!host) return false;
    for (const brand in BRAND_INFRA) {
      if (isBrandInfra(host, brand)) return true;
    }
    return false;
  }


  function parseURL(raw) {
    raw = (raw || "").trim();
    const out = {
      raw: raw,
      valid: false,
      scheme: null,
      host: null,
      path: null,
      query: null,
      hasHttps: false,
      tld: null,
      tldSuspicious: false,
      hasHomoglyph: false,
      homoglyphDecoded: null,
      typosquatBrand: null,
      typosquatScore: 0,
      suspiciousPathWords: [],
      error: null
    };

    if (!raw) {
      out.error = "empty";
      return out;
    }

    let urlStr = raw;
    if (!/^https?:\/\//i.test(urlStr)) {
      urlStr = "https://" + urlStr;
    }

    let u;
    try {
      u = new URL(urlStr);
    } catch (e) {
      out.error = "invalid URL";
      return out;
    }

    out.scheme = u.protocol.replace(":", "");
    out.host = u.hostname.toLowerCase();
    out.path = u.pathname;
    out.query = u.search.replace(/^\?/, "");
    out.hasHttps = out.scheme === "https";
    out.valid = true;

    // eTLD+1 (registered domain) — uses PSL if available, falls back to last 2 labels
    if (window.PSL && window.PSL.getETLDPlusOne) {
      out.registeredDomain = window.PSL.getETLDPlusOne(out.host);
    } else {
      const ps = out.host.split(".");
      out.registeredDomain = ps.length >= 2 ? ps.slice(-2).join(".") : out.host;
    }

    // TLD
    const parts = out.host.split(".");
    if (parts.length >= 2) {
      out.tld = "." + parts[parts.length - 1];
      const sus = window.SUSPICIOUS_TLDS || [];
      out.tldSuspicious = sus.indexOf(out.tld) !== -1;
    }

    // homoglyph
    if (hasHomoglyph(out.host)) {
      out.hasHomoglyph = true;
      out.homoglyphDecoded = normalizeHomoglyphs(out.host);
    }

    // typosquat — runs against the second-level label only (strip the TLD)
    // so "zenithbank.xyz" checks against "zenithbank", not "zenithbank.xyz"
    const regDom = out.registeredDomain || out.host;
    const sld = regDom.split(".")[0] || regDom;
    const brandList = window.BRANDS || [];

    // priority 1: exact SLD match + suspicious TLD
    // this MUST run before typosquat so it beats lookalike matches
    let exactBrandWrongTld = null;
    if (brandList.indexOf(sld) !== -1) {
      const tldPart = "." + regDom.split(".").slice(-1)[0];
      const sus = window.SUSPICIOUS_TLDS || [];
      if (sus.indexOf(tldPart) !== -1) {
        exactBrandWrongTld = sld;
      }
    }

    // priority 2: typosquat (only if exact-SLD-wrong-TLD didn't fire)
    let t = { brand: null, score: 0 };
    if (!exactBrandWrongTld) {
      t = typosquatScore(sld);
      // v16.2: if direct score is weak, try digit-normalized form
      if (t.score < 85) {
        const nd = normalizeDigits(sld);
        if (nd !== sld) {
          const t2 = typosquatScore(nd);
          if (t2.score > t.score) {
            t = { brand: t2.brand, score: t2.score, digitSub: true };
          }
        }
      }
    }


    if (t.brand && isBrandInfra(out.host, t.brand)) {
      // host contains the brand but it's the brand's own domain — not phishing
      out.typosquatBrand = null;
      out.typosquatScore = 0;
      out.brandInfraMatch = t.brand;
    } else if (t.brand && isBrandInfra(out.registeredDomain, t.brand)) {
      // eTLD+1 is brand-owned — legit
      out.typosquatBrand = null;
      out.typosquatScore = 0;
      out.brandInfraMatch = t.brand;
    } else if (exactBrandWrongTld) {
      out.typosquatBrand = exactBrandWrongTld;
      out.typosquatScore = 100;
      out.exactSldWrongTld = true;
    } else if (isAnyBrandInfra(out.host)) {
      // v16.7: host belongs to a real brand's own infra — no typosquat
      out.typosquatBrand = null;
      out.typosquatScore = 0;
    } else {
      out.typosquatBrand = t.brand;
      out.typosquatScore = t.score;
      // v16.6: check auth-lure on the SLD itself, not just subdomains
      if (hasAuthLure(sld)) {
        out.authLure = true;
        out.typosquatScore = Math.min(100, out.typosquatScore + 15);
      }
    }

    // brand-as-subdomain second pass — catches "gtbank.com.verified-alert.ng"
    // where the brand name is in the subdomain, not the registered domain
    if (!out.typosquatBrand && out.registeredDomain) {
      const subLen = out.host.length - out.registeredDomain.length;
      const subdomain = subLen > 0
        ? out.host.slice(0, subLen).replace(/\.$/, "")
        : "";
      const brands = window.BRANDS || [];
      for (const label of subdomain.split(".").filter(Boolean)) {
        // skip generic labels
        if (label === "www" || label === "com" || label === "net" ||
            label === "org" || label === "login" || label === "secure" ||
            label === "account" || label === "auth" || label === "app" ||
            label === "web" || label === "api" || label === "mail" ||
            label === "signin" || label === "portal" || label === "support" ||
            label.length < 3) {
          continue;
        }
        // check 1: exact brand in subdomain (e.g. gtbank.com.verified-alert.ng)
        if (brands.indexOf(label) !== -1 && !isBrandInfra(out.host, label)) {
          out.typosquatBrand = label;
          out.typosquatScore = 100;
          out.brandAsSubdomain = true;
          break;
        }
        // v16.4: split subdomain on separators, normalize digits, retry typosquat
        const parts = String(label).split(/[.\-_]/).filter(p => p.length > 2);
        let bestT = typosquatScore(label);
        let bestTDigitSub = false;
        for (const p of parts) {
          const nd = normalizeDigits(p);
          const pt = typosquatScore(nd);
          if (pt.score > bestT.score) {
            bestT = pt;
            bestTDigitSub = (nd !== p);
          }
        }
        // also try normalized whole label
        const ndLabel = normalizeDigits(label);
        if (ndLabel !== label) {
          const t3 = typosquatScore(ndLabel);
          if (t3.score > bestT.score) {
            bestT = t3;
            bestTDigitSub = true;
          }
        }
        const st = bestT;
        if (st.brand && !isBrandInfra(out.host, st.brand) && !isAnyBrandInfra(out.host)) {
          out.typosquatBrand = st.brand;
          out.typosquatScore = st.score;
          // v16.4/v16.6: auth-lure word boost — uses shared helper
          if (hasAuthLure(label)) {
            out.typosquatScore = Math.min(100, out.typosquatScore + 15);
            out.authLure = true;
          }
          out.brandAsSubdomain = true;
          break;
        }
      }
    }

    // path words
    const pLow = (out.path || "").toLowerCase();
    for (const w of SUSPICIOUS_PATH_WORDS) {
      if (pLow.indexOf(w) !== -1) out.suspiciousPathWords.push(w);
    }

    return out;
  }

  // extract all URLs from a block of text
  function extractURLs(text) {
    text = text || "";
    const re = /https?:\/\/[^\s<>"']+/gi;
    const found = text.match(re) || [];
    const seen = new Set();
    const out = [];
    for (let u of found) {
      u = u.replace(/[.,;:)\]}>]+$/, "");
      if (!seen.has(u)) {
        seen.add(u);
        out.push(u);
      }
    }
    return out;
  }

  window.URLAnalysis = {
    parseURL: parseURL,
    levenshtein: levenshtein,
    hasHomoglyph: hasHomoglyph,
    normalizeHomoglyphs: normalizeHomoglyphs,
    normalizeDigits: normalizeDigits,
    typosquatScore: typosquatScore,
    extractURLs: extractURLs,
    SUSPICIOUS_PATH_WORDS: SUSPICIOUS_PATH_WORDS
  };
})();
