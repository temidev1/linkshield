// phish-detector web · smishing analysis
// ported from modules/smishing.py
//
// exposes window.Smishing with:
//   analyze(text)         -> findings dict
//   score(findings)       -> { score, reasons, verdict }

(function () {
  "use strict";

  const NIGERIAN_PHONE_RE = /\b(?:\+?234|0)[789][01]\d{8}\b/g;
  const ACCOUNT_NUMBER_RE = /\b\d{10}\b/g;
  // amount: must be N/NGN/₦ followed by digit, with a word boundary
  // avoids matching "within 24 hours"
  const AMOUNT_RE = /(?:\bN|NGN|₦)\s?([0-9][0-9,]*(?:\.\d+)?)\b(?!\s?(?:hour|hours|day|days|minute|minutes|second|seconds|week|weeks|month|months|year|years|hrs|mins|secs))/gi;

  function extractPhoneNumbers(text) {
    const m = text.match(NIGERIAN_PHONE_RE) || [];
    return Array.from(new Set(m));
  }

  function extractAccountNumbers(text) {
    const phones = extractPhoneNumbers(text);
    const m = text.match(ACCOUNT_NUMBER_RE) || [];
    const out = [];
    for (const n of m) {
      let isInPhone = false;
      for (const p of phones) {
        if (p.indexOf(n) !== -1) { isInPhone = true; break; }
      }
      if (!isInPhone && out.indexOf(n) === -1) out.push(n);
    }
    return out;
  }

  function extractAmounts(text) {
    const out = [];
    let m;
    const re = new RegExp(AMOUNT_RE.source, "gi");
    while ((m = re.exec(text)) !== null) {
      const v = m[1].replace(/,/g, "");
      if (out.indexOf(v) === -1) out.push(v);
    }
    return out;
  }

  function matchList(text, list) {
    const low = text.toLowerCase();
    const found = [];
    for (const item of list) {
      const re = new RegExp("\\b" + escapeRegex(item) + "\\b", "i");
      if (re.test(low) && found.indexOf(item) === -1) {
        found.push(item);
      }
    }
    return found;
  }

  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }

  function matchKeywords(text) {
    const low = text.toLowerCase();
    const matches = [];
    const seen = new Set();
    const kws = window.SMISHING_KEYWORDS || [];
    for (const [kw, cat, sev] of kws) {
      if (low.indexOf(kw) !== -1) {
        const key = cat + "::" + kw;
        if (!seen.has(key)) {
          seen.add(key);
          matches.push({ keyword: kw, category: cat, severity: sev });
        }
      }
    }
    return matches;
  }

  function rollupByCategory(matches) {
    const cats = {};
    for (const m of matches) {
      if (!cats[m.category]) {
        cats[m.category] = { count: 0, keywords: [], severity: "low" };
      }
      cats[m.category].count += 1;
      cats[m.category].keywords.push(m.keyword);
      if (m.severity === "high") cats[m.category].severity = "high";
      else if (m.severity === "med" && cats[m.category].severity !== "high") {
        cats[m.category].severity = "med";
      }
    }
    return cats;
  }

  function analyze(text) {
    text = text || "";
    const urls = (window.URLAnalysis && window.URLAnalysis.extractURLs)
      ? window.URLAnalysis.extractURLs(text) : [];
    const keywordMatches = matchKeywords(text);
    const cats = rollupByCategory(keywordMatches);

    return {
      text: text,
      length: text.length,
      phoneNumbers: extractPhoneNumbers(text),
      accountNumbers: extractAccountNumbers(text),
      amounts: extractAmounts(text),
      urls: urls,
      banksMentioned: matchList(text, window.NG_BANKS || []),
      telcosMentioned: matchList(text, window.NG_TELCOS || []),
      agenciesMentioned: matchList(text, window.NG_AGENCIES || []),
      keywordMatches: keywordMatches,
      categories: cats
    };
  }

  function score(f) {
    let s = 0;
    const reasons = [];
    const cats = f.categories || {};

    // has a strong signal category?
    const highCats = [
      "bvn_request", "otp_request", "card_request", "threat",
      "urgency", "action", "whatsapp_hijack", "loan_scam",
      "reward_scam", "cbn_grant", "gov_grant", "scam_crypto",
      "job_scam", "pin_request", "gov_scam"
    ];
    let hasHighSignal = highCats.some(c => cats[c]);
    if (f.urls && f.urls.length) hasHighSignal = true;

    // BVN / OTP requests
    if (cats.bvn_request) {
      s += 35;
      reasons.push("Requests BVN or personal identifier (" +
        cats.bvn_request.keywords.slice(0, 2).join(", ") + ")");
    }
    if (cats.otp_request) {
      s += 35;
      reasons.push("Requests OTP or verification code (" +
        cats.otp_request.keywords.slice(0, 2).join(", ") + ")");
    }
    if (cats.card_request) {
      s += 30;
      reasons.push("Requests card details or PIN");
    }
    if (cats.pin_request) {
      s += 15;
      reasons.push("Requests PIN");
    }

    // impersonation
    if (f.banksMentioned && f.banksMentioned.length) {
      const b = f.banksMentioned.slice(0, 2).join(", ");
      if (hasHighSignal) {
        s += 20;
        reasons.push("Impersonates " + b);
      } else {
        reasons.push("Mentions " + b + " (no phishing pattern)");
      }
    }
    if (f.telcosMentioned && f.telcosMentioned.length && hasHighSignal) {
      s += 10;
      reasons.push("References " + f.telcosMentioned.slice(0, 2).join(", "));
    }
    if (f.agenciesMentioned && f.agenciesMentioned.length && hasHighSignal) {
      s += 15;
      reasons.push("Impersonates government agency (" +
        f.agenciesMentioned.slice(0, 2).join(", ") + ")");
    }

    // urgent / threat / action
    if (cats.urgency) {
      s += 15;
      reasons.push("Uses urgency (" +
        cats.urgency.keywords.slice(0, 2).join(", ") + ")");
    }
    if (cats.threat) {
      s += 20;
      reasons.push("Threatens account action (" +
        cats.threat.keywords.slice(0, 2).join(", ") + ")");
    }
    if (cats.action) {
      s += 10;
      reasons.push("Asks to click or verify (" +
        cats.action.keywords.slice(0, 2).join(", ") + ")");
    }
    if (cats.money) {
      s += 15;
      reasons.push("Payment-related (" +
        cats.money.keywords.slice(0, 2).join(", ") + ")");
    }

    // specific scam categories
    if (cats.cbn_grant || cats.gov_grant) {
      s += 25;
      reasons.push("Claims government grant or CBN scheme");
    }
    if (cats.gov_scam) {
      const n = cats.gov_scam.count;
      const base = 30;
      const extra = Math.min(20, (n - 1) * 5);
      s += base + extra;
      reasons.push("Government scheme scam (" +
        cats.gov_scam.keywords.slice(0, 3).join(", ") + ")");
    }
    if (cats.loan_scam) {
      s += 20;
      reasons.push("Fake loan offer");
    }
    if (cats.reward_scam) {
      s += 25;
      reasons.push("Fake reward / prize claim");
    }
    if (cats.scam_crypto) {
      s += 25;
      reasons.push("Crypto scam pattern");
    }
    if (cats.telco_scam) {
      s += 15;
      reasons.push("Fake telco promo");
    }
    if (cats.job_scam) {
      const n = cats.job_scam.count;
      const base = 25;
      const extra = Math.min(25, (n - 1) * 8);
      s += base + extra;
      reasons.push("Task / recruitment scam (" +
        cats.job_scam.keywords.slice(0, 3).join(", ") + ")");
    }
    if (cats.invite_code) {
      s += 15;
      reasons.push("Uses invite/referral code (task scam pattern)");
    }
    if (cats.whatsapp_hijack) {
      s += 30;
      reasons.push("WhatsApp account takeover attempt");
    }
    if (cats.chain) {
      s += 10;
      reasons.push("Asks to forward or share with others");
    }

    // link signal
    if (f.urls && f.urls.length) {
      s += 5;
      reasons.push("Contains " + f.urls.length + " link(s)");
    }
    if (f.accountNumbers && f.accountNumbers.length) {
      s += 10;
      reasons.push("Includes account number (" + f.accountNumbers[0] + ")");
    }

    return { score: Math.min(100, s), reasons: reasons };
  }

  function verdictFromScore(s) {
    if (s >= 60) return "smishing";
    if (s >= 25) return "suspicious";
    return "clean";
  }

  window.Smishing = {
    analyze: analyze,
    score: score,
    verdictFromScore: verdictFromScore,
    extractPhoneNumbers: extractPhoneNumbers,
    extractAccountNumbers: extractAccountNumbers,
    extractAmounts: extractAmounts
  };
})();
