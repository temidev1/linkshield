// phish-detector web · report
// orchestration layer: detect input type, run analyzers, produce verdict + reasons.

(function () {
  "use strict";

  function detectInputType(raw) {
    raw = (raw || "").trim();
    if (!raw) return "empty";

    // if it has headers like "From:" / "Subject:" / "Authentication-Results:" — email
    if (/^\s*(from|subject|authentication-results|received|reply-to):/im.test(raw)) {
      return "email";
    }

    // if the entire input is a single URL (with or without scheme) — url
    const singleLine = raw.split(/\n/).filter(l => l.trim().length > 0);
    if (singleLine.length === 1) {
      const line = singleLine[0].trim();
      // URL-ish: has a dot, no spaces
      if (!/\s/.test(line) && /\./.test(line) && line.length > 3) {
        return "url";
      }
    }

    // otherwise assume sms / message
    return "message";
  }

  // ---- URL path ----
  function checkURL(raw) {
    const parsed = window.URLAnalysis.parseURL(raw);
    if (!parsed.valid) {
      return {
        inputType: "url",
        verdict: "unknown",
        score: 0,
        confidence: 20,
        reasons: ["Could not understand this link"],
        details: [],
        target: raw
      };
    }

    let score = 0;
    const reasons = [];
    const details = [];

    // https
    if (parsed.hasHttps) details.push({ state: "ok", text: "Uses a secure connection (HTTPS)" });
    else { score += 10; details.push({ state: "bad", text: "Does NOT use a secure connection" });
           reasons.push("This link is not secure (no HTTPS)"); }

    // TLD
    if (parsed.tldSuspicious) {
      score += 15;
      details.push({ state: "bad", text: "Unusual website ending (" + parsed.tld + ")" });
      reasons.push("The website ending (" + parsed.tld + ") is often used by scammers");
    } else if (parsed.tld) {
      details.push({ state: "ok", text: "Normal website ending (" + parsed.tld + ")" });
    }

    // homoglyph
    if (parsed.hasHomoglyph) {
      score += 25;
      details.push({ state: "bad", text: "Uses lookalike letters (fake characters)" });
      reasons.push("The domain has fake letters that look real (decodes to " + parsed.homoglyphDecoded + ")");
    } else {
      details.push({ state: "ok", text: "No fake lookalike letters" });
    }

    // Attack class 1: brand-as-subdomain
    if (parsed.brandAsSubdomain && parsed.typosquatBrand) {
      score += 50;
      details.push({ state: "bad", text: "Uses " + parsed.typosquatBrand + "'s name in the URL to look official" });
      reasons.push("This link uses '" + parsed.typosquatBrand + "'s name to look official, but the real site is a different domain");
    } else if (parsed.exactSldWrongTld && parsed.typosquatBrand) {
      score += 50;
      details.push({ state: "bad", text: "Uses " + parsed.typosquatBrand + "'s name with an unusual website ending (" + parsed.tld + ")" });
      reasons.push("This link uses '" + parsed.typosquatBrand + "'s name but with a suspicious website ending (" + parsed.tld + ")");
    } else if (parsed.typosquatBrand && parsed.typosquatScore >= 85) {
      score += 50;
      details.push({ state: "bad", text: "Looks like " + parsed.typosquatBrand + " but is not" });
      reasons.push("This domain pretends to be '" + parsed.typosquatBrand + "' (" + parsed.typosquatScore + "% similar) - do not trust it");
    } else if (parsed.typosquatBrand && parsed.typosquatScore >= 78) {
      score += 30;
      details.push({ state: "bad", text: "Looks like " + parsed.typosquatBrand + " but is not" });
      reasons.push("This domain pretends to be '" + parsed.typosquatBrand + "' (" + parsed.typosquatScore + "% similar)");
    } else if (parsed.typosquatBrand && parsed.typosquatScore >= 70) {
      // v16.6: 70-77% is too weak to flag alone — info only, +5 max
      score += 5;
      details.push({ state: "warn", text: "Somewhat similar to " + parsed.typosquatBrand });
      reasons.push("This domain looks a bit like '" + parsed.typosquatBrand + "' (" + parsed.typosquatScore + "% similar) — could be a coincidence");
    } else if (parsed.typosquatBrand && parsed.typosquatScore >= 60) {
      score += 5;
      details.push({ state: "warn", text: "Similar to " + parsed.typosquatBrand });
      reasons.push("This domain looks like '" + parsed.typosquatBrand + "'");
    } else {
      details.push({ state: "ok", text: "No brand impersonation detected" });
    }

    // path words
    if (parsed.suspiciousPathWords.length) {
      score += 2;
      details.push({ state: "warn", text: "URL path contains: " + parsed.suspiciousPathWords.join(", ") });
    }

    // host info
    details.push({ state: "info", text: "Domain: " + parsed.host });

    // v16.1 shortener check
    const SHORTENERS = window.SHORTENERS || [
      "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
      "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "rebrand.ly",
      "tiny.cc", "s.id", "shorte.st", "adf.ly", "lnkd.in", "t.ly"
    ];
    const hostLower = (parsed.host || "").toLowerCase();
    parsed.isShortener = SHORTENERS.indexOf(hostLower) !== -1;
    if (parsed.isShortener) {
      score += 25;
      details.push({ state: "warn", text: "Shortened link - real destination is hidden" });
      reasons.push("This is a shortened link. We expanded it and checked the real destination.");
    }

    // v16.1 free-host platform check
    const FREE_HOSTS = window.SUSPICIOUS_HOSTS || [];
    if (FREE_HOSTS.some(function (h) { return hostLower === h || hostLower.slice(-(h.length + 1)) === "." + h; })) {
      score += 20;
      details.push({ state: "warn", text: "Hosted on a free platform often used by scammers" });
      reasons.push("This link is on a free hosting site, which scammers often use for fake pages.");
    }

    // v16.1 IP address as hostname
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostLower)) {
      score += 30;
      details.push({ state: "bad", text: "Uses a raw IP address instead of a domain name" });
      reasons.push("Real websites use names like gtbank.com. This uses a number address, which is a red flag.");
    }

    // v16.5 @-trick
    if (raw.indexOf("@") !== -1 && raw.indexOf("@") < raw.indexOf("//") + 60) {
      score += 55;
      details.push({ state: "bad", text: "Contains '@' — the text before it is fake; the real destination is after it" });
      reasons.push("This link uses an '@' trick. Everything before the '@' is a lie — the browser goes to whatever comes after. Do not click.");
    }

    // v16.6 typosquat + suspicious TLD stacking — escalate hard when three signals line up
    if (parsed.typosquatBrand && parsed.typosquatScore >= 70 && parsed.tldSuspicious && parsed.authLure) {
      score += 35;
      reasons.push("Impersonates '" + parsed.typosquatBrand + "', uses a scammer TLD (" + parsed.tld + "), and pairs it with a login/verify word — classic phishing pattern");
    } else if (parsed.typosquatBrand && parsed.typosquatScore >= 70 && parsed.tldSuspicious) {
      score += 20;
      reasons.push("Impersonates '" + parsed.typosquatBrand + "' AND uses a scammer TLD (" + parsed.tld + ")");
    }

    // v16.4: auth-lure word in a brand-impersonating subdomain = strong signal
    if (parsed.authLure && parsed.typosquatBrand) {
      score += 25;
      details.push({ state: "bad", text: "Uses a login/verify word in a fake '" + parsed.typosquatBrand + "' address" });
      reasons.push("This address combines '" + parsed.typosquatBrand + "' with a login or verification word — a common phishing pattern.");
    }

    score = Math.min(100, score);
    const verdict = verdictFromScore(score);

    return {
      inputType: "url",
      verdict: verdict,
      score: score,
      confidence: 75,
      reasons: reasons,
      details: details,
      target: raw,
      parsed: parsed
    };
  }

  // ---- message (SMS / WhatsApp) path ----
  function checkMessage(raw) {
    const f = window.Smishing.analyze(raw);
    const s = window.Smishing.score(f);
    const v = window.Smishing.verdictFromScore(s.score);

    const details = [];

    // extract a summary
    if (f.phoneNumbers.length) {
      details.push({ state: "warn", text: "Phone number: " + f.phoneNumbers.join(", ") });
    }
    if (f.accountNumbers.length) {
      details.push({ state: "warn", text: "Account number: " + f.accountNumbers.join(", ") });
    }
    if (f.amounts.length) {
      details.push({ state: "info", text: "Amount: NGN " + f.amounts.join(", ") });
    }
    if (f.banksMentioned.length) {
      details.push({ state: "info", text: "Mentions bank: " + f.banksMentioned.join(", ") });
    }
    if (f.telcosMentioned.length) {
      details.push({ state: "info", text: "Mentions telco: " + f.telcosMentioned.join(", ") });
    }
    if (f.agenciesMentioned.length) {
      details.push({ state: "info", text: "Mentions agency: " + f.agenciesMentioned.join(", ") });
    }
    if (f.urls.length) {
      details.push({ state: "warn", text: "Contains " + f.urls.length + " link(s)" });
    }
    if (!details.length) {
      details.push({ state: "ok", text: "No suspicious patterns found" });
    }

    return {
      inputType: "message",
      verdict: v === "smishing" ? "phish" : v,
      score: s.score,
      confidence: 80,
      reasons: s.reasons,
      details: details,
      target: raw,
      findings: f
    };
  }

  // ---- email path ----
  function checkEmail(raw) {
    const f = window.EmailAnalysis.analyze(raw);
    const s = window.EmailAnalysis.score(f);
    const v = window.EmailAnalysis.verdictFromScore(s.score);

    const details = [];

    if (f.from) {
      details.push({ state: "info", text: "From: " + f.from });
    }
    if (f.senderMismatch && f.replyTo) {
      details.push({ state: "bad",
                     text: "Reply-to does NOT match the sender: " + f.replyTo });
    }
    if (f.subject) {
      details.push({ state: "info", text: "Subject: " + f.subject });
    }

    // auth
    const a = f.auth || {};
    details.push({
      state: a.spf === "pass" ? "ok" : a.spf === "fail" ? "bad" : "warn",
      text: "SPF: " + (a.spf || "unknown")
    });
    details.push({
      state: a.dkim === "pass" ? "ok" : (a.dkim === "fail" || a.dkim === "none") ? "bad" : "warn",
      text: "DKIM: " + (a.dkim || "unknown")
    });
    details.push({
      state: a.dmarc === "pass" ? "ok" : a.dmarc === "fail" ? "bad" : "warn",
      text: "DMARC: " + (a.dmarc || "unknown")
    });

    if (f.urgencyWords.length) {
      details.push({ state: "warn",
                     text: "Urgent words: " + f.urgencyWords.slice(0, 3).join(", ") });
    }
    if (f.threatWords.length) {
      details.push({ state: "warn",
                     text: "Threats: " + f.threatWords.slice(0, 3).join(", ") });
    }
    if (f.genericGreeting) {
      details.push({ state: "warn", text: "Generic greeting (not personalized)" });
    }
    if (f.urls.length) {
      details.push({ state: "warn", text: "Contains " + f.urls.length + " link(s)" });
    }

    return {
      inputType: "email",
      verdict: v,
      score: s.score,
      confidence: 85,
      reasons: s.reasons,
      details: details,
      target: f.from || "(unknown sender)",
      findings: f
    };
  }



// ---------- async reputation + expand via backend ----------
// these call the serverless endpoints (local dev-server or Vercel)

function fetchReputation(url) {
  return fetch("/api/reputation", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url })
  })
  .then(r => r.ok ? r.json() : null)
  .then(data => data && data.results ? data.results : null)
  .catch(() => null);
}

function fetchExpansion(url) {
  return fetch("/api/expand", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: url })
  })
  .then(r => r.ok ? r.json() : null)
  .catch(() => null);
}

// async wrapper around checkURL for the reputation layer
async function checkURLAsync(raw) {
  const base = checkURL(raw);
  if (base.error || !base.parsed || !base.parsed.valid) return base;

  let reputationResults = null;
  let expansionResults = null;

  // shortener expansion first
  if (base.parsed.isShortener) {
    expansionResults = await fetchExpansion(base.parsed.raw);
    if (expansionResults && expansionResults.final && expansionResults.final !== base.parsed.raw) {
      // add hop detail
      for (const hop of expansionResults.hops) {
        if (hop === base.parsed.raw) continue;
        base.details.push({ state: "warn", text: "Redirects to: " + hop });
      }
      if (expansionResults.hops.length > 1) {
        base.reasons.push("Hidden destination: " +
          expansionResults.hops[expansionResults.hops.length - 1]);
        base.score = Math.min(100, base.score + 15);
        base.verdict = verdictFromScore(base.score);
      }
    }
  }

  // reputation check
  reputationResults = await fetchReputation(base.parsed.raw);
  if (reputationResults && reputationResults.length) {
    let flaggedCount = 0;
    let repTotal = 0;
    let repFlagged = 0;
    let repErrored = 0;
    for (const r of reputationResults) {
      repTotal++;
      if (r.available === false) { repErrored++; continue; }
      if (r.flagged === true) {
        flaggedCount++;
        repFlagged++;
      }
    }
    // v16.3: one summary line instead of per-vendor dump
    if (repTotal > 0 && repErrored === repTotal) {
      base.details.push({ state: "info", text: "Reputation: services unavailable — could not verify" });
    } else if (repFlagged > 0) {
      base.details.push({ state: "bad",
        text: "Reputation: " + repFlagged + " of " + repTotal + " services flagged this link" });
    } else {
      base.details.push({ state: "ok",
        text: "Reputation: checked " + repTotal + " services, none flagged" });
    }
    if (flaggedCount > 0) {
      // v16.2: weight by vendor severity — VT is noisy, blocklists are not
      let repBonus = 0;
      for (const r of reputationResults) {
        if (r.available === false || r.flagged !== true) continue;
        const svc = (r.service || "").toLowerCase();
        const note = r.note || "";
        if (svc.indexOf("virustotal") !== -1) {
          const m = note.match(/(\d+)\s*\//);
          const n = m ? parseInt(m[1], 10) : 1;
          if (n >= 6)       repBonus += 40;
          else if (n >= 3)  repBonus += 15;
          else              repBonus += 5;
        } else if (svc.indexOf("safe browsing") !== -1 ||
                   svc.indexOf("urlhaus") !== -1 ||
                   svc.indexOf("openphish") !== -1 ||
                   svc.indexOf("phishing.database") !== -1 ||
                   svc.indexOf("urlscan") !== -1) {
          repBonus += 25;
        } else {
          repBonus += 10;
        }
      }
      repBonus = Math.min(60, repBonus);
      if (repBonus > 0) {
        base.score = Math.min(100, base.score + repBonus);
        base.verdict = verdictFromScore(base.score);
      }
    }
  } else {
    base.details.push({ state: "info", text: "Reputation: services unavailable — could not verify" });
    if (base.verdict === "clean") {
      base.score = Math.min(100, base.score + 15);
      base.verdict = verdictFromScore(base.score);
      base.reasons.push("We could not verify this link's reputation — treat it cautiously.");
    }
  }

  return base;
}


  function verdictFromScore(s) {
    // single strong signal (typosquat >=85) can reach DANGER on its own
    if (s >= 50) return "phish";
    if (s >= 25) return "suspicious";
    return "clean";
  }

  // ---- top-level dispatcher ----
  function analyze(raw) {
    const type = detectInputType(raw);
    if (type === "empty") {
      return { error: "Please paste a link or message first." };
    }
    if (type === "url") return checkURL(raw);
    if (type === "email") return checkEmail(raw);
    return checkMessage(raw);
  }

  window.Report = {
    analyze: analyze,
    analyzeAsync: analyzeAsync,
    detectInputType: detectInputType,
    checkURL: checkURL,
    checkURLAsync: checkURLAsync,
    checkMessage: checkMessage,
    checkEmail: checkEmail,
    fetchReputation: fetchReputation,
    fetchExpansion: fetchExpansion
  };

  // async version that runs reputation + shortener checks
  async function analyzeAsync(raw) {
    const type = detectInputType(raw);
    if (type === "empty") {
      return { error: "Please paste a link or message first." };
    }
    if (type === "url") return await checkURLAsync(raw);
    // for messages + emails, run their normal checks
    if (type === "email") return checkEmail(raw);
    return checkMessage(raw);
  }
})();
