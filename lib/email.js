// phish-detector web · email header parsing
// ported from modules/email.py
//
// exposes window.EmailAnalysis with:
//   parse(raw)  -> parsed header fields
//   analyze(raw) -> full analysis with auth + urgency + attachments

(function () {
  "use strict";

  const URGENCY_WORDS = [
    "urgent", "immediately", "asap", "right away", "action required",
    "final notice", "last chance", "expires", "expiring", "time sensitive",
    "within 24 hours", "within 48 hours", "act now", "verify now",
    "confirm now", "update now", "click now", "act immediately",
    "immediate action", "deadline", "limited time", "respond immediately"
  ];

  const THREAT_WORDS = [
    "account will be closed", "account suspended", "account disabled",
    "account locked", "access denied", "access revoked", "will be deleted",
    "will be terminated", "legal action", "lawsuit", "suspend your",
    "close your account", "delete your account", "revoke your",
    "unauthorized access", "security breach", "unusual activity",
    "suspicious activity", "compromised", "failed login"
  ];

  const GENERIC_GREETINGS = [
    "dear customer", "dear user", "dear valued customer", "dear member",
    "dear client", "dear account holder", "hello user",
    "dear sir/madam", "to whom it may concern"
  ];

  // split raw email into headers object + body string
  function parseHeaders(raw) {
    raw = (raw || "").replace(/\r\n/g, "\n");
    const lines = raw.split("\n");
    const headers = {};
    let current = null;
    let bodyStart = -1;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line === "" && bodyStart === -1) {
        bodyStart = i + 1;
        break;
      }
      if (/^[ \t]/.test(line) && current) {
        // continuation
        headers[current] += " " + line.trim();
      } else {
        const m = line.match(/^([A-Za-z0-9-]+):\s*(.*)$/);
        if (m) {
          current = m[1].toLowerCase();
          headers[current] = m[2].trim();
        }
      }
    }

    const body = bodyStart >= 0 ? lines.slice(bodyStart).join("\n") : "";
    return { headers: headers, body: body };
  }

  function parseAuthResults(headers) {
    const out = { spf: null, dkim: null, dmarc: null };
    const authHdr = headers["authentication-results"] || "";
    if (authHdr) {
      const spfMatch = authHdr.match(/\bspf\s*=\s*(\w+)/i);
      if (spfMatch) out.spf = spfMatch[1].toLowerCase();
      const dkimMatch = authHdr.match(/\bdkim\s*=\s*(\w+)/i);
      if (dkimMatch) out.dkim = dkimMatch[1].toLowerCase();
      const dmarcMatch = authHdr.match(/\bdmarc\s*=\s*(\w+)/i);
      if (dmarcMatch) out.dmarc = dmarcMatch[1].toLowerCase();
    }
    const spfRecv = headers["received-spf"] || "";
    if (spfRecv && !out.spf) {
      const low = spfRecv.toLowerCase();
      if (low.indexOf("pass") !== -1) out.spf = "pass";
      else if (low.indexOf("softfail") !== -1) out.spf = "softfail";
      else if (low.indexOf("fail") !== -1) out.spf = "fail";
      else if (low.indexOf("neutral") !== -1) out.spf = "neutral";
      else if (low.indexOf("none") !== -1) out.spf = "none";
    }
    return out;
  }

  function extractEmailAddr(s) {
    if (!s) return null;
    const m = s.match(/<([^>]+)>/);
    if (m) return m[1].trim().toLowerCase();
    return s.trim().toLowerCase();
  }

  function extractDomain(addr) {
    if (!addr) return null;
    const m = addr.match(/@([a-zA-Z0-9.\-]+)/);
    return m ? m[1].toLowerCase() : null;
  }

  function detectPhrases(text, phrases) {
    if (!text) return [];
    const low = text.toLowerCase();
    return phrases.filter(p => low.indexOf(p) !== -1);
  }

  function checkSenderMismatch(fromAddr, replyTo, returnPath) {
    const f = extractEmailAddr(fromAddr);
    const r = extractEmailAddr(replyTo);
    const rp = extractEmailAddr(returnPath);
    if (f && r && f !== r) return true;
    if (f && rp && f !== rp) return true;
    return false;
  }

  function extractSenderIP(received) {
    // received is a joined string of all Received headers
    if (!received) return null;
    const m = received.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    return m ? m[0] : null;
  }

  function parse(raw) {
    const p = parseHeaders(raw);
    const auth = parseAuthResults(p.headers);
    return {
      headers: p.headers,
      body: p.body,
      from: p.headers["from"] || null,
      to: p.headers["to"] || null,
      replyTo: p.headers["reply-to"] || null,
      returnPath: p.headers["return-path"] || null,
      subject: p.headers["subject"] || null,
      date: p.headers["date"] || null,
      messageId: p.headers["message-id"] || null,
      received: p.headers["received"] || "",
      senderIp: extractSenderIP(p.headers["received"] || ""),
      auth: auth,
      authResultsRaw: p.headers["authentication-results"] || null
    };
  }

  function analyze(raw, headersOnly) {
    const parsed = parse(raw);
    const body = headersOnly ? "" : (parsed.body || "");
    const combined = (parsed.subject || "") + "\n" + body;

    const urgency = detectPhrases(combined, URGENCY_WORDS);
    const threats = detectPhrases(combined, THREAT_WORDS);
    const genericGreeting = detectPhrases(combined, GENERIC_GREETINGS).length > 0;

    const urls = (window.URLAnalysis && window.URLAnalysis.extractURLs)
      ? window.URLAnalysis.extractURLs(combined) : [];

    const senderMismatch = checkSenderMismatch(
      parsed.from, parsed.replyTo, parsed.returnPath);

    return {
      from: parsed.from,
      to: parsed.to,
      replyTo: parsed.replyTo,
      returnPath: parsed.returnPath,
      subject: parsed.subject,
      date: parsed.date,
      messageId: parsed.messageId,
      senderIp: parsed.senderIp,
      senderDomain: extractDomain(extractEmailAddr(parsed.from)),
      auth: parsed.auth,
      authResultsRaw: parsed.authResultsRaw,
      senderMismatch: senderMismatch,
      urgencyWords: urgency,
      threatWords: threats,
      genericGreeting: genericGreeting,
      urls: urls
    };
  }

  function score(f) {
    let s = 0;
    const reasons = [];

    const a = f.auth || {};
    if (a.spf === "fail") {
      s += 20;
      reasons.push("Sender failed SPF check (email may be spoofed)");
    }
    if (a.dkim === "fail" || a.dkim === "none" || a.dkim === null) {
      s += 15;
      reasons.push("DKIM: " + (a.dkim || "none"));
    }
    if (a.dmarc === "fail") {
      s += 20;
      reasons.push("Sender failed DMARC check");
    }

    if (f.senderMismatch) {
      s += 20;
      reasons.push("Reply-to address differs from sender");
    }
    if (f.urgencyWords && f.urgencyWords.length) {
      s += 10;
      reasons.push("Urgent language: " + f.urgencyWords.slice(0, 3).join(", "));
    }
    if (f.threatWords && f.threatWords.length) {
      s += 10;
      reasons.push("Threatening language: " + f.threatWords.slice(0, 3).join(", "));
    }
    if (f.genericGreeting) {
      s += 5;
      reasons.push("Generic greeting (not personalized)");
    }

    return { score: Math.min(100, s), reasons: reasons };
  }

  function verdictFromScore(s) {
    if (s >= 60) return "phish";
    if (s >= 25) return "suspicious";
    return "clean";
  }

  window.EmailAnalysis = {
    parse: parse,
    analyze: analyze,
    score: score,
    verdictFromScore: verdictFromScore
  };
})();
