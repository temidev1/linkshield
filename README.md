# LinkShield

Free phishing link checker for Nigeria. Paste a link or message — get a verdict in seconds.

**Live:** https://linkshield-ng.netlify.app

## What it does

Paste any suspicious link, SMS, or WhatsApp message. LinkShield checks it against live threat databases and Nigerian scam patterns, then gives you a clear color-coded verdict:

- ✅ **NO THREATS FOUND** — nothing suspicious found
- ⚠️ **BE CAREFUL** — some risk signals
- 🛑 **DANGER** — likely a scam

## What it checks

- **URL structure** — typosquats, homoglyphs, digit substitution, brand-as-subdomain
- **Suspicious TLDs** — `.xyz`, `.tk`, `.top`, and other scammer favorites
- **Shorteners** — expands bit.ly, tinyurl, and similar before scoring
- **`@`-trick** — detects the classic `paypal.com@evil.com` pattern
- **Reputation** — Google Safe Browsing, VirusTotal, URLhaus (via Netlify Functions)
- **Nigerian scam keywords** — BVN requests, CBN grants, fake telco promos, task scams

## Stack

- **Frontend:** vanilla JS, HTML, CSS — no framework, no build step
- **Backend:** Netlify Functions (Node.js) for reputation lookups
- **Host:** Netlify (free tier)

## Deploy your own

1. Clone this repo
2. Zip the folder contents
3. Drop the zip at https://app.netlify.com/drop
4. Add these environment variables in Netlify:
   - `PHISHDETECT_GSB_KEY`
   - `PHISHDETECT_VT_KEY`
   - `PHISHDETECT_ABUSECH_KEY`
  
## Local development

The frontend runs entirely client-side. To test locally:

    python3 -m http.server 8080

Then open http://localhost:8080.

Note: the `/api/reputation` and `/api/expand` endpoints only work when deployed to Netlify. Locally, reputation checks will show "services unavailable" — but URL parsing, keyword scanning, and verdict scoring all work.


## Privacy

Nothing you paste is stored on our servers. URLs are checked against public threat databases. Nothing is logged.

## License

MIT
