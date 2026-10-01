// phish-detector web · mini public suffix list
// enough to extract registerable domains for common TLDs.
// not exhaustive — covers the TLDs our users encounter.

(function () {
  "use strict";

  // two-level public suffixes (exceptions exist, we ignore them)
  const TWO_LEVEL = {
    "co.uk": 1, "org.uk": 1, "ac.uk": 1, "gov.uk": 1, "me.uk": 1,
    "co.za": 1, "org.za": 1, "gov.za": 1,
    "com.au": 1, "net.au": 1, "org.au": 1, "edu.au": 1, "gov.au": 1,
    "co.nz": 1, "org.nz": 1, "net.nz": 1,
    "co.jp": 1, "or.jp": 1, "ne.jp": 1, "ac.jp": 1, "go.jp": 1,
    "com.br": 1, "net.br": 1, "org.br": 1,
    "com.cn": 1, "net.cn": 1, "org.cn": 1, "gov.cn": 1,
    "com.hk": 1, "org.hk": 1, "net.hk": 1,
    "com.sg": 1, "org.sg": 1, "net.sg": 1,
    "com.my": 1, "org.my": 1, "net.my": 1,
    "co.in": 1, "net.in": 1, "org.in": 1, "gen.in": 1, "firm.in": 1,
    "co.ke": 1, "or.ke": 1, "ne.ke": 1, "go.ke": 1,
    "com.gh": 1, "org.gh": 1, "edu.gh": 1, "gov.gh": 1,
    "co.ke": 1,
    // Nigeria — the important ones
    "com.ng": 1, "org.ng": 1, "net.ng": 1, "edu.ng": 1,
    "gov.ng": 1, "sch.ng": 1, "name.ng": 1, "i.ng": 1, "mil.ng": 1,
  };

  // very common ccTLDs treated as one-level (single label)
  const SINGLE_LEVEL = {
    "ng": 1, "gh": 1, "ke": 1, "za": 1, "ug": 1, "tz": 1, "rw": 1,
    "uk": 1, "us": 1, "ca": 1, "de": 1, "fr": 1, "it": 1, "es": 1,
    "nl": 1, "be": 1, "ch": 1, "se": 1, "no": 1, "dk": 1, "fi": 1,
    "ie": 1, "pt": 1, "pl": 1, "ru": 1, "ua": 1, "tr": 1, "in": 1,
    "pk": 1, "bd": 1, "lk": 1, "my": 1, "sg": 1, "ph": 1, "id": 1,
    "th": 1, "vn": 1, "jp": 1, "kr": 1, "cn": 1, "hk": 1, "tw": 1,
    "au": 1, "nz": 1, "br": 1, "mx": 1, "ar": 1, "cl": 1, "co": 1,
    "pe": 1, "ve": 1,
  };

  // well-known gTLDs (always two labels minimum)
  const GTDL = {
    "com": 1, "org": 1, "net": 1, "edu": 1, "gov": 1, "mil": 1,
    "int": 1, "info": 1, "biz": 1, "name": 1, "io": 1, "co": 1,
    "ai": 1, "app": 1, "dev": 1, "xyz": 1, "top": 1, "shop": 1,
    "online": 1, "site": 1, "club": 1, "pro": 1, "tech": 1,
  };

  function getETLDPlusOne(host) {
    if (!host) return "";
    host = host.toLowerCase().replace(/\.$/, "");

    // strip leading "www."
    if (host.startsWith("www.")) host = host.slice(4);

    const parts = host.split(".");
    if (parts.length <= 2) return host;

    // check the last two labels against the two-level public suffix list
    const last2 = parts.slice(-2).join(".");
    if (TWO_LEVEL[last2]) {
      // registerable domain is: label + last2
      if (parts.length >= 3) {
        return parts.slice(-3).join(".");
      }
      return host;
    }

    // check single-label ccTLD → registerable domain is the last two labels
    const last1 = parts[parts.length - 1];
    if (SINGLE_LEVEL[last1]) {
      return parts.slice(-2).join(".");
    }

    // gTLD → registerable domain is the last two labels
    if (GTDL[last1]) {
      return parts.slice(-2).join(".");
    }

    // fallback — treat last two labels as registerable
    return parts.slice(-2).join(".");
  }

  window.PSL = {
    getETLDPlusOne: getETLDPlusOne
  };
})();
