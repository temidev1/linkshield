// phish-detector web · app v0.8
// wires UI: theme toggle, input, check, share, copy, history, examples

(function () {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const THEME_KEY = "phishdetect_theme";

  // ---------- elements ----------
  const themeToggle   = $("theme-toggle");
  const inputEl       = $("input");
  const checkBtn      = $("check-btn");
  const loadingEl     = $("loading");
  const loadingSteps  = $("loading-steps");
  const resultEl      = $("result");
  const verdictBanner = $("verdict-banner");
  const verdictIcon   = $("verdict-icon");
  const verdictTitle  = $("verdict-title");
  const verdictSub    = $("verdict-subtitle");
  const guidanceEl    = $("verdict-guidance");
  const guidanceList  = $("guidance-list");
  const detailsList   = $("details-list");
  const reasonsBlock  = $("reasons-block");
  const reasonsList   = $("reasons-list");
  const shareBtn      = $("share-btn");
  const copyBtn       = $("copy-btn");
  const errorEl       = $("error");
  const errorText     = $("error-text");

  let lastResult = null;
  let lastInput = "";

  // ---------- theme ----------
  function applyTheme(theme) {
    const root = document.documentElement;
    if (theme === "auto") {
      const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.setAttribute("data-theme", prefersDark ? "dark" : "light");
    } else {
      root.setAttribute("data-theme", theme);
    }
  }

  function loadTheme() {
    try {
      const saved = localStorage.getItem(THEME_KEY);
      if (saved === "dark" || saved === "light" || saved === "auto") {
        applyTheme(saved);
        return saved;
      }
    } catch (e) {}
    applyTheme("auto");
    return "auto";
  }

  function cycleTheme() {
    let current = "auto";
    try { current = localStorage.getItem(THEME_KEY) || "auto"; } catch (e) {}
    const next = current === "auto" ? "light"
               : current === "light" ? "dark"
               : "auto";
    try { localStorage.setItem(THEME_KEY, next); } catch (e) {}
    applyTheme(next);
  }

  // ---------- history ----------

  // ---------- utilities ----------
  function show(el) { el.classList.remove("hidden"); }
  function hide(el) { el.classList.add("hidden"); }

  function resetUI() {
    hide(resultEl);
    hide(loadingEl);
    hide(errorEl);
    loadingSteps.innerHTML = "";
    lastResult = null;
  }

  // ---------- verdict rendering ----------
  const VERDICT_UI = {
    clean: {
      bannerClass: "verdict-safe",
      icon: "✅",
      title: "NO THREATS FOUND",
      subtitle: "We checked this link and found no red flags.",
      guidance: []
    },
    suspicious: {
      bannerClass: "verdict-warn",
      icon: "⚠️",
      title: "BE CAREFUL",
      subtitle: "This looks risky. Do not trust it without checking.",
      guidance: [
        "Do not enter your password or personal details.",
        "If it claims to be your bank, call the bank using the number on the back of your card.",
        "When in doubt, close the page and do not click."
      ]
    },
    phish: {
      bannerClass: "verdict-danger",
      icon: "🛑",
      title: "DANGER",
      subtitle: "This is a scam. Do NOT click or reply.",
      guidance: [
        "Do not click the link.",
        "Do not enter any password, PIN, or BVN.",
        "Do not send money to any account mentioned.",
        "Block the sender and report the message to WhatsApp or your network.",
        "If you already clicked, change your passwords and call your bank immediately."
      ]
    },
    unknown: {
      bannerClass: "verdict-warn",
      icon: "❓",
      title: "WE CANNOT TELL",
      subtitle: "Not enough information to decide. Be careful.",
      guidance: [
        "Treat it as suspicious until proven otherwise.",
        "Do not click or share any information."
      ]
    }
  };

  function renderVerdict(result) {
    const ui = VERDICT_UI[result.verdict] || VERDICT_UI.unknown;

    verdictBanner.className = "verdict-banner " + ui.bannerClass;
    verdictIcon.textContent = ui.icon;
    verdictTitle.textContent = ui.title;
    verdictSub.textContent = ui.subtitle;

    // guidance
    if (ui.guidance && ui.guidance.length) {
      guidanceList.innerHTML = "";
      for (const g of ui.guidance) {
        const li = document.createElement("li");
        li.textContent = g;
        guidanceList.appendChild(li);
      }
      show(guidanceEl);
    } else {
      hide(guidanceEl);
    }

    // details
    detailsList.innerHTML = "";
    for (const d of (result.details || [])) {
      const li = document.createElement("li");
      li.className = d.state || "info";
      li.textContent = d.text;
      detailsList.appendChild(li);
    }

    // reasons
    if (result.reasons && result.reasons.length) {
      reasonsList.innerHTML = "";
      for (const r of result.reasons) {
        const li = document.createElement("li");
        li.className = "bad";
        li.textContent = r;
        reasonsList.appendChild(li);
      }
      show(reasonsBlock);
    } else {
      hide(reasonsBlock);
    }

    show(resultEl);
    setTimeout(() => {
      resultEl.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);
  }

  // ---------- run check ----------
  function runCheck() {
    const raw = (inputEl.value || "").trim();
    if (!raw) {
      errorText.textContent = "Please paste a link or message first.";
      show(errorEl);
      return;
    }

    resetUI();
    show(loadingEl);

    const stages = [
      "Reading your message",
      "Checking the link",
      "Looking for danger signs",
      "Checking known scam lists",
      "Preparing your result"
    ];
    loadingSteps.innerHTML = "";
    let stepIdx = 0;

    const tick = setInterval(() => {
      if (stepIdx < stages.length) {
        const li = document.createElement("li");
        li.textContent = stages[stepIdx];
        loadingSteps.appendChild(li);
        stepIdx += 1;
      }
    }, 200);

    setTimeout(async () => {
      clearInterval(tick);
      try {
        const result = await window.Report.analyzeAsync(raw);
        if (result.error) {
          hide(loadingEl);
          errorText.textContent = result.error;
          show(errorEl);
          return;
        }
        lastResult = result;
        lastInput = raw;

        hide(loadingEl);
        renderVerdict(result);
      } catch (e) {
        hide(loadingEl);
        errorText.textContent = "Something went wrong. Please try again.";
        show(errorEl);
        console.error(e);
      }
    }, 1000);
  }

  // ---------- clipboard ----------
  async function pasteFromClipboard() {
    try {
      const text = await navigator.clipboard.readText();
      if (text) inputEl.value = text;
    } catch (e) {
      inputEl.focus();
      errorText.textContent = "Could not read the clipboard. Please paste it manually into the box.";
      show(errorEl);
    }
  }

  function copyReasons() {
    if (!lastResult) return;
    const lines = [];
    lines.push("Phish Detector result");
    lines.push("Verdict: " + (VERDICT_UI[lastResult.verdict] || VERDICT_UI.unknown).title);
    if (lastResult.reasons && lastResult.reasons.length) {
      lines.push("");
      lines.push("Why:");
      for (const r of lastResult.reasons) lines.push("  - " + r);
    }
    lines.push("");
    lines.push("Checked with phish-detector (built by Maverick)");
    const text = lines.join("\n");

    navigator.clipboard.writeText(text)
      .then(() => {
        copyBtn.textContent = "Copied ✓";
        setTimeout(() => { copyBtn.textContent = "Copy the reasons"; }, 1500);
      })
      .catch(() => {
        errorText.textContent = "Could not copy. Long-press the reasons to select them manually.";
        show(errorEl);
      });
  }

  function shareResult() {
    if (!lastResult) return;
    const title = (VERDICT_UI[lastResult.verdict] || VERDICT_UI.unknown).title;
    const reasons = (lastResult.reasons || []).slice(0, 3).join("\n• ");
    const text = `Phish Detector says: ${title}\n\n${reasons ? "Why:\n• " + reasons + "\n\n" : ""}` +
                 `Check any link before you click it:`;
    const url = window.location.href;

    if (navigator.share) {
      navigator.share({
        title: "Phish Detector result",
        text: text,
        url: url
      }).catch(() => {});
    } else {
      // fallback: copy to clipboard
      navigator.clipboard.writeText(text + " " + url)
        .then(() => {
          shareBtn.textContent = "Copied ✓";
          setTimeout(() => { shareBtn.textContent = "Share"; }, 1500);
        });
    }
  }

  function clearAll() {
    inputEl.value = "";
    resetUI();
    inputEl.focus();
  }

  // ---------- examples ----------
  function loadExampleURL() {
    inputEl.value = "https://instaqram.com/login";
    inputEl.focus();
  }

  function loadExampleMsg() {
    inputEl.value =
      "Dear customer, your Zenith Bank account will be blocked within 24 hours. " +
      "Send your BVN immediately to verify. Click here: https://bit.ly/abc123";
    inputEl.focus();
  }

  // ---------- wire up ----------
  loadTheme();
  themeToggle.addEventListener("click", cycleTheme);

  checkBtn.addEventListener("click", runCheck);
  shareBtn.addEventListener("click", shareResult);
  copyBtn.addEventListener("click", copyReasons);

  inputEl.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      runCheck();
    }
  });


  // watch system theme changes when set to auto
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
      let current = "auto";
      try { current = localStorage.getItem(THEME_KEY) || "auto"; } catch (e) {}
      if (current === "auto") applyTheme("auto");
    });
  }
})();
