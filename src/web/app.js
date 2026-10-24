document.addEventListener("DOMContentLoaded", () => {
  // Elements
  const themeToggle = document.getElementById("themeToggle");
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tabPanes = document.querySelectorAll(".tab-pane");

  const corpusSelect = document.getElementById("corpusSelect");
  const emailInput = document.getElementById("emailInput");
  const analyzeEmailBtn = document.getElementById("analyzeEmailBtn");
  const clearEmailBtn = document.getElementById("clearEmailBtn");
  const browseBtn = document.getElementById("browseBtn");
  const fileInput = document.getElementById("fileInput");
  const fileDropZone = document.getElementById("fileDropZone");

  const emailEmptyState = document.getElementById("emailEmptyState");
  const emailResultsContent = document.getElementById("emailResultsContent");
  const scoreValue = document.getElementById("scoreValue");
  const scoreCircle = document.getElementById("scoreCircle");
  const tierBadge = document.getElementById("tierBadge");
  const tierVerdict = document.getElementById("tierVerdict");
  const headerPts = document.getElementById("headerPts");
  const bodyPts = document.getElementById("bodyPts");
  const urlPts = document.getElementById("urlPts");
  const authBonus = document.getElementById("authBonus");

  const senderDisplay = document.getElementById("senderDisplay");
  const senderEmail = document.getElementById("senderEmail");
  const senderDomain = document.getElementById("senderDomain");
  const senderReplyTo = document.getElementById("senderReplyTo");
  const emailSubject = document.getElementById("emailSubject");
  const spfBadge = document.getElementById("spfBadge");
  const dkimBadge = document.getElementById("dkimBadge");

  const findingsCount = document.getElementById("findingsCount");
  const findingsList = document.getElementById("findingsList");
  const linksCount = document.getElementById("linksCount");
  const linksList = document.getElementById("linksList");
  const recommendationsList = document.getElementById("recommendationsList");
  const disclaimerText = document.getElementById("disclaimerText");

  const standaloneUrlInput = document.getElementById("standaloneUrlInput");
  const analyzeUrlBtn = document.getElementById("analyzeUrlBtn");
  const urlResultsContainer = document.getElementById("urlResultsContainer");
  const chipBtns = document.querySelectorAll(".chip-btn");

  const runBenchmarkBtn = document.getElementById("runBenchmarkBtn");
  const benchmarkTableBody = document.getElementById("benchmarkTableBody");

  // 1. Theme Toggle
  themeToggle.addEventListener("click", () => {
    const isDark = document.body.classList.toggle("dark-theme");
    document.body.classList.toggle("light-theme", !isDark);
    const moonIcon = themeToggle.querySelector(".moon-icon");
    const sunIcon = themeToggle.querySelector(".sun-icon");
    if (moonIcon && sunIcon) {
      moonIcon.style.display = isDark ? "block" : "none";
      sunIcon.style.display = isDark ? "none" : "block";
    }
  });

  // 2. Tab Navigation
  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      tabPanes.forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      const pane = document.getElementById(targetId);
      if (pane) pane.classList.add("active");
    });
  });

  // 3. Populate Synthetic Corpus Dropdown
  async function loadCorpusList() {
    try {
      const res = await fetch("/api/corpus");
      if (!res.ok) return;
      const data = await res.json();
      data.files.forEach((file) => {
        const opt = document.createElement("option");
        opt.value = file.filename;
        opt.textContent = `${file.title} (${file.type})`;
        corpusSelect.appendChild(opt);
      });
    } catch (err) {
      console.warn("Could not load corpus list:", err);
    }
  }
  loadCorpusList();

  // Load selected corpus file
  corpusSelect.addEventListener("change", async () => {
    const filename = corpusSelect.value;
    if (!filename) return;

    try {
      const res = await fetch(`/api/corpus/${encodeURIComponent(filename)}`);
      if (res.ok) {
        const text = await res.text();
        emailInput.value = text;
        runEmailAnalysis(text);
      }
    } catch (err) {
      alert("Error loading corpus file: " + err.message);
    }
  });

  // 4. File Drag and Drop & Browse
  browseBtn.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", (e) => {
    const file = e.target.files[0];
    if (file) readFile(file);
  });

  fileDropZone.addEventListener("dragover", (e) => {
    e.preventDefault();
    fileDropZone.classList.add("dragover");
  });

  fileDropZone.addEventListener("dragleave", () => {
    fileDropZone.classList.remove("dragover");
  });

  fileDropZone.addEventListener("drop", (e) => {
    e.preventDefault();
    fileDropZone.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      readFile(e.dataTransfer.files[0]);
    }
  });

  function readFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      emailInput.value = event.target.result;
      runEmailAnalysis(emailInput.value);
    };
    reader.readAsText(file);
  }

  // 5. Clear Button
  clearEmailBtn.addEventListener("click", () => {
    emailInput.value = "";
    corpusSelect.value = "";
    emailEmptyState.style.display = "flex";
    emailResultsContent.style.display = "none";
  });

  // 6. Analyze Email Action
  analyzeEmailBtn.addEventListener("click", () => {
    const content = emailInput.value.trim();
    if (!content) {
      alert("Please paste email content or select a synthetic test sample.");
      return;
    }
    runEmailAnalysis(content);
  });

  async function runEmailAnalysis(rawText) {
    const textSpan = document.getElementById("analyzeEmailBtnText");
    analyzeEmailBtn.disabled = true;
    if (textSpan) textSpan.textContent = "Analyzing...";

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: rawText }),
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const report = await res.json();
      renderEmailReport(report);
    } catch (err) {
      alert("Analysis failed: " + err.message);
    } finally {
      analyzeEmailBtn.disabled = false;
      if (textSpan) textSpan.textContent = "Analyze Threat";
    }
  }

  function renderEmailReport(report) {
    emailEmptyState.style.display = "none";
    emailResultsContent.style.display = "block";

    // 1. Score & Tier
    const score = report.risk_score;
    const tier = report.tier;
    scoreValue.textContent = score;
    tierBadge.textContent = tier.name;
    tierBadge.style.backgroundColor = `${tier.color}25`;
    tierBadge.style.color = tier.color;
    tierBadge.style.border = `1px solid ${tier.color}`;

    scoreCircle.style.borderColor = tier.color;
    scoreValue.style.color = tier.color;
    tierVerdict.textContent = report.summary_verdict;

    // 2. Component scores
    headerPts.textContent = report.component_scores.header_points;
    bodyPts.textContent = report.component_scores.body_points;
    urlPts.textContent = report.component_scores.url_points;
    authBonus.textContent = `-${report.component_scores.auth_bonus}`;

    // 3. Sender & Auth Info
    const sender = report.sender_info;
    senderDisplay.textContent = sender.from_display || "(None specified)";
    senderEmail.textContent = sender.from_email || "(None)";
    senderDomain.textContent = sender.from_domain || "(None)";
    senderReplyTo.textContent = sender.reply_to || "(Matches sender)";
    emailSubject.textContent = sender.subject || "(No Subject)";

    // SPF & DKIM pills
    updateAuthPill(spfBadge, sender.spf);
    updateAuthPill(dkimBadge, sender.dkim);

    // 4. Findings List
    findingsList.innerHTML = "";
    findingsCount.textContent = report.findings.length;
    if (report.findings.length === 0) {
      findingsList.innerHTML = `<p class="muted" style="font-size:13px;">No suspicious heuristic flags triggered.</p>`;
    } else {
      report.findings.forEach((f) => {
        const div = document.createElement("div");
        div.className = `finding-card severity-${f.severity}`;
        div.innerHTML = `
          <div class="finding-header">
            <span class="finding-title">${formatCategory(f.category)}</span>
            <span class="finding-pts" style="color: ${getSeverityColor(f.severity)}">+${f.points} pts</span>
          </div>
          <div class="finding-desc">${escapeHtml(f.description)}</div>
          ${f.evidence ? `<div class="finding-evidence">Evidence: ${escapeHtml(f.evidence)}</div>` : ""}
        `;
        findingsList.appendChild(div);
      });
    }

    // 5. Embedded Links
    linksList.innerHTML = "";
    linksCount.textContent = report.urls.length;
    if (report.urls.length === 0) {
      linksList.innerHTML = `<p class="muted" style="font-size:13px;">No external hyperlinks found in email content.</p>`;
    } else {
      report.urls.forEach((u) => {
        const div = document.createElement("div");
        div.className = "link-item";
        div.innerHTML = `
          <div class="link-header">
            <span class="link-target">${escapeHtml(u.url)}</span>
            <span class="badge-truth ${u.risk_score > 30 ? "phish" : "legit"}">${u.risk_score} pts</span>
          </div>
          <div class="link-anchor">
            <span>Domain: <strong>${escapeHtml(u.domain || "N/A")}</strong></span>
            ${u.anchor_text && u.anchor_text !== u.url ? ` | Anchor text: <em>"${escapeHtml(u.anchor_text)}"</em>` : ""}
          </div>
        `;
        linksList.appendChild(div);
      });
    }

    // 6. Recommendations
    recommendationsList.innerHTML = "";
    report.recommendations.forEach((rec) => {
      const li = document.createElement("li");
      li.textContent = rec;
      recommendationsList.appendChild(li);
    });

    // 7. Disclaimer
    disclaimerText.textContent = report.disclaimer;
  }

  function updateAuthPill(el, status) {
    const st = (status || "unknown").toLowerCase();
    el.textContent = st.toUpperCase();
    el.className = `auth-pill ${st}`;
  }

  function formatCategory(cat) {
    return cat
      .replace(/_/g, " ")
      .replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function getSeverityColor(sev) {
    switch (sev) {
      case "critical": return "#ef4444";
      case "high": return "#f97316";
      case "medium": return "#f59e0b";
      case "low": return "#00df81";
      case "info": return "#2cc295";
      default: return "#707d7d";
    }
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  // 7. Standalone URL Tab
  chipBtns.forEach((chip) => {
    chip.addEventListener("click", () => {
      const u = chip.getAttribute("data-url");
      standaloneUrlInput.value = u;
      runUrlAnalysis(u);
    });
  });

  analyzeUrlBtn.addEventListener("click", () => {
    const u = standaloneUrlInput.value.trim();
    if (!u) {
      alert("Please enter a URL to inspect.");
      return;
    }
    runUrlAnalysis(u);
  });

  async function runUrlAnalysis(urlStr) {
    const textSpan = document.getElementById("analyzeUrlBtnText");
    analyzeUrlBtn.disabled = true;
    if (textSpan) textSpan.textContent = "Scanning...";

    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: urlStr }),
      });

      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const report = await res.json();
      renderUrlReport(report);
    } catch (err) {
      alert("URL scan error: " + err.message);
    } finally {
      analyzeUrlBtn.disabled = false;
      if (textSpan) textSpan.textContent = "Scan Link";
    }
  }

  function renderUrlReport(report) {
    urlResultsContainer.style.display = "block";
    const tier = report.tier;

    let findingsHtml = "";
    if (report.findings.length === 0) {
      findingsHtml = `<p class="muted" style="font-size:13px;">No suspicious URL flags detected. Destination domain appears clean.</p>`;
    } else {
      findingsHtml = report.findings
        .map(
          (f) => `
        <div class="finding-card severity-${f.severity}">
          <div class="finding-header">
            <span class="finding-title">${formatCategory(f.category)}</span>
            <span class="finding-pts" style="color: ${getSeverityColor(f.severity)}">+${f.points} pts</span>
          </div>
          <div class="finding-desc">${escapeHtml(f.description)}</div>
          <div class="finding-evidence">Target: ${escapeHtml(f.evidence)}</div>
        </div>
      `
        )
        .join("");
    }

    urlResultsContainer.innerHTML = `
      <div class="score-banner">
        <div class="score-circle" style="border-color: ${tier.color};">
          <span class="score-number" style="color: ${tier.color};">${report.risk_score}</span>
          <span class="score-label">/ 100</span>
        </div>
        <div class="score-meta">
          <div class="tier-badge" style="background-color: ${tier.color}25; color: ${tier.color}; border: 1px solid ${tier.color};">
            ${tier.name}
          </div>
          <h3 class="tier-verdict">${report.summary_verdict}</h3>
        </div>
      </div>

      <div class="section-box" style="margin-top: 20px;">
        <h4>Heuristic URL Findings (${report.findings.length})</h4>
        <div class="findings-list">${findingsHtml}</div>
      </div>

      <div class="disclaimer-box" style="margin-top: 16px;">
        <strong>Offline Security Advisory:</strong>
        <p>${report.disclaimer}</p>
      </div>
    `;
  }

  // 8. Synthetic Corpus Benchmark Tab
  runBenchmarkBtn.addEventListener("click", async () => {
    const textSpan = document.getElementById("runBenchmarkBtnText");
    runBenchmarkBtn.disabled = true;
    if (textSpan) textSpan.textContent = "Running Benchmark...";
    benchmarkTableBody.innerHTML = `<tr><td colspan="7" class="text-center">Executing heuristics across test corpus...</td></tr>`;

    try {
      const res = await fetch("/api/benchmark");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      benchmarkTableBody.innerHTML = "";
      data.results.forEach((r) => {
        const isPhish = r.expected_truth === "Phishing";
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><code>${escapeHtml(r.filename)}</code></td>
          <td>${escapeHtml(r.title)}</td>
          <td><span class="badge-truth ${isPhish ? "phish" : "legit"}">${r.expected_truth}</span></td>
          <td><strong style="color: ${r.tier.color}; font-size: 14px;">${r.risk_score}/100</strong></td>
          <td><span class="badge-truth" style="background: ${r.tier.color}20; color: ${r.tier.color}; border: 1px solid ${r.tier.color};">${r.tier.name}</span></td>
          <td>${r.findings_count} flags</td>
          <td><button class="btn btn-secondary btn-sm load-sample-btn" data-file="${r.filename}">Inspect</button></td>
        `;
        benchmarkTableBody.appendChild(tr);
      });

      // Bind inspect buttons
      document.querySelectorAll(".load-sample-btn").forEach((btn) => {
        btn.addEventListener("click", () => {
          const fn = btn.getAttribute("data-file");
          // Switch to email tab
          document.querySelector('[data-tab="emailTab"]').click();
          corpusSelect.value = fn;
          corpusSelect.dispatchEvent(new Event("change"));
        });
      });
    } catch (err) {
      alert("Benchmark failed: " + err.message);
    } finally {
      runBenchmarkBtn.disabled = false;
      if (textSpan) textSpan.textContent = "Run Benchmark";
    }
  });
});
