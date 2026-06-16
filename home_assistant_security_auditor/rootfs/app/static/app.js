const state = {
  filter: "all",
  findings: [],
};

const elements = {
  button: document.querySelector("#run-scan"),
  score: document.querySelector("#score"),
  scoreCopy: document.querySelector("#score-copy"),
  target: document.querySelector("#target"),
  generated: document.querySelector("#generated"),
  statusLine: document.querySelector("#status-line"),
  findings: document.querySelector("#findings"),
  segments: [...document.querySelectorAll(".segment")],
};

function severityLabel(item) {
  if (item.status === "pass") return "Geslaagd";
  const labels = {
    critical: "Kritiek",
    high: "Hoog",
    medium: "Medium",
    low: "Laag",
    info: "Info",
  };
  return labels[item.severity] || item.severity;
}

function scoreCopy(score) {
  if (score >= 85) return "Sterke basis. Controleer de adviezen voor verdere verharding.";
  if (score >= 65) return "Redelijke basis, maar er zijn verbeterpunten voor externe toegang.";
  if (score >= 40) return "Er zijn meerdere risico's zichtbaar. Pak de hoogste bevindingen eerst op.";
  return "De huidige configuratie verdient aandacht voordat externe toegang betrouwbaar veilig is.";
}

function renderFindings() {
  const visible = state.findings.filter((item) => state.filter === "all" || item.status === state.filter);
  elements.findings.innerHTML = "";
  if (visible.length === 0) {
    elements.findings.innerHTML = '<article class="finding"><div class="finding-accent"></div><div><h3>Geen bevindingen</h3><p>Er zijn geen items voor dit filter.</p></div></article>';
    return;
  }
  for (const item of visible) {
    const article = document.createElement("article");
    article.className = "finding";
    article.dataset.severity = item.severity;
    article.dataset.status = item.status;

    const details = item.details && Object.keys(item.details).length
      ? `<pre>${escapeHtml(JSON.stringify(item.details, null, 2))}</pre>`
      : "";

    article.innerHTML = `
      <div class="finding-accent"></div>
      <div>
        <h3>${escapeHtml(item.title)}</h3>
        <p>${escapeHtml(item.advice)}</p>
        <div class="finding-meta">${escapeHtml(item.id)}</div>
        ${details}
      </div>
      <span class="badge">${escapeHtml(severityLabel(item))}</span>
    `;
    elements.findings.appendChild(article);
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function runScan() {
  elements.button.disabled = true;
  elements.statusLine.textContent = "Scan wordt uitgevoerd...";
  try {
    const response = await fetch("/api/audit", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    state.findings = data.findings || [];
    elements.score.textContent = data.score;
    elements.scoreCopy.textContent = scoreCopy(data.score);
    elements.target.textContent = data.target || "Niet ingesteld";
    elements.generated.textContent = new Date(data.generated_at).toLocaleString();
    elements.statusLine.textContent = `${state.findings.length} controles uitgevoerd`;
    renderFindings();
  } catch (error) {
    elements.statusLine.textContent = `Scan mislukt: ${error.message}`;
  } finally {
    elements.button.disabled = false;
  }
}

elements.button.addEventListener("click", runScan);
for (const segment of elements.segments) {
  segment.addEventListener("click", () => {
    state.filter = segment.dataset.filter;
    for (const item of elements.segments) item.classList.toggle("active", item === segment);
    renderFindings();
  });
}

runScan();

