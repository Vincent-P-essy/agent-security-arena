const state = { scenarios: [], report: null };

const percent = (value) => `${(value * 100).toFixed(1)}%`;
const defenseLabel = (value) => value.replaceAll("_", " ").replace(/\b\w/g, (c) => c.toUpperCase());

async function loadScenarios() {
  const list = document.querySelector("#scenario-list");
  list.replaceChildren();
  try {
    const response = await fetch("/api/scenarios");
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    state.scenarios = await response.json();
    const attacks = state.scenarios.filter((item) => !item.benign).length;
    const benign = state.scenarios.length - attacks;
    document.querySelector("#scenario-count").textContent = String(state.scenarios.length);
    document.querySelector("#scenario-mix").textContent = `${attacks} attacks / ${benign} controls`;
    document.querySelector("#corpus-status").textContent = `${attacks} adversarial, ${benign} benign`;
    for (const scenario of state.scenarios) {
      const row = document.createElement("div");
      row.className = "scenario-item";
      const marker = document.createElement("i");
      marker.className = `scenario-kind${scenario.benign ? " benign" : ""}`;
      const body = document.createElement("div");
      const title = document.createElement("strong");
      title.textContent = scenario.title;
      const type = document.createElement("span");
      type.textContent = `${scenario.attack_type} / ${scenario.content_type}`;
      body.append(title, type);
      row.append(marker, body);
      list.append(row);
    }
  } catch (error) {
    document.querySelector("#corpus-status").textContent = "Suite unavailable";
    list.textContent = String(error);
  }
}

async function loadLatestReport() {
  try {
    const response = await fetch("/api/report");
    if (response.ok) {
      state.report = await response.json();
      renderReport(state.report);
    }
  } catch (_) {
    // The dashboard remains usable when no prior in-process report exists.
  }
}

function selectedDefenses() {
  return [...document.querySelectorAll("#defense-controls input:checked")].map((item) => item.value);
}

async function runEvaluation() {
  const button = document.querySelector("#run-button");
  const runState = document.querySelector("#run-state");
  const defenses = selectedDefenses();
  if (!defenses.length) {
    runState.className = "run-state error";
    runState.innerHTML = '<span class="state-dot"></span> Select a defense';
    return;
  }
  button.disabled = true;
  runState.className = "run-state running";
  runState.innerHTML = '<span class="state-dot"></span> Running';
  try {
    const response = await fetch("/api/evaluate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        defenses,
        repetitions: Number(document.querySelector("#repetitions").value),
      }),
    });
    if (!response.ok) throw new Error(await response.text());
    state.report = await response.json();
    renderReport(state.report);
    runState.className = "run-state";
    runState.innerHTML = '<span class="state-dot"></span> Complete';
  } catch (error) {
    runState.className = "run-state error";
    runState.innerHTML = '<span class="state-dot"></span> Failed';
    document.querySelector("#measurement-caption").textContent = String(error);
  } finally {
    button.disabled = false;
  }
}

function renderReport(report) {
  const summaries = report.summaries;
  const best = [...summaries].sort(
    (a, b) => a.fault_rate.rate - b.fault_rate.rate || a.attack_success_rate.rate - b.attack_success_rate.rate,
  )[0];
  document.querySelector("#best-asr").textContent = percent(best.attack_success_rate.rate);
  document.querySelector("#best-defense").textContent = defenseLabel(best.defense);
  document.querySelector("#secret-rate").textContent = percent(best.secret_leakage_rate.rate);
  document.querySelector("#refusal-rate").textContent = percent(best.false_refusal_rate.rate);
  document.querySelector("#fault-rate").textContent = percent(best.fault_rate.rate);
  document.querySelector("#run-id").textContent = new Date(report.generated_at).toLocaleTimeString();
  document.querySelector("#measurement-caption").textContent = `${summaries.length} defense configurations / ${summaries[0]?.samples ?? 0} samples each`;
  document.querySelector("#export-button").disabled = false;

  const body = document.querySelector("#results-body");
  body.replaceChildren();
  for (const item of summaries) {
    const row = document.createElement("tr");
    const values = [
      defenseLabel(item.defense),
      `${item.completed_samples}/${item.samples}`,
      percent(item.fault_rate.rate),
      percent(item.attack_success_rate.rate),
      percent(item.tool_misuse_rate.rate),
      percent(item.secret_leakage_rate.rate),
      percent(item.false_refusal_rate.rate),
      percent(item.grounded_answer_rate.rate),
      `${item.p95_latency_ms.toFixed(2)} ms`,
    ];
    values.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 0) cell.className = "defense-name";
      if (index === 3) cell.classList.add(item.attack_success_rate.rate <= 0.1 ? "rate-good" : "rate-bad");
      row.append(cell);
    });
    body.append(row);
  }
  drawChart(summaries);
}

function drawChart(summaries) {
  const canvas = document.querySelector("#comparison-chart");
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.floor(rect.width * ratio));
  canvas.height = Math.max(1, Math.floor(rect.height * ratio));
  const context = canvas.getContext("2d");
  context.scale(ratio, ratio);
  const width = rect.width;
  const height = rect.height;
  const margin = { top: 18, right: 12, bottom: 64, left: 42 };
  const plotWidth = width - margin.left - margin.right;
  const plotHeight = height - margin.top - margin.bottom;
  context.clearRect(0, 0, width, height);
  context.font = "11px system-ui";
  context.textAlign = "right";
  context.textBaseline = "middle";
  for (let step = 0; step <= 4; step += 1) {
    const value = step / 4;
    const y = margin.top + plotHeight * (1 - value);
    context.strokeStyle = "#e4e7e3";
    context.beginPath();
    context.moveTo(margin.left, y);
    context.lineTo(width - margin.right, y);
    context.stroke();
    context.fillStyle = "#747b75";
    context.fillText(`${Math.round(value * 100)}%`, margin.left - 7, y);
  }
  const groupWidth = plotWidth / Math.max(1, summaries.length);
  const barWidth = Math.min(20, groupWidth / 5.5);
  const series = [
    ["attack_success_rate", "#d9485f"],
    ["tool_misuse_rate", "#c77800"],
    ["false_refusal_rate", "#087f5b"],
    ["fault_rate", "#4c6ef5"],
  ];
  summaries.forEach((item, groupIndex) => {
    const center = margin.left + groupWidth * (groupIndex + 0.5);
    series.forEach(([key, color], seriesIndex) => {
      const value = item[key].rate;
      const barHeight = value * plotHeight;
      const x = center + (seriesIndex - (series.length - 1) / 2) * (barWidth + 3) - barWidth / 2;
      context.fillStyle = color;
      context.fillRect(x, margin.top + plotHeight - barHeight, barWidth, barHeight);
    });
    context.save();
    context.translate(center, margin.top + plotHeight + 12);
    context.rotate(-0.35);
    context.fillStyle = "#59605a";
    context.textAlign = "right";
    context.textBaseline = "middle";
    context.fillText(defenseLabel(item.defense), 0, 0);
    context.restore();
  });
}

function exportReport() {
  if (!state.report) return;
  const blob = new Blob([`${JSON.stringify(state.report, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "agent-security-arena-report.json";
  link.click();
  URL.revokeObjectURL(url);
}

document.querySelector("#run-button").addEventListener("click", runEvaluation);
document.querySelector("#refresh-scenarios").addEventListener("click", loadScenarios);
document.querySelector("#export-button").addEventListener("click", exportReport);
window.addEventListener("resize", () => { if (state.report) drawChart(state.report.summaries); });
loadScenarios();
loadLatestReport();
