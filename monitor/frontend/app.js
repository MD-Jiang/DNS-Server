/* ── Config ────────────────────────────────────────────────────────────────── */
const API       = "";           // same origin; set to "http://localhost:8080" for dev
const POLL_MS   = 2000;
const PIE_COLORS = {
  types:  ["#38bdf8","#818cf8","#34d399","#fb923c","#f472b6","#a78bfa","#94a3b8"],
  rcodes: ["#34d399","#f87171","#fb923c","#fbbf24","#94a3b8"],
};

/* ── Chart.js global defaults ──────────────────────────────────────────────── */
Chart.defaults.color          = "#94a3b8";
Chart.defaults.borderColor    = "rgba(255,255,255,.06)";
Chart.defaults.font.family    = "inherit";

/* ── State ─────────────────────────────────────────────────────────────────── */
let chartQps, chartTypes, chartRcodes;
let lastTotal = 0;

/* ── Boot ──────────────────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  poll();
  setInterval(poll, POLL_MS);

  document.getElementById("bench-run").addEventListener("click", runBench);
});

/* ── Polling ───────────────────────────────────────────────────────────────── */
async function poll() {
  const [stats, proc, health] = await Promise.allSettled([
    fetchJSON(`${API}/api/stats`),
    fetchJSON(`${API}/api/process`),
    fetchJSON(`${API}/api/server/health`),
  ]);

  if (stats.status === "fulfilled") updateStats(stats.value);
  if (proc.status  === "fulfilled") updateProc(proc.value);

  const online = health.status === "fulfilled" && health.value?.online;
  updateBadge("badge-server", online ? "在线" : "离线",
              online ? "ok" : "down");
  updateBadge("badge-proxy",  stats.status === "fulfilled" ? "代理正常" : "代理异常",
              stats.status === "fulfilled" ? "ok" : "down");
}

async function fetchJSON(url) {
  const r = await fetch(url);
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

/* ── DOM updates ───────────────────────────────────────────────────────────── */
function updateStats(d) {
  setText("kpi-total", fmtNum(d.total));
  setText("kpi-qps",   d.current_qps + " /s");
  setText("kpi-avg",   d.latency.avg_ms + " ms");
  setText("kpi-p95",   `P95: ${d.latency.p95_ms} ms  最大值: ${d.latency.max_ms} ms`);
  setText("uptime",    "运行时长 " + fmtUptime(d.uptime_s));

  // QPS line chart
  const labels = d.qps_timeline.map(b =>
    new Date(b.ts * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
  );
  const counts = d.qps_timeline.map(b => b.count);
  chartQps.data.labels   = labels;
  chartQps.data.datasets[0].data = counts;
  chartQps.update("none");

  // Pie: query types
  if (Object.keys(d.query_types).length) {
    const typePairs = Object.entries(d.query_types).sort((a, b) => b[1] - a[1]);
    chartTypes.data.labels   = typePairs.map(p => p[0]);
    chartTypes.data.datasets[0].data   = typePairs.map(p => p[1]);
    chartTypes.data.datasets[0].backgroundColor =
      typePairs.map((_, i) => PIE_COLORS.types[i % PIE_COLORS.types.length]);
    chartTypes.update("none");
  }

  // Pie: rcodes
  if (Object.keys(d.rcodes).length) {
    const rcodePairs = Object.entries(d.rcodes).sort((a, b) => b[1] - a[1]);
    const rcolorMap  = { NOERROR: PIE_COLORS.rcodes[0], NXDOMAIN: PIE_COLORS.rcodes[1],
                         SERVFAIL: PIE_COLORS.rcodes[2], TIMEOUT: PIE_COLORS.rcodes[3] };
    chartRcodes.data.labels   = rcodePairs.map(p => p[0]);
    chartRcodes.data.datasets[0].data   = rcodePairs.map(p => p[1]);
    chartRcodes.data.datasets[0].backgroundColor =
      rcodePairs.map(p => rcolorMap[p[0]] || PIE_COLORS.rcodes[4]);
    chartRcodes.update("none");
  }

  // Top domains table
  const tbody = document.querySelector("#tbl-domains tbody");
  tbody.innerHTML = d.top_domains.map(([domain, count], i) =>
    `<tr><td>${i + 1}</td><td>${escHtml(domain)}</td><td>${fmtNum(count)}</td></tr>`
  ).join("");

  lastTotal = d.total;
}

function updateProc(d) {
  if (!d.online) {
    setText("kpi-cpu", "—");
    setText("kpi-mem", "进程未找到");
    return;
  }
  setText("kpi-cpu", d.cpu_pct.toFixed(1) + " %");
  setText("kpi-mem", `RSS ${d.mem_rss_mb} MB`);
}

function updateBadge(id, label, cls) {
  const el = document.getElementById(id);
  el.textContent = "● " + label;
  el.className   = "badge " + (cls || "");
}

/* ── Benchmark ─────────────────────────────────────────────────────────────── */
async function runBench() {
  const btn  = document.getElementById("bench-run");
  const res  = document.getElementById("bench-result");
  const mode        = document.getElementById("bench-mode").value;
  const domainSet   = document.getElementById("bench-domain-set").value;
  const host        = document.getElementById("bench-host").value.trim() || undefined;
  const port = parseInt(document.getElementById("bench-port").value) || 2053;

  let concurrency, total;
  if (mode === "normal") {
    concurrency = parseInt(document.getElementById("bench-concurrency").value) || 20;
    total       = parseInt(document.getElementById("bench-total").value) || 500;
  } else {
    // stress: override with higher defaults
    concurrency = Math.max(
      parseInt(document.getElementById("bench-concurrency").value) || 100, 50
    );
    total       = Math.max(
      parseInt(document.getElementById("bench-total").value) || 2000, 500
    );
  }

  btn.disabled    = true;
  btn.textContent = "⏳ 测试中…";
  res.className   = "bench-result";
  res.textContent = `正在发送 ${total} 个请求（并发 ${concurrency}）…`;

  try {
    const body = { mode, concurrency, total, domain_set: domainSet };
    if (host) { body.target_host = host; }
    body.target_port = port;

    const data = await fetchJSON_post(`${API}/api/bench`, body);
    res.textContent = formatBenchResult(data);
  } catch (e) {
    res.textContent = "错误：" + e.message;
  } finally {
    btn.disabled    = false;
    btn.textContent = "▶ 开始测试";
  }
}

async function fetchJSON_post(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(r.status);
  return r.json();
}

function formatBenchResult(d) {
  const bar = (n, total) => {
    const pct = total ? Math.round((n / total) * 20) : 0;
    return "█".repeat(pct) + "░".repeat(20 - pct) + ` ${n}`;
  };
  const domainSetLabel = d.domain_set === "local" ? "本地域名" : "外部域名";
  return [
    `模式       : ${d.mode}`,
    `域名集     : ${domainSetLabel}`,
    `总计       : ${d.total}  耗时: ${d.duration_s}s`,
    `QPS        : ${d.qps}`,
    ``,
    `成功       : ${bar(d.success,  d.total)}`,
    `失败       : ${bar(d.error,    d.total)}`,
    `超时       : ${bar(d.timeout,  d.total)}`,
    ``,
    `延迟 (ms)`,
    `  均值     : ${d.latency_ms.avg}`,
    `  P50      : ${d.latency_ms.p50}`,
    `  P95      : ${d.latency_ms.p95}`,
    `  P99      : ${d.latency_ms.p99}`,
    `  最大值   : ${d.latency_ms.max}`,
  ].join("\n");
}

/* ── Chart init ────────────────────────────────────────────────────────────── */
function initCharts() {
  const line = document.getElementById("chart-qps").getContext("2d");
  chartQps = new Chart(line, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "QPS",
        data: [],
        borderColor:     "#38bdf8",
        backgroundColor: "rgba(56,189,248,.10)",
        borderWidth: 2,
        pointRadius: 0,
        fill: true,
        tension: 0.3,
      }],
    },
    options: {
      animation: false,
      plugins: { legend: { display: false } },
      scales: {
        x: {
          ticks: { maxTicksLimit: 8, maxRotation: 0 },
          grid:  { color: "rgba(255,255,255,.05)" },
        },
        y: {
          beginAtZero: true,
          grid: { color: "rgba(255,255,255,.05)" },
        },
      },
    },
  });

  chartTypes = new Chart(
    document.getElementById("chart-types").getContext("2d"),
    makePieConfig()
  );

  chartRcodes = new Chart(
    document.getElementById("chart-rcodes").getContext("2d"),
    makePieConfig()
  );
}

function makePieConfig() {
  return {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderWidth: 2,
      borderColor: "oklch(18% 0.01 260)" }] },
    options: {
      animation: false,
      cutout: "62%",
      plugins: {
        legend: {
          position: "bottom",
          labels: { boxWidth: 12, padding: 12, font: { size: 11 } },
        },
      },
    },
  };
}

/* ── Helpers ───────────────────────────────────────────────────────────────── */
function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function fmtNum(n) {
  return n >= 1_000_000 ? (n / 1_000_000).toFixed(1) + "M"
       : n >= 1_000     ? (n / 1_000).toFixed(1) + "K"
       : String(n);
}

function fmtUptime(s) {
  s = Math.floor(s);
  if (s < 60)   return s + " 秒";
  if (s < 3600) return Math.floor(s / 60) + " 分 " + (s % 60) + " 秒";
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  return h + " 时 " + m + " 分";
}

function escHtml(str) {
  return str.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}
