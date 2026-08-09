<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from "vue";
import {
  IconActivity,
  IconBolt,
  IconDatabase,
  IconBrain,
  IconDeviceDesktopAnalytics,
  IconEye,
  IconPlayerPlay,
  IconRefresh,
  IconSearch,
  IconServer,
  IconTerminal2,
  IconTrash,
  IconWifi,
} from "@tabler/icons-vue";

type Row = Record<string, any>;
type ViewName = "overview" | "inventory" | "memory" | "topology" | "diagnostics" | "ops" | "jobs" | "ask";

type ResourceKey =
  | "health" | "webui" | "devices" | "aps" | "topology" | "neighbors" | "jobs" | "diagnostics"
  | "attention" | "workflows" | "backups" | "topologyChanges" | "history" | "healthTimeline"
  | "commands" | "options" | "automation" | "settings";

const navItems = [
  { id: "overview" as ViewName, label: "Overview", icon: IconActivity },
  { id: "inventory" as ViewName, label: "Inventory", icon: IconDatabase },
  { id: "memory" as ViewName, label: "Memory", icon: IconBrain },
  { id: "topology" as ViewName, label: "Topology", icon: IconServer },
  { id: "diagnostics" as ViewName, label: "Diagnostics", icon: IconDeviceDesktopAnalytics },
  { id: "ops" as ViewName, label: "Operations", icon: IconBolt },
  { id: "jobs" as ViewName, label: "Jobs", icon: IconTerminal2 },
  { id: "ask" as ViewName, label: "Ask", icon: IconSearch },
];

const state = reactive<Record<string, any>>({
  health: null,
  webui: null,
  devices: [],
  aps: [],
  topology: { nodes: [], edges: [], raw_edges: [] },
  neighbors: [],
  jobs: [],
  diagnostics: null,
  attention: { items: [] },
  workflows: [],
  backups: [],
  topologyChanges: [],
  history: [],
  healthTimeline: { rows: [] },
  commands: [],
  options: { targets: [], domains: [], speed_profiles: ["quick", "balanced", "thorough"], speed_runs: ["1", "2", "3", "4", "5"], quick_actions: [] },
  automation: { schedules: [], attention_rules: [] },
  settings: {},
});

const errors = reactive<Record<string, string>>({});
const lastLoaded = reactive<Record<string, number>>({});
const loading = reactive<Record<string, boolean>>({});

const view = ref<ViewName>("overview");
const inventoryKind = ref<"devices" | "aps">("devices");
const selected = ref<Row | null>(null);
const selectedDetail = ref<any>(null);
const selectedLoading = ref(false);
const search = ref("");
const statusFilter = ref("");
const memoryMode = ref("switch");
const memoryTarget = ref("SQ10");
const memoryPort = ref("");
const memoryData = ref<any>(null);
const probeTarget = ref("127.0.0.1");
const probeOrigin = ref("host");
const checkTarget = ref("example.com");
const speedProfile = ref("balanced");
const speedRuns = ref("2");
const interfaceTarget = ref("");
const interfaceName = ref("");
const interfaceChart = ref("classic");
const throughputServer = ref("");
const throughputDirection = ref("both");
const throughputPort = ref("5201");
const throughputSeconds = ref("10");
const portHealthTarget = ref("");
const portHealthInterface = ref("");
const portHealthSample = ref("5");
const portExpectedSpeed = ref("1000");
const cableTarget = ref("");
const cableInterface = ref("");
const backupTarget = ref("");
const commandSearch = ref("");
const commandAction = ref("");
const commandArgs = reactive<Record<string, string>>({});
const jobFilter = ref("all");
const activeJob = ref("No job selected");
const jobLog = ref("Select a job to view output.");
const liveLog = ref("Run a task to stream output here.");
const askQuestion = ref("How many APs are offline in SQ10?");
const askResult = ref<any>(null);
const askLoading = ref(false);
const askSession = ref<Row>({ history: [] });
const askTranscript = ref<Row[]>([]);
const askPreview = ref<any>(null);
const statusMessage = ref("[STATUS] Ready");
const shellRef = ref<HTMLElement | null>(null);
const eventSource = ref<EventSource | null>(null);
let timer = 0;
let statusTimer = 0;

const resources: Record<ResourceKey, string> = {
  health: "/api/health",
  webui: "/api/webui/status",
  devices: "/api/devices",
  aps: "/api/aps",
  topology: "/api/topology/graph",
  neighbors: "/api/neighbors",
  jobs: "/api/jobs",
  diagnostics: "/api/diagnostics",
  attention: "/api/attention",
  workflows: "/api/workflows",
  backups: "/api/backups",
  topologyChanges: "/api/topology/changes",
  history: "/api/history",
  healthTimeline: "/api/health/timeline",
  commands: "/api/commands",
  options: "/api/options",
  automation: "/api/automation",
  settings: "/api/settings",
};

const lightKeys: ResourceKey[] = ["health", "webui", "jobs", "diagnostics", "attention"];
const heavyKeys: ResourceKey[] = ["devices", "aps", "topology", "neighbors", "workflows", "backups", "topologyChanges", "history", "healthTimeline", "commands", "options", "automation", "settings"];

function handlePointerMove(event: PointerEvent) {
  const root = shellRef.value;
  if (!root || event.pointerType === "touch") return;
  root.style.setProperty("--pointer-x", `${event.clientX}px`);
  root.style.setProperty("--pointer-y", `${event.clientY}px`);
}

function resetPointer() {
  shellRef.value?.style.setProperty("--pointer-x", "72vw");
  shellRef.value?.style.setProperty("--pointer-y", "18vh");
}

async function api(path: string, opts: RequestInit = {}) {
  const response = await fetch(path, { headers: { "content-type": "application/json" }, ...opts });
  const text = await response.text();
  const data = text ? JSON.parse(text) : null;
  if (!response.ok) throw new Error(data?.error || data?.reason || text || response.statusText);
  return data;
}

function normalizeResource(key: ResourceKey, data: any) {
  if (!data) return data;
  if (key === "commands") return Array.isArray(data) ? data : data.commands || [];
  if (key === "workflows") return Array.isArray(data) ? data : data.workflows || [];
  if (key === "jobs") return Array.isArray(data) ? data : data.rows || data.jobs || [];
  if (["devices", "aps", "neighbors", "topologyChanges", "history", "backups"].includes(key)) {
    return Array.isArray(data) ? data : data.rows || data.items || [];
  }
  return data;
}

async function loadKey(key: ResourceKey) {
  loading[key] = true;
  try {
    const data = await api(resources[key]);
    state[key] = normalizeResource(key, data);
    errors[key] = "";
    lastLoaded[key] = Date.now();
  } catch (error: any) {
    errors[key] = error.message || String(error);
  } finally {
    loading[key] = false;
  }
}

async function loadKeys(keys: ResourceKey[]) {
  await Promise.allSettled(keys.map((key) => loadKey(key)));
}

function refreshAll() {
  loadKeys([...lightKeys, ...heavyKeys]);
}

function refreshCurrentView() {
  if (view.value === "inventory") return loadKeys(["devices", "aps"]);
  if (view.value === "topology") return loadKeys(["topology", "neighbors", "topologyChanges"]);
  if (view.value === "diagnostics") return loadKeys(["diagnostics", "options"]);
  if (view.value === "ops") return loadKeys(["workflows", "commands", "backups", "automation"]);
  if (view.value === "jobs") return loadKeys(["jobs"]);
  return loadKeys(lightKeys);
}

function notify(msg: string) {
  const text = String(msg || "Ready");
  statusMessage.value = text.startsWith("[") ? text : `[STATUS] ${text}`;
  window.clearTimeout(statusTimer);
  statusTimer = window.setTimeout(() => { statusMessage.value = "[STATUS] Ready"; }, 4200);
}

const counts = computed(() => state.health?.counts || {});
const rows = computed<Row[]>(() => inventoryKind.value === "devices" ? state.devices : state.aps);
const filteredRows = computed(() => {
  const q = search.value.trim().toLowerCase();
  return rows.value.filter((row) => {
    const blob = JSON.stringify(row).toLowerCase();
    return (!q || blob.includes(q)) && (!statusFilter.value || row.status === statusFilter.value);
  });
});
const inventoryColumns = computed(() => inventoryKind.value === "devices"
  ? [["IP", "ip"], ["Hostname", "hostname"], ["Platform", "platform"], ["Model", "model"], ["Status", "status"]]
  : [["IP", "ip"], ["Name", "name"], ["Switch", "switch_name"], ["Port", "switch_port"], ["Status", "status"]]
);
const targetOptions = computed(() => state.options?.targets?.length ? state.options.targets : [{ label: "Localhost", value: "127.0.0.1" }]);
const domainOptions = computed(() => state.options?.domains?.length ? state.options.domains : [{ label: "Example", value: "example.com" }]);
const speedProfileOptions = computed(() => state.options?.speed_profiles?.length ? state.options.speed_profiles : ["quick", "balanced", "thorough"]);
const speedRunOptions = computed(() => {
  const runs = state.options?.speed_runs?.length ? state.options.speed_runs : ["1", "2", "3", "4", "5"];
  return speedProfile.value === "quick" ? runs : runs.filter((run: string) => Number(run) >= 2);
});
const runningJobs = computed(() => state.jobs.filter((job: Row) => ["queued", "running"].includes(String(job.status))));
const failedJobs = computed(() => state.jobs.filter((job: Row) => String(job.status) === "failed"));
const attentionItems = computed(() => state.attention?.items || []);
const recentJobs = computed(() => state.jobs.slice(0, 5));
const visibleJobs = computed(() => {
  if (jobFilter.value === "all") return state.jobs;
  if (jobFilter.value === "active") return state.jobs.filter((job: Row) => ["queued", "running"].includes(String(job.status)));
  return state.jobs.filter((job: Row) => String(job.status) === jobFilter.value);
});
const commands = computed<Row[]>(() => state.commands || []);
const visibleCommands = computed(() => {
  const q = commandSearch.value.trim().toLowerCase();
  return commands.value.filter((cmd) => !q || JSON.stringify(cmd).toLowerCase().includes(q));
});
const activeCommand = computed(() => commands.value.find((cmd) => cmd.id === commandAction.value) || visibleCommands.value[0] || null);
const commandById = computed(() => new Map(commands.value.map((cmd) => [cmd.id, cmd])));
const workflowRows = computed(() => state.workflows || []);
const diagnosticSummary = computed(() => state.diagnostics?.summary || { counts: {} });
const graph = computed(() => state.topology || { nodes: [], edges: [], raw_edges: [] });
const graphNodes = computed(() => {
  const nodes = (graph.value.nodes || []).slice(0, 36);
  const cx = 400;
  const cy = 190;
  const rx = 310;
  const ry = 135;
  return nodes.map((node: Row, index: number) => {
    const angle = (Math.PI * 2 * index) / Math.max(nodes.length, 1) - Math.PI / 2;
    return { ...node, x: cx + Math.cos(angle) * rx, y: cy + Math.sin(angle) * ry };
  });
});
const graphNodeMap = computed(() => new Map(graphNodes.value.map((node: Row) => [node.id, node])));
const graphEdges = computed(() => (graph.value.edges || []).slice(0, 80).map((edge: Row) => ({ ...edge, sourceNode: graphNodeMap.value.get(edge.source), targetNode: graphNodeMap.value.get(edge.target) })).filter((edge: Row) => edge.sourceNode && edge.targetNode));
const memoryRows = computed<Row[]>(() => {
  const data = memoryData.value;
  if (!data) return [];
  const rows = data.attachments?.relationships || data.current || (memoryMode.value === "explain" ? data.rows : []) || [];
  return [...rows].sort((left: Row, right: Row) => Number(right.last_seen || right.updated_at || right.first_seen || 0) - Number(left.last_seen || left.updated_at || left.first_seen || 0));
});
const memoryNeighbors = computed(() => memoryData.value?.attachments?.neighbors || []);
const memoryTimeline = computed<Row[]>(() => {
  const data = memoryData.value;
  if (!data) return [];
  const rows = data.timeline || (["ip", "mac", "timeline"].includes(memoryMode.value) ? data.rows : []) || [];
  return [...rows].sort((left: Row, right: Row) => Number(right.created_at || 0) - Number(left.created_at || 0) || Number(right.id || 0) - Number(left.id || 0));
});
const memoryLatestAt = computed(() => {
  if (memoryData.value?.latest_recorded_at) return Number(memoryData.value.latest_recorded_at);
  return Math.max(
    0,
    ...memoryRows.value.map((row: Row) => Number(row.last_seen || row.updated_at || row.first_seen || 0)),
    ...memoryTimeline.value.map((row: Row) => Number(row.created_at || 0)),
  );
});
const webuiWarning = computed(() => {
  if (state.webui && state.webui.ok === false) return `WebUI state needs attention: ${(state.webui.missing || []).join(", ")}`;
  const failed = Object.entries(errors).filter(([, value]) => value).slice(0, 2);
  return failed.length ? `Some data failed to load: ${failed.map(([key]) => key).join(", ")}` : "";
});

const askRows = computed<Row[]>(() => Array.isArray(askResult.value?.result?.rows) ? askResult.value.result.rows : []);
const askWorkflow = computed<Row[]>(() => Array.isArray(askResult.value?.workflow) ? askResult.value.workflow : []);
const askPlan = computed<Row | null>(() => askResult.value?.command_plan && typeof askResult.value.command_plan === "object" ? askResult.value.command_plan : null);
const askColumns = computed(() => {
  const preferred = ["name", "hostname", "ip", "status", "kind", "switch_name", "switch_port", "platform", "model", "event_type", "rel_type", "subject_id", "object_id", "source", "confidence", "last_seen", "created_at"];
  const available = new Set(askRows.value.flatMap((row) => Object.keys(row).filter((key) => !key.endsWith("_iso"))));
  const ordered = preferred.filter((key) => available.has(key));
  for (const key of available) if (!ordered.includes(key) && ordered.length < 8) ordered.push(key);
  return ordered.slice(0, 8);
});
const askStateLabel = computed(() => {
  if (askLoading.value) return "querying";
  if (askResult.value?.ok === false) return "not matched";
  if (askPlan.value?.status === "needs_clarification") return "needs input";
  if (askPlan.value?.status === "preview_only") return "preview only";
  if (askPlan.value?.status === "ready") return "plan ready";
  if (askResult.value) return "answered";
  return "ready";
});

const healthLabel = computed(() => {
  if (runningJobs.value.length) return `${runningJobs.value.length} running`;
  if (failedJobs.value.length) return `${failedJobs.value.length} failed`;
  if (Number(counts.value.offline_devices || 0) || Number(counts.value.offline_aps || 0)) return "review";
  return "steady";
});
const overviewStats = computed(() => [
  { label: "Devices", value: counts.value.devices || 0, hint: `${counts.value.offline_devices || 0} offline` },
  { label: "APs", value: counts.value.aps || 0, hint: `${counts.value.offline_aps || 0} offline` },
  { label: "Links", value: counts.value.neighbors || 0, hint: "topology cache" },
  { label: "Jobs", value: counts.value.running_jobs || 0, hint: `${counts.value.failed_jobs || 0} failed` },
]);

function fmtTime(value: any) {
  const num = Number(value);
  if (!Number.isFinite(num) || num <= 0) return "not recorded";
  const date = new Date(num * 1000);
  if (Number.isNaN(date.getTime())) return "not recorded";
  return date.toISOString().replace(/\.\d{3}Z$/, "Z");
}

function isTimestampKey(key: string) {
  return key.endsWith("_at") || ["first_seen", "last_seen", "last_failed"].includes(key);
}

function cellValue(row: Row, key: string) {
  return isTimestampKey(key) ? fmtTime(row[key]) : (row[key] || "");
}

function columnLabel(key: string) {
  return key.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function badgeClass(value: any) {
  const s = String(value || "").toLowerCase();
  if (s.includes("fail") || s === "offline" || s.includes("cancel") || s === "danger" || s === "attention") return "text-bg-danger";
  if (s.includes("run") || s.includes("queue") || s.includes("warn") || s === "warning" || s === "review" || s === "watch" || s === "interactive") return "text-bg-warning";
  if (s.includes("online") || s.includes("complete") || s === "ok" || s === "steady" || s === "safe") return "text-bg-success";
  return "text-bg-secondary";
}

function fieldList(row: Row | null) {
  if (!row) return [];
  return Object.entries(row).filter(([, value]) => value !== null && value !== undefined && value !== "").slice(0, 18);
}

async function selectRow(row: Row) {
  selected.value = row;
  selectedDetail.value = null;
  selectedLoading.value = true;
  try {
    const kind = inventoryKind.value === "aps" ? "ap" : "device";
    const target = row.ip || row.name || row.hostname;
    selectedDetail.value = await api(`/api/inventory/detail?kind=${encodeURIComponent(kind)}&target=${encodeURIComponent(target)}`);
  } catch (error: any) {
    notify(error.message || String(error));
  } finally {
    selectedLoading.value = false;
  }
}

function useSelectedForMemory(mode = "switch") {
  if (!selected.value) return;
  memoryMode.value = mode;
  memoryTarget.value = selected.value.switch_name || selected.value.hostname || selected.value.name || selected.value.ip || "";
  memoryPort.value = selected.value.switch_port || "";
  view.value = "memory";
  loadMemory();
}

async function loadMemory() {
  const target = memoryTarget.value.trim();
  if (!target) return notify("Choose a memory target");
  try {
    const params = new URLSearchParams({ mode: memoryMode.value, target, limit: "160" });
    if (memoryPort.value.trim()) params.set("port", memoryPort.value.trim());
    memoryData.value = await api(`/api/memory/query?${params.toString()}`);
    notify("Memory loaded");
  } catch (error: any) {
    notify(error.message || String(error));
  }
}

function commandArgsFor(cmd: Row | null) {
  const out: Row = {};
  for (const field of cmd?.arg_schema || []) out[field.name] = commandArgs[field.name] || field.default || "";
  return out;
}

async function previewCommand(action = activeCommand.value?.id, args: Row = commandArgsFor(activeCommand.value)) {
  if (!action) return notify("Choose a command");
  try {
    const preview = await api("/api/preview", { method: "POST", body: JSON.stringify({ action, args }) });
    liveLog.value = preview.blocked ? `${preview.reason}\n${preview.command || ""}` : preview.command;
    notify(preview.blocked ? "Preview is blocked" : "Preview ready");
  } catch (error: any) {
    notify(error.message || String(error));
  }
}

async function startJob(action: string, args: Row = {}) {
  try {
    const job = await api("/api/jobs", { method: "POST", body: JSON.stringify({ action, args }) });
    notify(`Started ${action}`);
    await loadKey("jobs");
    watchJob(job.id);
    view.value = "jobs";
  } catch (error: any) {
    notify(error.message || String(error));
  }
}

function runCommand() {
  const cmd = activeCommand.value;
  if (!cmd) return notify("Choose a command");
  if (cmd.run_supported === false || cmd.risk_level === "danger") return previewCommand(cmd.id, commandArgsFor(cmd));
  startJob(cmd.id, commandArgsFor(cmd));
}

function canRetry(job: Row) {
  const cmd = commandById.value.get(job.action);
  if (!cmd || cmd.run_supported === false || cmd.risk_level === "danger") return false;
  return !(cmd.arg_schema || []).some((field: Row) => field.required && !field.default);
}

function reviewJobCommand(job: Row) {
  commandAction.value = job.action;
  view.value = "ops";
  notify("Command opened for review");
}

function retryJob(job: Row) {
  const cmd = commandById.value.get(job.action);
  if (!cmd) return notify("Unknown command for retry");
  startJob(job.action, commandArgsFor(cmd));
}

function runProbe() { startJob(probeOrigin.value === "core" ? "diagnose-core-ping" : "diagnose-latency", { target: probeTarget.value || "127.0.0.1", count: "5" }); }
function speedDefaultRuns(profile: string) { return profile === "quick" ? "1" : profile === "thorough" ? "3" : "2"; }
function setSpeedProfile(profile: string) { speedProfile.value = profile; speedRuns.value = speedDefaultRuns(profile); }
function runSpeed() { startJob("diagnose-speed", { profile: speedProfile.value || "balanced", runs: speedRuns.value || speedDefaultRuns(speedProfile.value) }); }
function runFiltering() { startJob("diagnose-filtering", { target: checkTarget.value || "google.com" }); }
function runInterface() { startJob("diagnose-interface", { target: interfaceTarget.value, interface: interfaceName.value, chart: interfaceChart.value, once: true }); }
function runThroughput() {
  const target = throughputServer.value || state.options?.core_iperf_server;
  target ? startJob("diagnose-throughput", { target, direction: throughputDirection.value, port: throughputPort.value, seconds: throughputSeconds.value }) : notify("Choose an iperf3 server");
}
function runPortHealth() {
  portHealthTarget.value && portHealthInterface.value
    ? startJob("diagnose-port-health", { device: portHealthTarget.value, interface: portHealthInterface.value, sample_seconds: portHealthSample.value, expected_speed: portExpectedSpeed.value })
    : notify("Choose a switch and interface");
}
function runCableStatus() {
  cableTarget.value && cableInterface.value
    ? startJob("diagnose-cable", { device: cableTarget.value, interface: cableInterface.value })
    : notify("Choose a switch and copper interface");
}
function previewCableTest() {
  cableTarget.value && cableInterface.value
    ? previewCommand("diagnose-cable-test", { device: cableTarget.value, interface: cableInterface.value })
    : notify("Choose a switch and copper interface");
}
function runDoctor() { startJob("diagnose-doctor", {}); }
function runBackup() { backupTarget.value.trim() ? startJob("backup-run", { target: backupTarget.value.trim() }) : notify("Choose a backup target"); }

async function cancelJob(id: string) {
  try {
    await api(`/api/jobs/${id}/cancel`, { method: "POST" });
    notify("Cancel requested");
    await loadKey("jobs");
  } catch (error: any) {
    notify(error.message || String(error));
  }
}

async function watchJob(id: string) {
  eventSource.value?.close();
  activeJob.value = id;
  jobLog.value = "";
  liveLog.value = "";
  let lastLogId = 0;
  try {
    const existing = await api(`/api/jobs/${id}`);
    if (existing.logs?.length) {
      jobLog.value = existing.logs.map((item: Row) => `[${item.stream}] ${item.line}`).join("\n") + "\n";
      liveLog.value = jobLog.value;
    }
    lastLogId = Math.max(0, ...(existing.logs || []).map((item: Row) => Number(item.id || 0)));
  } catch { /* existing logs are optional */ }
  const source = new EventSource(`/api/jobs/${id}/events?after=${lastLogId}`);
  eventSource.value = source;
  source.onmessage = (event) => {
    const item = JSON.parse(event.data);
    if (item.line === "heartbeat") return;
    const line = `[${item.stream}] ${item.line}\n`;
    jobLog.value += line;
    liveLog.value += line;
  };
  source.onerror = () => {
    source.close();
    window.setTimeout(() => loadKeys(["jobs", "health", "diagnostics", "attention"]), 700);
  };
}

async function runAsk() {
  const question = askQuestion.value.trim();
  if (!question) return notify("Enter a question first");
  askLoading.value = true;
  statusMessage.value = "[STATUS] Resolving retrieval or registered command intent...";
  window.clearTimeout(statusTimer);
  try {
    const result = await api("/api/ask", {
      method: "POST",
      body: JSON.stringify({ question, limit: 120, session: askSession.value }),
    });
    askResult.value = result;
    askSession.value = result.session || askSession.value;
    askPreview.value = null;
    askTranscript.value.push({ question, answer: result.answer || result.error || "No answer was available.", intent: result.intent });
    askTranscript.value = askTranscript.value.slice(-8);
    notify(result?.ok === false ? "No workflow matched" : result?.command_plan ? "Command plan ready" : "Answer ready");
  } catch (error: any) {
    notify(error.message || String(error));
  } finally {
    askLoading.value = false;
  }
}

function askSuggestion(value: string) {
  askQuestion.value = value;
  runAsk();
}

function resetAsk() {
  askSession.value = { history: [] };
  askTranscript.value = [];
  askResult.value = null;
  askPreview.value = null;
  notify("Ask context cleared");
}

async function previewAskPlan() {
  const plan = askPlan.value;
  if (!plan) return notify("No command plan to preview");
  try {
    askPreview.value = await api("/api/preview", { method: "POST", body: JSON.stringify({ action: plan.action, args: plan.args || {} }) });
    notify(askPreview.value?.missing_args?.length ? "Plan still needs input" : "Preview refreshed");
  } catch (error: any) {
    notify(error.message || String(error));
  }
}

async function runAskPlan() {
  const plan = askPlan.value;
  if (!plan) return notify("No command plan to run");
  if (plan.missing_args?.length) return notify(`Provide ${plan.missing_args.join(", ")}`);
  if (plan.run_supported === false || ["config", "danger"].includes(plan.risk_level)) {
    await previewAskPlan();
    return notify(plan.reason || "This plan is preview-only");
  }
  if (plan.requires_confirmation && !window.confirm(`Run ${plan.label}?\n\n${plan.command}\n\nSafety: ${plan.safety_class}`)) return;
  await startJob(plan.action, plan.args || {});
}

onMounted(async () => {
  await loadKeys([...lightKeys, ...heavyKeys]);
  if (!commandAction.value && commands.value.length) commandAction.value = commands.value[0].id;
  timer = window.setInterval(() => loadKeys(lightKeys), 9000);
});

onBeforeUnmount(() => {
  window.clearInterval(timer);
  window.clearTimeout(statusTimer);
  eventSource.value?.close();
});
</script>

<template>
  <div ref="shellRef" class="page netops-page" @pointermove="handlePointerMove" @pointerleave="resetPointer">
    <header class="navbar netops-navbar">
      <div class="container-xl nav-wrap">
        <button class="navbar-brand netops-brand" @click="view = 'overview'">
          <span class="brand-mark">N</span>
          <span>NetOps</span>
        </button>
        <nav class="nav-tabs-lite" aria-label="NetOps views">
          <button v-for="item in navItems" :key="item.id" class="nav-link" :class="{ active: view === item.id }" @click="view = item.id">
            <component :is="item.icon" :size="17" stroke-width="1.8" />
            <span>{{ item.label }}</span>
          </button>
        </nav>
        <div class="nav-actions">
          <span class="nav-status">{{ statusMessage }}</span>
          <span class="status-pill" :class="badgeClass(healthLabel)">{{ healthLabel }}</span>
          <button class="btn btn-outline-secondary btn-sm" @click="refreshCurrentView">
            <IconRefresh :size="16" stroke-width="1.8" />
            Refresh
          </button>
        </div>
      </div>
    </header>

    <main class="page-body">
      <div class="container-xl quiet-container">
        <div v-if="webuiWarning" class="api-banner">
          <strong>Data state</strong>
          <span>{{ webuiWarning }}</span>
          <button class="text-button" @click="refreshAll">Reload all</button>
        </div>

        <Transition name="quiet-fade" mode="out-in">
          <section v-if="view === 'overview'" key="overview" class="view-space">
            <div class="compact-header">
              <div>
                <h1 class="page-title">Overview</h1>
                <p class="page-kicker">Health, activity, and the next useful operation.</p>
              </div>
            </div>

            <div class="stat-strip">
              <div v-for="stat in overviewStats" :key="stat.label" class="stat-cell">
                <span>{{ stat.label }}</span>
                <strong>{{ stat.value }}</strong>
                <small>{{ stat.hint }}</small>
              </div>
            </div>

            <div class="section-grid two-col even">
              <section class="rule-section">
                <div class="section-title-row">
                  <h2>Signals</h2>
                  <button class="text-button" @click="view = 'ops'">Operations</button>
                </div>
                <div class="rule-list">
                  <div v-for="item in attentionItems.slice(0, 6)" :key="`${item.kind}-${item.title}-${item.text}`" class="rule-item">
                    <div>
                      <strong>{{ item.title }}</strong>
                      <span>{{ item.text }}</span>
                    </div>
                    <span class="status-pill" :class="badgeClass(item.level)">{{ item.kind }}</span>
                  </div>
                  <div v-if="!attentionItems.length" class="empty-line">Nothing unusual in the current cache.</div>
                </div>
              </section>

              <section class="rule-section">
                <div class="section-title-row">
                  <h2>Quick actions</h2>
                  <span class="text-secondary small">safe jobs</span>
                </div>
                <div class="quick-grid">
                  <button class="btn btn-light" @click="startJob('health-check')">Fast health</button>
                  <button class="btn btn-light" @click="startJob('workflow-refresh-inventory')">Refresh inventory</button>
                  <button class="btn btn-light" @click="startJob('topology-scan')">Topology scan</button>
                  <button class="btn btn-light" @click="view = 'diagnostics'">Diagnostics</button>
                </div>
              </section>
            </div>

            <div class="section-grid two-col even">
              <section class="rule-section">
                <div class="section-title-row"><h2>Recent jobs</h2><button class="text-button" @click="view = 'jobs'">Open jobs</button></div>
                <div class="rule-list">
                  <div v-for="job in recentJobs" :key="job.id" class="rule-item">
                    <div><strong>{{ job.action }}</strong><span>{{ job.command }}</span></div>
                    <span class="status-pill" :class="badgeClass(job.status)">{{ job.status }}</span>
                  </div>
                  <div v-if="!recentJobs.length" class="empty-line">No jobs recorded.</div>
                </div>
              </section>
              <section class="rule-section">
                <div class="section-title-row"><h2>Diagnostics</h2><button class="text-button" @click="view = 'diagnostics'">Run check</button></div>
                <div class="diag-list">
                  <div class="diag-line"><span>Latency</span><strong>{{ diagnosticSummary.latest_probe?.avg_ms || 'none' }}</strong><small>{{ diagnosticSummary.latest_probe?.target || 'no probe' }}</small></div>
                  <div class="diag-line"><span>Speed</span><strong>{{ diagnosticSummary.latest_speed?.download_mbps ? `${Number(diagnosticSummary.latest_speed.download_mbps).toFixed(1)} down` : 'none' }}</strong><small>{{ diagnosticSummary.latest_speed?.upload_mbps ? `${Number(diagnosticSummary.latest_speed.upload_mbps).toFixed(1)} up` : 'no speed test' }}</small></div>
                  <div class="diag-line"><span>Filtering</span><strong>{{ diagnosticSummary.latest_filtering?.result || 'none' }}</strong><small>{{ diagnosticSummary.latest_filtering?.target || 'no check' }}</small></div>
                </div>
              </section>
            </div>
          </section>

          <section v-else-if="view === 'inventory'" key="inventory" class="view-space">
            <div class="compact-header">
              <div><h1 class="page-title">Inventory</h1><p class="page-kicker">Find devices and APs quickly, inspect history, then launch safe actions.</p></div>
              <div class="segmented-control">
                <button :class="{ active: inventoryKind === 'devices' }" @click="inventoryKind = 'devices'; selected = null">Devices</button>
                <button :class="{ active: inventoryKind === 'aps' }" @click="inventoryKind = 'aps'; selected = null">APs</button>
              </div>
            </div>
            <div class="inventory-workspace">
            <section class="rule-section inventory-main">
              <div class="filter-line inventory-filter">
                <label class="field-group search-control"><span class="field-label">Search inventory</span><span class="input-icon"><span class="input-icon-addon"><IconSearch :size="16" stroke-width="1.8" /></span><input v-model="search" class="form-control" placeholder="IP, hostname, platform, switch" /></span></label>
                <div class="choice-row status-choices">
                  <button class="choice-chip" :class="{ active: statusFilter === '' }" @click="statusFilter = ''">All</button>
                  <button class="choice-chip" :class="{ active: statusFilter === 'ONLINE' }" @click="statusFilter = 'ONLINE'">Online</button>
                  <button class="choice-chip" :class="{ active: statusFilter === 'OFFLINE' }" @click="statusFilter = 'OFFLINE'">Offline</button>
                </div>
              </div>
              <div class="table-responsive table-zone">
                <table class="table table-vcenter quiet-table">
                  <thead><tr><th v-for="[label] in inventoryColumns" :key="label">{{ label }}</th></tr></thead>
                  <tbody>
                    <tr v-for="row in filteredRows" :key="`${inventoryKind}-${row.ip || row.name}`" :class="{ selected: selected === row }" @click="selectRow(row)">
                      <td v-for="[label, key] in inventoryColumns" :key="label"><span v-if="key === 'status'" class="status-pill" :class="badgeClass(row[key])">{{ row[key] || 'unknown' }}</span><span v-else>{{ cellValue(row, key) }}</span></td>
                    </tr>
                    <tr v-if="!filteredRows.length"><td :colspan="inventoryColumns.length" class="text-secondary">No matching records.</td></tr>
                  </tbody>
                </table>
              </div>
            </section>
            <aside v-if="selected" class="detail-drawer">
              <div class="section-title-row"><h2>{{ selected.hostname || selected.name || selected.ip }}</h2><button class="text-button" @click="selected = null">Close</button></div>
              <div v-if="selectedLoading" class="empty-line">Loading details...</div>
              <div class="selected-grid"><div v-for="[key, value] in fieldList(selected)" :key="key"><span>{{ String(key).replaceAll('_', ' ') }}</span><strong>{{ isTimestampKey(key) ? fmtTime(value) : value }}</strong></div></div>
              <div class="inline-actions detail-actions">
                <button class="btn btn-light btn-sm" @click="startJob('diagnose-latency', { target: selected.ip, count: '5' })">Probe</button>
                <button class="btn btn-light btn-sm" @click="useSelectedForMemory(inventoryKind === 'aps' ? 'device' : 'switch')">Memory</button>
                <button v-if="inventoryKind === 'devices'" class="btn btn-light btn-sm" @click="backupTarget = selected.ip; view = 'ops'">Backup</button>
              </div>
              <section class="drawer-subsection"><div class="section-title-row"><h3>History</h3><span class="text-secondary small">Newest first</span></div><div class="rule-list dense-list"><div v-for="event in (selectedDetail?.history || []).slice(0, 6)" :key="event.id" class="rule-item"><div><strong>{{ event.event_type }} {{ event.field_name || '' }}</strong><span>{{ event.previous_value || 'none' }} -> {{ event.current_value || 'current' }}</span></div><small>Recorded {{ fmtTime(event.created_at) }}</small></div><div v-if="!(selectedDetail?.history || []).length" class="empty-line">No history recorded.</div></div></section>
            </aside>
            </div>
          </section>

          <section v-else-if="view === 'memory'" key="memory" class="view-space">
            <div class="compact-header"><div><h1 class="page-title">Memory</h1><p class="page-kicker">Relationship history for switches, ports, IPs, MACs, and AP movement.</p></div><button class="btn btn-light" @click="startJob('memory-refresh')"><IconRefresh :size="16" />Refresh memory</button></div>
            <section class="rule-section">
              <div class="memory-query-grid">
                <label class="field-group"><span class="field-label">Mode</span><select v-model="memoryMode" class="form-select"><option value="switch">Switch</option><option value="device">Device</option><option value="ip">IP</option><option value="mac">MAC</option><option value="port">Port</option><option value="timeline">Timeline</option><option value="explain">Sources</option></select></label>
                <label class="field-group"><span class="field-label">Target</span><input v-model="memoryTarget" class="form-control" placeholder="SQ10, IP, MAC, hostname" @keyup.enter="loadMemory" /></label>
                <label v-if="memoryMode === 'port'" class="field-group"><span class="field-label">Port</span><input v-model="memoryPort" class="form-control" placeholder="Gi1/0/7" @keyup.enter="loadMemory" /></label>
                <div class="inline-actions end-actions"><button class="btn btn-primary" @click="loadMemory">Load</button><button class="btn btn-light" @click="previewCommand(memoryMode === 'port' ? 'memory-port' : memoryMode === 'ip' ? 'memory-ip' : memoryMode === 'mac' ? 'memory-mac' : 'memory-switch', { target: memoryTarget, port: memoryPort })">Preview</button></div>
              </div>
            </section>
            <div v-if="memoryData" class="stat-strip"><div class="stat-cell"><span>Mode</span><strong>{{ memoryMode }}</strong><small>{{ memoryData.target || memoryTarget }}</small></div><div class="stat-cell"><span>Current</span><strong>{{ memoryRows.length }}</strong><small>relationships</small></div><div class="stat-cell"><span>Neighbors</span><strong>{{ memoryNeighbors.length }}</strong><small>topology</small></div><div class="stat-cell"><span>Events</span><strong>{{ memoryTimeline.length }}</strong><small>Latest {{ fmtTime(memoryLatestAt) }}</small></div></div>
            <div class="section-grid two-col even">
              <section class="rule-section"><div class="section-title-row"><h2>Current relationships</h2><span class="text-secondary small">Newest recorded first</span></div><div class="table-responsive compact-table-zone"><table class="table quiet-table"><thead><tr><th>Type</th><th>Subject</th><th>Object</th><th>Source</th><th>Status</th><th>First seen</th><th>Last recorded</th></tr></thead><tbody><tr v-for="row in memoryRows.slice(0, 80)" :key="row.rel_key || row.ip || row.id"><td>{{ row.rel_type || row.switch_port || row.kind }}</td><td>{{ row.subject_id || row.name || row.ip }}</td><td>{{ row.object_id || row.switch_name }}</td><td>{{ row.source || row.platform }}</td><td><span class="status-pill" :class="badgeClass(row.status)">{{ row.status || 'known' }}</span></td><td>{{ fmtTime(row.first_seen) }}</td><td>{{ fmtTime(row.last_seen || row.updated_at) }}</td></tr><tr v-if="!memoryRows.length"><td colspan="7" class="text-secondary">No current relationship rows loaded.</td></tr></tbody></table></div></section>
              <section class="rule-section"><div class="section-title-row"><h2>Timeline</h2><span class="text-secondary small">{{ memoryTimeline.length }} events - newest first</span></div><div class="rule-list dense-list"><div v-for="event in memoryTimeline.slice(0, 14)" :key="event.id" class="rule-item"><div><strong>{{ event.event_type }} {{ event.rel_type || '' }}</strong><span>{{ event.subject_id }} -> {{ event.object_id || event.detail }}</span></div><small>Recorded {{ fmtTime(event.created_at) }}</small></div><div v-if="!memoryTimeline.length" class="empty-line">No timeline rows loaded.</div></div></section>
            </div>
          </section>

          <section v-else-if="view === 'topology'" key="topology" class="view-space">
            <div class="compact-header"><div><h1 class="page-title">Topology</h1><p class="page-kicker">Neighbor graph, raw links, and change timeline.</p></div><button class="btn btn-light" @click="startJob('topology-scan')">Refresh topology</button></div>
            <section class="rule-section topology-section">
              <div class="topology-canvas">
                <div v-if="!graphNodes.length" class="topology-empty"><strong>No topology cached</strong><span>Run topology scan to populate the graph.</span></div>
              <svg class="topology-graph" viewBox="0 0 800 380" role="img" aria-label="Topology graph">
                <line v-for="edge in graphEdges" :key="edge.id" :x1="edge.sourceNode.x" :y1="edge.sourceNode.y" :x2="edge.targetNode.x" :y2="edge.targetNode.y" class="graph-edge" />
                <g v-for="node in graphNodes" :key="node.id" class="graph-node"><circle :cx="node.x" :cy="node.y" r="18" /><text :x="node.x" :y="node.y + 34" text-anchor="middle">{{ String(node.label).slice(0, 18) }}</text></g>
              </svg>
              </div>
            </section>
            <div class="section-grid two-col even"><section class="rule-section"><div class="section-title-row"><h2>Neighbors</h2><span class="text-secondary small">{{ graph.raw_edges?.length || 0 }} links</span></div><div class="rule-list dense-list"><div v-for="edge in (graph.raw_edges || []).slice(0, 12)" :key="`${edge.local_ip}-${edge.local_port}-${edge.remote_name}`" class="rule-item"><div><strong>{{ edge.local_name || edge.local_ip }} {{ edge.local_port }}</strong><span>{{ edge.remote_name }} {{ edge.remote_port }} {{ edge.remote_ip }}</span></div></div><div v-if="!(graph.raw_edges || []).length" class="empty-line">No topology links cached.</div></div></section><section class="rule-section"><div class="section-title-row"><h2>Changes</h2><span class="text-secondary small">{{ state.topologyChanges.length }} events</span></div><div class="rule-list dense-list"><div v-for="row in state.topologyChanges.slice(0, 12)" :key="row.id" class="rule-item"><div><strong>{{ row.event_type }}</strong><span>{{ row.local_ip }} {{ row.local_port }} -> {{ row.remote_name }}</span></div><small>{{ fmtTime(row.created_at) }}</small></div><div v-if="!state.topologyChanges.length" class="empty-line">No topology changes recorded.</div></div></section></div>
          </section>

          <section v-else-if="view === 'diagnostics'" key="diagnostics" class="view-space">
            <div class="compact-header"><div><h1 class="page-title">Diagnostics</h1><p class="page-kicker">Run focused checks and watch job output.</p></div><div class="inline-actions"><span class="status-pill text-bg-secondary">{{ diagnosticSummary.counts?.diagnostic_runs || 0 }} records</span><button class="btn btn-light btn-sm icon-text-btn" @click="runDoctor"><IconActivity :size="15" />Readiness</button></div></div>
            <div class="section-grid four-col run-grid">
              <section class="rule-section action-section"><h2>Latency</h2><div class="choice-row compact"><button class="choice-chip" :class="{ active: probeOrigin === 'host' }" @click="probeOrigin = 'host'">Host</button><button class="choice-chip" :class="{ active: probeOrigin === 'core' }" @click="probeOrigin = 'core'">Core</button></div><input v-model="probeTarget" class="form-control" placeholder="Target" /><button class="btn btn-primary w-100 icon-text-btn" @click="runProbe"><IconPlayerPlay :size="15" />Run probe</button></section>
              <section class="rule-section action-section"><h2>Internet speed</h2><div class="choice-row compact"><button v-for="profile in speedProfileOptions" :key="profile" class="choice-chip" :class="{ active: speedProfile === profile }" @click="setSpeedProfile(profile)">{{ profile }}</button></div><div class="choice-row compact"><button v-for="run in speedRunOptions" :key="run" class="choice-chip" :class="{ active: speedRuns === run }" @click="speedRuns = run">{{ run }}</button></div><button class="btn btn-primary w-100 icon-text-btn" @click="runSpeed"><IconPlayerPlay :size="15" />Run speed</button></section>
              <section class="rule-section action-section"><h2>Core throughput</h2><input v-model="throughputServer" class="form-control" :placeholder="state.options?.core_iperf_server || 'iperf3 server'" /><div class="choice-row compact"><button v-for="mode in ['both', 'upload', 'download']" :key="mode" class="choice-chip" :class="{ active: throughputDirection === mode }" @click="throughputDirection = mode">{{ mode }}</button></div><div class="input-pair"><input v-model="throughputPort" type="number" class="form-control" placeholder="Port" /><input v-model="throughputSeconds" type="number" class="form-control" placeholder="Seconds" /></div><button class="btn btn-primary w-100 icon-text-btn" @click="runThroughput"><IconPlayerPlay :size="15" />Run throughput</button></section>
              <section class="rule-section action-section"><h2>Filtering</h2><input v-model="checkTarget" class="form-control" placeholder="Domain" /><div class="choice-row compact"><button v-for="domain in domainOptions" :key="domain.value" class="choice-chip" @click="checkTarget = domain.value">{{ domain.label }}</button></div><button class="btn btn-primary w-100 icon-text-btn" @click="runFiltering"><IconPlayerPlay :size="15" />Run filtering</button></section>
              <section class="rule-section action-section"><h2>Port health</h2><input v-model="portHealthTarget" class="form-control" placeholder="Switch" /><input v-model="portHealthInterface" class="form-control" placeholder="Interface" /><div class="input-pair"><input v-model="portHealthSample" type="number" class="form-control" placeholder="Sample seconds" /><input v-model="portExpectedSpeed" type="number" class="form-control" placeholder="Expected Mbps" /></div><button class="btn btn-primary w-100 icon-text-btn" @click="runPortHealth"><IconPlayerPlay :size="15" />Sample port</button></section>
              <section class="rule-section action-section"><h2>Copper cable</h2><input v-model="cableTarget" class="form-control" placeholder="Switch" /><input v-model="cableInterface" class="form-control" placeholder="Interface" /><div class="inline-actions"><button class="btn btn-primary icon-text-btn" @click="runCableStatus"><IconEye :size="15" />Read status</button><button class="btn btn-light icon-text-btn" @click="previewCableTest"><IconEye :size="15" />Preview TDR</button></div></section>
              <section class="rule-section action-section"><h2>Legacy rates</h2><input v-model="interfaceTarget" class="form-control" placeholder="Device" /><input v-model="interfaceName" class="form-control" placeholder="Interface" /><select v-model="interfaceChart" class="form-select"><option value="classic">Classic</option><option value="histogram">Histogram</option></select><button class="btn btn-primary w-100 icon-text-btn" @click="runInterface"><IconPlayerPlay :size="15" />Sample once</button></section>
            </div>
            <section class="rule-section log-section"><div class="section-title-row"><h2>Live output</h2><span class="text-secondary small">{{ activeJob }}</span></div><pre class="log-output">{{ liveLog }}</pre></section>
            <section class="rule-section"><div class="section-title-row"><h2>Diagnostic chronology</h2><span class="text-secondary small">newest first</span></div><div class="rule-list dense-list"><div v-for="row in (state.diagnostics?.diagnostic_runs || []).slice(0, 16)" :key="row.id" class="rule-item"><div><strong>{{ row.kind }} · {{ row.target || 'local' }}</strong><span>{{ row.summary }}</span></div><div><span class="status-pill" :class="badgeClass(row.status)">{{ row.status }}</span><small>{{ row.recorded_at_iso || fmtTime(row.created_at) }}</small></div></div><div v-if="!(state.diagnostics?.diagnostic_runs || []).length" class="empty-line">No diagnostic records.</div></div></section>
          </section>

          <section v-else-if="view === 'ops'" key="ops" class="view-space">
            <div class="compact-header"><div><h1 class="page-title">Operations</h1><p class="page-kicker">Workflows, backups, command previews, and automation planning.</p></div><button class="btn btn-light" @click="startJob('health-check')">Fast health</button></div>
            <section class="rule-section"><div class="section-title-row"><h2>Workflows</h2><span class="text-secondary small">safe execution</span></div><div class="workflow-list"><div v-for="workflow in workflowRows" :key="workflow.id" class="workflow-item"><div><strong>{{ workflow.label }}</strong><span>{{ workflow.description }}</span></div><button class="btn btn-light btn-sm" @click="startJob(workflow.action)">Run</button></div></div></section>
            <div class="section-grid two-col even"><section class="rule-section"><div class="section-title-row"><h2>Backup</h2><span class="text-secondary small">online and changed-only</span></div><input v-model="backupTarget" class="form-control" placeholder="Target" /><div class="inline-actions"><button class="btn btn-primary" @click="runBackup">Start backup</button><button class="btn btn-light" @click="previewCommand('backup-run', { target: backupTarget })">Preview</button></div></section><section class="rule-section"><div class="section-title-row"><h2>Automation V2</h2><span class="status-pill text-bg-secondary">planned</span></div><div class="rule-list dense-list"><div v-for="schedule in state.automation.schedules" :key="schedule.id" class="rule-item"><div><strong>{{ schedule.label }}</strong><span>{{ schedule.cadence }} - {{ schedule.action }}</span></div><span class="status-pill text-bg-secondary">{{ schedule.enabled ? 'on' : 'off' }}</span></div></div></section></div>
            <section class="rule-section"><div class="section-title-row"><h2>Command palette</h2><span class="text-secondary small">{{ visibleCommands.length }} commands</span></div><div class="command-layout"><label class="field-group"><span class="field-label">Find command</span><input v-model="commandSearch" class="form-control" placeholder="Domain, command, description" /></label><label class="field-group"><span class="field-label">Command</span><select v-model="commandAction" class="form-select"><option v-for="cmd in visibleCommands" :key="cmd.id" :value="cmd.id">{{ cmd.label }} - {{ cmd.domain }}</option></select></label><template v-for="field in activeCommand?.arg_schema || []" :key="field.name"><label class="field-group"><span class="field-label">{{ field.label || field.name }}</span><select v-if="field.type === 'select'" v-model="commandArgs[field.name]" class="form-select"><option value="">Default</option><option v-for="option in field.options || []" :key="option" :value="option">{{ option }}</option></select><label v-else-if="field.type === 'boolean'" class="check-line"><input v-model="commandArgs[field.name]" type="checkbox" true-value="true" false-value="" /> <span>Enable</span></label><input v-else v-model="commandArgs[field.name]" :type="field.type === 'number' ? 'number' : 'text'" class="form-control" :placeholder="field.placeholder || field.default || field.name" /></label></template><div class="inline-actions end-actions"><button class="btn btn-light" @click="previewCommand()">Preview</button><button class="btn btn-primary" :disabled="activeCommand?.run_supported === false || activeCommand?.risk_level === 'danger'" @click="runCommand">Run</button></div></div><p v-if="activeCommand" class="microcopy">{{ activeCommand.description }} <span class="status-pill" :class="badgeClass(activeCommand.risk_level)">{{ activeCommand.risk_level }}</span></p></section>
          </section>

          <section v-else-if="view === 'jobs'" key="jobs" class="view-space">
            <div class="compact-header"><div><h1 class="page-title">Jobs</h1><p class="page-kicker">Queue state, live output, cancellation, and safe retries.</p></div><button class="btn btn-light" @click="startJob('inventory-import-flat')"><IconDatabase :size="16" />Sync SQLite</button></div>
            <div class="choice-row job-filter"><button class="choice-chip" :class="{ active: jobFilter === 'all' }" @click="jobFilter = 'all'">All</button><button class="choice-chip" :class="{ active: jobFilter === 'active' }" @click="jobFilter = 'active'">Active</button><button class="choice-chip" :class="{ active: jobFilter === 'completed' }" @click="jobFilter = 'completed'">Completed</button><button class="choice-chip" :class="{ active: jobFilter === 'failed' }" @click="jobFilter = 'failed'">Failed</button></div>
            <div class="section-grid two-col even"><section class="rule-section jobs-section"><div class="rule-list jobs-list"><div v-for="job in visibleJobs" :key="job.id" class="job-row"><button class="job-pick" @click="watchJob(job.id)"><strong>{{ job.action }}</strong><small>{{ job.command }}</small></button><span class="job-actions"><span class="status-pill" :class="badgeClass(job.status)">{{ job.status }}</span><button v-if="job.status === 'running'" class="btn btn-sm btn-outline-danger" @click="cancelJob(job.id)">Cancel</button><button v-else-if="job.read_only && canRetry(job)" class="btn btn-sm btn-light" @click="retryJob(job)">Retry</button><button v-else-if="job.read_only" class="btn btn-sm btn-light" @click="reviewJobCommand(job)">Review</button></span></div><div v-if="!visibleJobs.length" class="empty-line">No jobs match this filter.</div></div></section><section class="rule-section log-section"><div class="section-title-row"><h2>Output</h2><span class="text-secondary small">{{ activeJob }}</span></div><pre class="log-output">{{ jobLog }}</pre></section></div>
          </section>

          <section v-else key="ask" class="view-space ask-view">
            <div class="compact-header">
              <div><h1 class="page-title">Ask</h1><p class="page-kicker">Current-state retrieval and registry-backed command planning.</p></div>
              <div class="inline-actions"><span class="status-pill" :class="badgeClass(askStateLabel)">{{ askStateLabel }}</span><button class="btn btn-light btn-sm icon-text-btn" title="Clear Ask context" @click="resetAsk"><IconTrash :size="15" />Clear</button></div>
            </div>
            <section class="rule-section ask-query ask-composer">
              <label class="field-group">
                <span class="field-label">Question or operation</span>
                <textarea v-model="askQuestion" class="form-control ask-textarea" placeholder="Run a fast health check for SQ34" @keydown.ctrl.enter.prevent="runAsk"></textarea>
              </label>
              <div class="ask-actions"><button class="btn btn-primary icon-text-btn" :disabled="askLoading" @click="runAsk"><IconSearch :size="16" />{{ askLoading ? 'Resolving...' : 'Ask' }}</button></div>
            </section>
            <section v-if="askResult" class="rule-section ask-thread">
              <template v-for="(message, index) in askTranscript" :key="`${index}-${message.question}`">
                <div class="ask-message question"><span>You</span><p>{{ message.question }}</p></div>
                <div class="ask-message assistant"><span>NetOps</span><p class="ask-answer">{{ message.answer }}</p></div>
              </template>
              <div v-if="askRows.length" class="ask-result-table table-responsive compact-table-zone">
                <table class="table quiet-table">
                  <thead><tr><th v-for="column in askColumns" :key="column">{{ columnLabel(column) }}</th></tr></thead>
                  <tbody><tr v-for="(row, index) in askRows.slice(0, 30)" :key="row.canonical_id || row.id || row.ip || row.name || index"><td v-for="column in askColumns" :key="column"><span v-if="column === 'status' || column === 'level'" class="status-pill" :class="badgeClass(row[column])">{{ row[column] || 'known' }}</span><template v-else>{{ cellValue(row, column) || '-' }}</template></td></tr></tbody>
                </table>
              </div>
              <div v-if="askResult.suggestions?.filter(Boolean).length" class="ask-suggestions"><button v-for="suggestion in askResult.suggestions.filter(Boolean).slice(0, 4)" :key="suggestion" class="choice-chip" @click="askSuggestion(suggestion)">{{ suggestion }}</button></div>
            </section>
            <section v-if="askPlan" class="rule-section ask-plan">
              <div class="section-title-row"><h2>{{ askPlan.label }}</h2><div class="inline-actions"><span class="status-pill" :class="badgeClass(askPlan.status)">{{ askPlan.status?.replaceAll('_', ' ') }}</span><span class="status-pill" :class="badgeClass(askPlan.risk_level)">{{ askPlan.safety_class }}</span></div></div>
              <div class="ask-plan-grid"><div><span>Action</span><strong>{{ askPlan.action }}</strong></div><div><span>State effects</span><strong>{{ askPlan.state_effects?.join(', ') || 'none' }}</strong></div><div><span>Confirmation</span><strong>{{ askPlan.requires_confirmation ? 'required' : 'not required' }}</strong></div><div><span>Output</span><strong>{{ askPlan.output_type }}</strong></div></div>
              <pre class="ask-command">{{ askPreview?.command || askPlan.command }}</pre>
              <p v-if="askPlan.missing_args?.length" class="validation-line">Missing: {{ askPlan.missing_args.join(', ') }}</p>
              <p v-if="askPlan.reason" class="microcopy">{{ askPlan.reason }}</p>
              <div class="ask-plan-actions"><button class="btn btn-light icon-text-btn" @click="previewAskPlan"><IconEye :size="16" />Refresh preview</button><button v-if="askPlan.run_supported !== false && !['config', 'danger'].includes(askPlan.risk_level)" class="btn btn-primary icon-text-btn" :disabled="askPlan.missing_args?.length" @click="runAskPlan"><IconPlayerPlay :size="16" />Run plan</button></div>
            </section>
            <section v-if="askResult && askWorkflow.length" class="rule-section ask-workflow">
              <div class="section-title-row"><h2>Workflow used</h2><span class="text-secondary small">{{ askResult.intent }}</span></div>
              <div class="ask-step-list"><div v-for="row in askWorkflow" :key="row.step" class="ask-step"><strong>{{ row.step }}. {{ row.source }}</strong><span>{{ row.operation }}</span></div></div>
              <p class="microcopy">Retrieval uses current SQLite memory. Operations are constrained to the structured command registry and remain plans until explicitly run.</p>
            </section>
          </section>
        </Transition>

        <div class="footer-note text-secondary"><span>DB: {{ state.health?.paths?.db || 'loading' }}</span><span>Loaded {{ Object.keys(lastLoaded).length }} resources</span></div>
      </div>
    </main>

  </div>
</template>
