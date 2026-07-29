from __future__ import annotations

# ---------------------------------------------------------------------------
# Operator console.
#
# The previous dashboard was a form per endpoint — useful for poking the API,
# useless for the job phase 1 actually requires: looking at what the engine
# decided and reviewing every hard_deny by hand before enforcement is switched
# on. This is that tool.
#
# Server-rendered, no build step, no external assets. It ships in the same
# container as the engine, which keeps the audit trail behind exactly one
# network boundary instead of two.
#
# SECURITY: this page exposes every decision and every action an agent proposed.
# Do not publish port 8080. Set AETHERYA_CONSOLE_API_KEY to require a key.
# ---------------------------------------------------------------------------


def console_html() -> str:
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ÆTHERYA — Operator Console</title>
<style>
  :root{
    --bg:#0f1720; --panel:#16212c; --panel-2:#1c2934; --line:#263644;
    --ink:#e6eef4; --muted:#8ba0b0; --accent:#2bb896; --accent-2:#3d9fd6;
    --allow:#2bb896; --log:#5b8fb9; --escalate:#d99a2b; --deny:#d9613d; --hard:#d93d5c;
  }
  @media (prefers-color-scheme: light){
    :root{ --bg:#f4f7f9; --panel:#fff; --panel-2:#f8fafc; --line:#dde5eb;
           --ink:#16242e; --muted:#5c7182; }
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
  a{color:var(--accent-2)}
  .wrap{max-width:1220px;margin:0 auto;padding:20px 16px 48px}
  header.top{display:flex;flex-wrap:wrap;gap:12px;align-items:center;
             justify-content:space-between;margin-bottom:16px}
  h1{font-size:1.15rem;margin:0;letter-spacing:.3px}
  h1 small{color:var(--muted);font-weight:400;font-size:.8rem;margin-left:8px}
  .status{display:flex;flex-wrap:wrap;gap:8px}
  .chip{border:1px solid var(--line);background:var(--panel);border-radius:999px;
        padding:4px 11px;font-size:.78rem;display:flex;gap:6px;align-items:center}
  .dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
  .dot.ok{background:var(--allow)} .dot.bad{background:var(--hard)}
  .dot.warn{background:var(--escalate)}
  .grid{display:grid;gap:14px;grid-template-columns:1fr}
  @media(min-width:980px){ .grid.split{grid-template-columns:1.55fr 1fr} }
  .card{background:var(--panel);border:1px solid var(--line);border-radius:12px;
        padding:14px;overflow:hidden}
  .card h2{margin:0 0 4px;font-size:.95rem}
  .card p.hint{margin:0 0 12px;color:var(--muted);font-size:.82rem}
  .filters{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
  button{font:inherit;cursor:pointer;border-radius:8px;border:1px solid var(--line);
         background:var(--panel-2);color:var(--ink);padding:5px 11px;font-size:.82rem}
  button:hover{border-color:var(--accent)}
  button.on{background:var(--accent);border-color:var(--accent);color:#06231c;font-weight:600}
  .tablewrap{overflow-x:auto}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;color:var(--muted);font-weight:600;padding:6px 8px;
     border-bottom:1px solid var(--line);white-space:nowrap}
  td{padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  tr:last-child td{border-bottom:0}
  .state{font-weight:700;font-size:.74rem;letter-spacing:.4px;white-space:nowrap}
  .s-allow{color:var(--allow)} .s-log_only{color:var(--log)}
  .s-escalate{color:var(--escalate)} .s-deny{color:var(--deny)}
  .s-hard_deny{color:var(--hard)}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.78rem;
        word-break:break-word}
  .muted{color:var(--muted)}
  .review{border:1px solid var(--line);border-left:3px solid var(--hard);
          border-radius:8px;padding:10px 12px;margin-bottom:10px;background:var(--panel-2)}
  .review .meta{display:flex;gap:12px;flex-wrap:wrap;color:var(--muted);
                font-size:.76rem;margin-bottom:6px}
  .crit{display:flex;gap:9px;align-items:flex-start;padding:7px 0;
        border-bottom:1px solid var(--line);font-size:.82rem}
  .crit:last-child{border-bottom:0}
  .mark{font-weight:700;flex:0 0 auto}
  .mark.ok{color:var(--allow)} .mark.no{color:var(--escalate)}
  .verdict{margin-top:12px;padding:10px 12px;border-radius:8px;font-weight:700;
           text-align:center;font-size:.85rem}
  .verdict.no{background:rgba(217,154,43,.14);color:var(--escalate);
              border:1px solid rgba(217,154,43,.4)}
  .verdict.yes{background:rgba(43,184,150,.14);color:var(--allow);
               border:1px solid rgba(43,184,150,.4)}
  .review.done{border-left-color:var(--muted);opacity:.72}
  .review.hold{border-left-color:var(--escalate)}
  .actions{display:flex;gap:8px;margin-top:9px;flex-wrap:wrap}
  .actions button{border:1px solid var(--line);background:var(--panel);
                  color:var(--fg);border-radius:6px;padding:6px 11px;cursor:pointer;
                  font-size:.76rem;font-family:inherit}
  .actions button.tp:hover{border-color:var(--allow);color:var(--allow)}
  .actions button.fp:hover{border-color:var(--hard);color:var(--hard)}
  .rv{margin-top:9px;font-size:.76rem;font-weight:600}
  .rv.tp{color:var(--allow)} .rv.fp{color:var(--hard)}
  .rv .note{font-weight:400;margin-top:3px}
  .empty{color:var(--muted);text-align:center;padding:26px 10px;font-size:.85rem}
  .unlock{margin-top:12px;border:1px solid var(--line);background:var(--panel);
          color:var(--fg);border-radius:6px;padding:7px 14px;cursor:pointer;
          font-size:.78rem;font-family:inherit}
  .unlock:hover{border-color:var(--allow);color:var(--allow)}
  .bar{display:flex;height:7px;border-radius:4px;overflow:hidden;margin:10px 0 6px;
       background:var(--panel-2)}
  .bar i{display:block}
  .legend{display:flex;flex-wrap:wrap;gap:10px;font-size:.76rem;color:var(--muted)}
  .legend b{color:var(--ink)}
  footer{margin-top:18px;color:var(--muted);font-size:.76rem;text-align:center}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1>ÆTHERYA <small>operator console</small></h1>
    <div class="status" id="status"><span class="chip"><span class="dot"></span>loading…</span></div>
  </header>

  <div class="grid split">
    <section class="card">
      <h2>Decision feed</h2>
      <p class="hint">Newest first, straight from the audit trail.</p>
      <div class="filters" id="filters"></div>
      <div class="bar" id="bar"></div>
      <div class="legend" id="legend"></div>
      <div class="tablewrap">
        <table>
          <thead><tr><th>time</th><th>actor</th><th>state</th><th>risk</th>
          <th>action</th><th>reason</th></tr></thead>
          <tbody id="feed"><tr><td colspan="6" class="empty">loading…</td></tr></tbody>
        </table>
      </div>
    </section>

    <section class="card">
      <h2>Phase readiness</h2>
      <p class="hint">Exit criteria for the configured phase.</p>
      <div id="criteria"><div class="empty">loading…</div></div>
      <div id="verdict"></div>
    </section>
  </div>

  <section class="card" id="approvals-card" style="margin-top:14px;display:none">
    <h2>Waiting for approval <span id="approval-count" class="muted"></span></h2>
    <p class="hint">
      Actions held for a human. These are live — an agent is blocked on each one
      until you answer, and each expires on its own if nobody does.
    </p>
    <div id="approvals"></div>
  </section>

  <section class="card" style="margin-top:14px">
    <h2>Hard-deny review <span id="review-count" class="muted"></span></h2>
    <p class="hint">
      Every one of these needs human eyes before enforcement is switched on.
      A false positive here is a detection bug — add the case to the corpus and
      fix the rule rather than loosening the policy.
    </p>
    <div id="review"><div class="empty">loading…</div></div>
  </section>

  <footer>
    Reviews are recorded against the audit trail and are what let
    <code>hard_deny_reviewed</code> pass. Do not expose this port publicly.
  </footer>
</div>

<script>
const STATES = ["all","allow","log_only","escalate","deny","hard_deny"];
const COLOR = {allow:"var(--allow)",log_only:"var(--log)",escalate:"var(--escalate)",
               deny:"var(--deny)",hard_deny:"var(--hard)"};
let active = "all";

const esc = s => String(s ?? "").replace(/[&<>"']/g,
  c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const clip = (s,n) => { s = String(s ?? ""); return s.length > n ? s.slice(0,n)+"…" : s; };
const time = t => { if(!t) return "—"; try { return new Date(t).toLocaleString(); }
                    catch(e){ return t; } };

// One place decides how the key travels. When AETHERYA_CONSOLE_API_KEY is set
// it gates the reads too, so a page that only sent it on writes would render
// empty against a configured deployment — which is the normal deployment.
const KEY = "aetherya.consoleKey";
const consoleKey = () => localStorage.getItem(KEY) || "";

function askForKey(){
  const entered = prompt("Console key (AETHERYA_CONSOLE_API_KEY):");
  if(entered){ localStorage.setItem(KEY, entered); return true; }
  return false;
}

class Unauthorized extends Error {}

// Never prompts. Asking here means every failed load asks again, and with a
// polling refresh behind it a wrong key turns into a dialog every few seconds
// that cannot be escaped. One place decides when to ask: refresh().
async function get(url){
  const r = await fetch(url, {headers:{
    "Accept":"application/json", "X-AETHERYA-Console-Key": consoleKey()
  }});
  if(r.status === 401) throw new Unauthorized();
  return await r.json();
}

function chip(label, value, cls){
  return `<span class="chip"><span class="dot ${cls}"></span>${esc(label)}
          <b>${esc(value)}</b></span>`;
}

async function loadStatus(){
  try {
    const h = await get("/health");
    const bits = [
      chip("service", h.ok ? "up" : "down", h.ok ? "ok" : "bad"),
      chip("degraded", h.degraded ? "yes" : "no", h.degraded ? "warn" : "ok"),
      chip("policy", String(h.effective_fingerprint||"").slice(7,15),
           h.policy_fingerprint_match ? "ok" : "bad"),
      chip("semantic", h.semantic_ready ? "ready" : "off",
           h.semantic_ready ? "ok" : "warn"),
    ];
    if (h.audit_mirror_configured)
      bits.push(chip("mirror", h.audit_mirror_ok ? "ok" : "failing",
                     h.audit_mirror_ok ? "ok" : "bad"));
    document.getElementById("status").innerHTML = bits.join("");
  } catch(e) {
    document.getElementById("status").innerHTML =
      chip("service","unreachable","bad");
  }
}

function renderFilters(){
  document.getElementById("filters").innerHTML = STATES.map(s =>
    `<button data-s="${s}" class="${s===active?"on":""}">${s}</button>`).join("");
  document.querySelectorAll("#filters button").forEach(b =>
    b.onclick = () => { active = b.dataset.s; renderFilters(); loadFeed(); });
}

function renderBar(rows){
  const counts = {};
  rows.forEach(r => counts[r.state] = (counts[r.state]||0)+1);
  const total = rows.length || 1;
  const order = ["allow","log_only","escalate","deny","hard_deny"];
  document.getElementById("bar").innerHTML = order.filter(s=>counts[s])
    .map(s => `<i style="width:${counts[s]/total*100}%;background:${COLOR[s]}"></i>`).join("");
  document.getElementById("legend").innerHTML = order.filter(s=>counts[s])
    .map(s => `<span><b style="color:${COLOR[s]}">${counts[s]}</b> ${s}</span>`).join("");
}

async function loadFeed(){
  const q = active === "all" ? "" : `&state=${encodeURIComponent(active)}`;
  const body = await get(`/v1/decisions?limit=200${q}`);
  const rows = body.decisions || [];
  const tbody = document.getElementById("feed");

  if(!rows.length){
    // An empty state that only says "empty" leaves you guessing whether the
    // service is broken or simply idle. Say which, and how to change it.
    tbody.innerHTML = `<tr><td colspan="6" class="empty">
      No decisions recorded yet — the engine is running and waiting for traffic.<br>
      <span class="mono" style="display:inline-block;margin-top:8px">
      aetherya decide "rm -rf /" --actor robert</span><br>
      <span style="display:inline-block;margin-top:6px">
      or point an agent at the gateway — see docs/gateway-openclaw.md</span>
      </td></tr>`;
    document.getElementById("bar").innerHTML = "";
    document.getElementById("legend").innerHTML = "";
    return;
  }
  renderBar(rows);
  tbody.innerHTML = rows.map(r => `
    <tr>
      <td class="muted mono">${esc(time(r.ts))}</td>
      <td>${esc(r.actor)}${r.escalated?' <span class="muted" title="intent was escalated">↑</span>':""}</td>
      <td class="state s-${esc(r.state)}">${esc(r.state)}</td>
      <td class="mono">${esc(r.risk_score)}</td>
      <td class="mono">${esc(clip(r.action,90))}</td>
      <td class="muted">${esc(clip(r.reason,70))}</td>
    </tr>`).join("");
}

async function loadRollout(){
  const body = await get("/v1/rollout/report");
  const rep = body.report;
  const crit = document.getElementById("criteria");
  const verdict = document.getElementById("verdict");

  if(!rep){
    crit.innerHTML = `<div class="empty">${esc(body.error || "unavailable")}</div>`;
    verdict.innerHTML = "";
    return;
  }
  crit.innerHTML = (rep.criteria||[]).map(c => `
    <div class="crit">
      <span class="mark ${c.passed?"ok":"no"}">${c.passed?"✓":"○"}</span>
      <span><b>${esc(c.name)}</b><br><span class="muted">${esc(c.detail)}</span></span>
    </div>`).join("");

  const ready = rep.ready_to_advance;
  verdict.innerHTML = `<div class="verdict ${ready?"yes":"no"}">
    ${ready?"READY":"NOT READY"} to advance to phase ${esc(rep.next_phase)}</div>
    <div class="legend" style="margin-top:8px">
      <span><b>${esc(rep.window.total_decisions)}</b> decisions</span>
      <span><b>${esc(rep.window.days)}</b> days</span>
      <span><b>${esc(rep.would_block_next_phase)}</b> phase ${esc(rep.next_phase)} would act on</span>
    </div>`;

  const review = document.getElementById("review");
  const events = rep.hard_deny_events || [];
  const pending = events.filter(e => !e.review).length;
  document.getElementById("review-count").textContent =
    events.length ? `${pending} of ${events.length} pending` : "";

  review.innerHTML = events.length ? events.map(e => `
    <div class="review${e.review ? " done" : ""}">
      <div class="meta"><span>${esc(time(e.ts))}</span><span>actor: ${esc(e.actor)}</span>
        <span>risk: ${esc(e.risk_score)}</span></div>
      <div class="mono">${esc(e.action)}</div>
      <div class="muted" style="margin-top:5px">→ ${esc(e.reason)}</div>
      ${e.review ? verdictBadge(e.review) : verdictButtons(e.event_id)}
    </div>`).join("")
    : `<div class="empty">no hard-deny events in the window</div>`;

  review.querySelectorAll("button[data-verdict]").forEach(b => {
    b.onclick = () => submitReview(b.dataset.id, b.dataset.verdict);
  });
}

function verdictBadge(r){
  const ok = r.verdict === "true_positive";
  return `<div class="rv ${ok ? "tp" : "fp"}">
    ${ok ? "✓ confirmed true positive" : "✗ FALSE POSITIVE — blocks the advance"}
    <span class="muted"> · ${esc(r.reviewer)} · ${esc(time(r.ts))}</span>
    ${r.note ? `<div class="muted note">${esc(r.note)}</div>` : ""}
  </div>`;
}

function verdictButtons(id){
  return `<div class="actions">
    <button data-verdict="true_positive" data-id="${esc(id)}" class="tp">
      ✓ Correct — it should have been blocked</button>
    <button data-verdict="false_positive" data-id="${esc(id)}" class="fp">
      ✗ False positive</button>
  </div>`;
}

const REVIEWER = "aetherya.reviewer";
const ADMIN = "aetherya.adminKey";

async function submitReview(eventId, verdict){
  // Worded to be unmistakable next to the key prompt: an operator who has just
  // pasted a key into one dialog will paste it into the next identical one,
  // and that writes the credential into the audit trail. The server refuses it
  // too — this only stops the round trip.
  let reviewer = localStorage.getItem(REVIEWER);
  while(!reviewer){
    reviewer = (prompt("WHO ARE YOU? Your name — not the console key. It is recorded next to this verdict.") || "").trim();
    if(!reviewer) return;
    if(reviewer === consoleKey()){
      alert("That is the console key, not a name. Enter the name to attribute this review to.");
      reviewer = "";
    }
  }
  localStorage.setItem(REVIEWER, reviewer);

  // A false positive is a claim the engine got it wrong. The note is what
  // tells you later which rule to narrow, so it is required, not optional.
  let note = "";
  if(verdict === "false_positive"){
    note = prompt("Why was this a false positive? (required — it is what identifies the rule to fix)") || "";
    if(!note.trim()){ return; }
  }

  const r = await fetch("/v1/reviews", {
    method: "POST",
    headers: {"Content-Type":"application/json", "X-AETHERYA-Console-Key": consoleKey()},
    body: JSON.stringify({event_id: eventId, verdict, reviewer, note})
  });
  const body = await r.json().catch(() => ({}));
  if(!r.ok){
    if(r.status === 401 && askForKey()) return submitReview(eventId, verdict);
    alert(`Could not record the review:

${body.error || r.status}`);
    return;
  }
  loadRollout();
}

// ---------------------------------------------------------------------------
// Approval queue
// ---------------------------------------------------------------------------

async function loadApprovals(){
  const card = document.getElementById("approvals-card");
  const body = await get("/v1/approvals/pending").catch(() => null);
  // The queue is optional. A deployment with it disabled should not show a
  // permanently empty panel implying something is broken.
  if(!body || !body.ok){ card.style.display = "none"; return; }

  const rows = body.pending || [];
  const stats = body.stats || {};
  card.style.display = rows.length || stats.expired ? "block" : "none";
  document.getElementById("approval-count").textContent =
    rows.length ? `${rows.length} waiting` : "";

  const panel = document.getElementById("approvals");
  panel.innerHTML = rows.length ? rows.map(r => `
    <div class="review hold">
      <div class="meta"><span>${esc(r.actor)}</span>
        <span>${esc(r.state)} · risk ${esc(r.risk_score)}</span>
        <span>held ${esc(since(r.requested_at))}</span>
        <span>expires ${esc(time(r.expires_at))}</span></div>
      <div class="mono">${esc((r.action||{}).raw_input || "")}</div>
      <div class="muted" style="margin-top:5px">→ ${esc(r.reason)}</div>
      <div class="actions">
        <button data-approve="1" data-id="${esc(r.request_id)}" class="tp">Approve</button>
        <button data-approve="0" data-id="${esc(r.request_id)}" class="fp">Reject</button>
      </div>
    </div>`).join("")
    : `<div class="empty">${stats.expired || 0} request(s) expired unanswered</div>`;

  panel.querySelectorAll("button[data-approve]").forEach(b => {
    b.onclick = () => resolveApproval(b.dataset.id, b.dataset.approve === "1");
  });
}

const since = ts => {
  if(!ts) return "—";
  const seconds = Math.max(0, Math.round((Date.now() - new Date(ts).getTime())/1000));
  return seconds < 60 ? `${seconds}s` : `${Math.round(seconds/60)}m`;
};

async function resolveApproval(requestId, approved){
  let reviewer = localStorage.getItem(REVIEWER);
  while(!reviewer){
    reviewer = (prompt("WHO ARE YOU? Your name — not a key. It is recorded against this decision.") || "").trim();
    if(!reviewer) return;
    if(reviewer === consoleKey()){
      alert("That is the console key, not a name.");
      reviewer = "";
    }
  }
  localStorage.setItem(REVIEWER, reviewer);

  let note = "";
  if(!approved){
    note = prompt("Why are you rejecting this? (required — the agent's owner will ask)") || "";
    if(!note.trim()) return;
  }

  // Answering mints a signed proof, so this needs the admin key rather than the
  // console key: reading the queue and authorising an irreversible action on
  // someone's behalf are not the same privilege.
  let admin = sessionStorage.getItem(ADMIN);
  if(!admin){
    admin = (prompt("Admin key (AETHERYA_APPROVALS_API_KEY) — approving signs a proof:") || "").trim();
    if(!admin) return;
    // Session storage, not local: an approval key should not outlive the tab.
    sessionStorage.setItem(ADMIN, admin);
  }

  const r = await fetch("/v1/approvals/resolve", {
    method: "POST",
    headers: {"Content-Type":"application/json", "X-AETHERYA-Admin-Key": admin},
    body: JSON.stringify({request_id: requestId, approved, decided_by: reviewer, note})
  });
  const body = await r.json().catch(() => ({}));
  if(!r.ok){
    if(r.status === 401 || r.status === 403) sessionStorage.removeItem(ADMIN);
    alert(`Could not record the decision:

${body.error || r.status}`);
    loadApprovals();
    return;
  }
  // The agent polling /v1/approvals/status picks these up on its own. Shown
  // here because an operator running the flow by hand needs all three: the
  // proof alone leaves the retry refused for missing evidence.
  if(body.confirmation){
    const shown = Object.entries(body.confirmation)
      .map(([k, v]) => `${k}=${String(v).slice(0, 60)}`).join(`
`);
    console.log("[ÆTHERYA] confirmation parameters for the retry:", body.confirmation);
    alert(`Approved. The agent retries with:

${shown}`);
  }
  loadApprovals();
}

// Polling is paused while locked. Without this a wrong key re-prompts on every
// tick; with it the page waits for the operator instead of nagging.
let paused = false;

function locked(unauthorized){
  const text = unauthorized
    ? "Locked — the console key was rejected."
    : "Could not reach the engine.";
  const panel = `<div class="empty">${text}<br>
    <button id="unlock" class="unlock">Enter console key</button></div>`;
  document.getElementById("criteria").innerHTML = panel;
  document.getElementById("review").innerHTML = "";
  document.getElementById("feed").innerHTML =
    `<tr><td colspan="6" class="empty">${text}</td></tr>`;
  const button = document.getElementById("unlock");
  if(button) button.onclick = unlock;
}

function unlock(){
  if(!askForKey()) return;
  paused = false;
  refresh();
}

async function refresh(){
  if(paused) return;
  try {
    await loadStatus(); await loadFeed(); await loadRollout(); await loadApprovals();
  } catch(e){
    paused = true;
    locked(e instanceof Unauthorized);
  }
}

renderFilters();
if(!consoleKey()) askForKey();
refresh();
setInterval(refresh, 10000);
</script>
</body>
</html>
"""
