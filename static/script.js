// ═══ CONFIG ═══════════════════════════════════════════════════════════════════
const CONFIG = {
  streamDelayMs: 80,
  analyzeStreamDelay: 25,
};

// ═══ STATE ════════════════════════════════════════════════════════════════════
const S = {
  alerts: [],
  isPaused: false,
  autoScroll: true,
  criticalOnly: false,
  noiseReduction: false,
  qty: 1,
  isAnalyzing: false,
  backendOnline: false,
  charts: {},
  hcTimer: null,
};

// ═══ CLOCK ════════════════════════════════════════════════════════════════════
function tick() { document.getElementById('clock').textContent = new Date().toTimeString().slice(0,8); }
setInterval(tick, 1000); tick();

// ═══ RESET STATS UI TO ZERO ═══════════════════════════════════════════════════
function resetStatsUI() {
  const reductionEl = document.getElementById("reductionPercent");
  const progressFill = document.getElementById("progressFill");
  const efficiencyBadge = document.getElementById("efficiencyBadge");
  
  reductionEl.innerText = "0%";
  reductionEl.style.color = "var(--text-muted)";
  reductionEl.style.textShadow = "none";
  
  document.getElementById("totalAlerts").innerText = "0";
  document.getElementById("noiseRemoved").innerText = "0";
  document.getElementById("cleanAlerts").innerText = "0";
  
  if (progressFill) {
    progressFill.style.width = "0%";
  }
  
  if (efficiencyBadge) {
    efficiencyBadge.style.background = "var(--surface2)";
    efficiencyBadge.style.color = "var(--text-muted)";
    efficiencyBadge.style.borderColor = "var(--border2)";
    efficiencyBadge.innerText = "NO DATA";
  }
  
  const drPct = document.getElementById('dr-pct');
  const drBar = document.getElementById('dr-bar');
  const drRaw = document.getElementById('dr-raw');
  const drClean = document.getElementById('dr-clean');
  
  if (drPct) drPct.innerText = '—%';
  if (drBar) drBar.style.width = '0%';
  if (drRaw) drRaw.innerText = '0 raw';
  if (drClean) drClean.innerText = '0 clean';
  
  const drStatsBody = document.getElementById('dr-stats-body');
  if (drStatsBody) {
    drStatsBody.innerHTML = '<div style="color:var(--text-muted);font-size:11px;text-align:center;padding:20px">No data yet — generate alerts first</div>';
  }
}

// ═══ BACKEND HEALTH CHECK ════════════════════════════════════════════════════
async function healthCheck() {
  const url = document.getElementById('api-url').value.trim();
  const ind = document.getElementById('backend-indicator');
  const dot = document.getElementById('be-dot');
  const lbl = document.getElementById('be-label');
  try {
    const r = await fetch(`${url}/health`, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      const data = await r.json();
      S.backendOnline = true;
      ind.className = 'backend-indicator online';
      dot.className = 'dot nominal';
      const stored = data.stored_alerts ? ` (${data.stored_alerts})` : '';
      lbl.textContent = (data.gemini_configured ? 'GEMINI ✓' : 'GEMINI ✗') + stored;
      return;
    }
  } catch {}
  S.backendOnline = false;
  ind.className = 'backend-indicator offline';
  dot.className = 'dot incident';
  lbl.textContent = 'BACKEND ✗';
}

function scheduleHealthCheck() {
  clearTimeout(S.hcTimer);
  S.hcTimer = setTimeout(healthCheck, 600);
}

healthCheck();
setInterval(healthCheck, 15000);


function apiUrl() { 
    // First check if user manually set a URL
    let manualUrl = document.getElementById('api-url').value.trim();
    if (manualUrl !== '') {
        return manualUrl;
    }
    // Otherwise auto-detect from current page
    return window.location.origin;
}

// ═══ QTY BUTTONS ════════════════════════════════════════════════════════════
document.querySelectorAll('.qty-btn').forEach(b => {
  b.addEventListener('click', () => {
    document.querySelectorAll('.qty-btn').forEach(x => x.classList.remove('active'));
    b.classList.add('active');
    S.qty = parseInt(b.dataset.v);
  });
});

// ═══ STATUS ══════════════════════════════════════════════════════════════════
function updateStatus() {
  const total = S.alerts.length;
  const crit  = S.alerts.filter(a => a.severity === 'CRITICAL').length;
  const high  = S.alerts.filter(a => a.severity === 'HIGH').length;
  const med   = S.alerts.filter(a => a.severity === 'MEDIUM').length;

  document.getElementById('s-total').textContent    = total;
  document.getElementById('s-crit').textContent     = crit;
  document.getElementById('s-high').textContent     = high;
  document.getElementById('s-med').textContent      = med;
  document.getElementById('chip-total').textContent = total;
  document.getElementById('chip-crit').textContent  = crit;
  document.getElementById('chip-high').textContent  = high;
  document.getElementById('ev-label').textContent   = `${total} events`;

  const dot = document.getElementById('status-dot');
  const txt = document.getElementById('status-text');
  if (total === 0)      { dot.className = 'dot nominal';   txt.textContent = 'NOMINAL'; }
  else if (crit > 0)    { dot.className = 'dot incident';  txt.textContent = 'INCIDENT'; }
  else if (high > 0)    { dot.className = 'dot degraded';  txt.textContent = 'DEGRADED'; }
  else                  { dot.className = 'dot analyzing'; txt.textContent = 'WARNING'; }
}

// ═══ LOG RENDERING ════════════════════════════════════════════════════════════
function fmtTime(ts) {
  return new Date(ts).toTimeString().slice(0,8);
}

function renderEntry(a) {
  const div = document.createElement('div');
  div.className = `log-entry ${a.severity}`;
  div.dataset.type    = (a.type     || '').toLowerCase();
  div.dataset.service = (a.service  || '').toLowerCase();
  div.dataset.msg     = (a.message  || '').toLowerCase();
  div.dataset.sev     = (a.severity || '').toLowerCase();
  div.innerHTML = `
    <span class="lt">${fmtTime(a.timestamp)}</span>
    <span class="ls">${(a.service||'').padEnd(11).slice(0,11)}</span>
    <span class="lm">${a.message || a.type}</span>
    <span class="lv ${a.severity}">${a.severity}</span>
  `;
  return div;
}

function appendEntry(a) {
  if (S.isPaused) return;
  const stream = document.getElementById('log-stream');
  const ph = stream.querySelector('.log-placeholder');
  if (ph) ph.remove();

  const el = renderEntry(a);
  applyEntryFilter(el, a);
  stream.appendChild(el);
  if (S.autoScroll) stream.scrollTop = stream.scrollHeight;
}

function appendSep(text) {
  const stream = document.getElementById('log-stream');
  const ph = stream.querySelector('.log-placeholder');
  if (ph) ph.remove();
  const div = document.createElement('div');
  div.className = 'log-sep';
  div.textContent = text;
  stream.appendChild(div);
  if (S.autoScroll) stream.scrollTop = stream.scrollHeight;
}

function applyEntryFilter(el, a) {
  const search = document.getElementById('search').value.toLowerCase();
  const type = (a.type||'').toLowerCase();
  const svc  = (a.service||'').toLowerCase();
  const msg  = (a.message||'').toLowerCase();
  const sev  = (a.severity||'').toLowerCase();

  let show = true;
  if (S.criticalOnly && sev !== 'critical') show = false;
  if (S.noiseReduction && sev === 'medium') show = false;
  if (search && !type.includes(search) && !svc.includes(search) && !msg.includes(search)) show = false;
  el.style.display = show ? '' : 'none';
}

function applyFilters() {
  document.querySelectorAll('.log-entry').forEach(el => {
    applyEntryFilter(el, {
      type: el.dataset.type, service: el.dataset.service,
      message: el.dataset.msg, severity: el.dataset.sev
    });
  });
}

// ═══ STREAM HELPERS ══════════════════════════════════════════════════════════
function streamAlerts(alerts, sep = null) {
  if (sep) appendSep(sep);
  alerts.forEach((a, i) => {
    const delay = sep
      ? i * (CONFIG.streamDelayMs * 0.6)
      : i * (S.qty <= 5 ? CONFIG.streamDelayMs * 3 : CONFIG.streamDelayMs);
    setTimeout(() => {
      S.alerts.push(a);
      appendEntry(a);
      updateStatus();
    }, delay);
  });
}

// ═══ GENERATE ALERTS — calls /generate ═══════════════════════════════════════
async function generateAlerts() {
  const type = document.getElementById('sel-type').value;
  const svc  = document.getElementById('sel-svc').value;

  if (!S.backendOnline) {
    toast('Backend offline — cannot generate alerts', 'error');
    return;
  }

  setBtnLoading('btn-gen', true);
  try {
    const res = await fetch(`${apiUrl()}/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alert_type: type, service: svc, quantity: S.qty }),
    });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    streamAlerts(data.alerts);
    await fetchStats();
  } catch (e) {
    toast(`Generate failed: ${e.message}`, 'error');
  } finally {
    setBtnLoading('btn-gen', false);
  }
}

// ═══ SIMULATE INCIDENT — calls /simulate-incident ════════════════════════════
async function simulateIncident() {
  if (!S.backendOnline) { toast('Backend offline', 'error'); return; }

  setBtnLoading('btn-incident', true);
  try {
    const res = await fetch(`${apiUrl()}/simulate-incident`, { method: 'POST' });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    const summary = data.chain_summary?.join(' → ') || 'INCIDENT CHAIN';
    streamAlerts(data.alerts, `INCIDENT: ${summary}`);
    toast(`Incident chain: ${data.chain_summary?.length || '?'} stages, ${data.count} alerts`, 'info');
    await fetchStats();
  } catch (e) {
    toast(`Incident failed: ${e.message}`, 'error');
  } finally {
    setBtnLoading('btn-incident', false);
  }
}

// ═══ ANALYZE — calls /analyze for AI summary ════════════════════════════════
async function analyzeAlerts() {
  if (S.alerts.length === 0) { toast('No alerts to analyze', 'error'); return; }
  if (S.isAnalyzing) return;
  if (!S.backendOnline) { toast('Backend offline — cannot analyze', 'error'); return; }

  S.isAnalyzing = true;
  setBtnLoading('btn-analyze', true);
  document.getElementById('an-badge').textContent = 'ANALYZING…';

  showScanState();

  const steps = ['step-1','step-2','step-3','step-4'];
  let stepIdx = 0;
  const stepTimer = setInterval(() => {
    if (stepIdx > 0) {
      const prev = document.getElementById(steps[stepIdx - 1]);
      if (prev) prev.className = 'scan-step done';
    }
    const cur = document.getElementById(steps[stepIdx]);
    if (cur) cur.className = 'scan-step active';
    stepIdx++;
    if (stepIdx >= steps.length) clearInterval(stepTimer);
  }, 600);

  try {
    const res = await fetch(`${apiUrl()}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alerts: S.alerts }),
    });
    if (!res.ok) throw new Error(await res.text());
    const analysis = await res.json();

    clearInterval(stepTimer);
    steps.forEach(s => { const el = document.getElementById(s); if(el) el.className = 'scan-step done'; });

    await sleep(300);

    renderResults(analysis);
    document.getElementById('an-badge').textContent = 'COMPLETE';
    toast('Analysis complete', 'ok');

    streamAiSummary(analysis.ai_summary || '');
    
    await fetchStats();

  } catch (e) {
    toast(`Analysis failed: ${e.message}`, 'error');
    document.getElementById('an-badge').textContent = 'ERROR';
    showIdleState();
  } finally {
    S.isAnalyzing = false;
    setBtnLoading('btn-analyze', false);
  }
}

// ═══ CLEAR HISTORY — calls backend to clear all data ════════════════════════
async function clearHistory() {
  if (!S.backendOnline) {
    toast('Backend offline — cannot clear history', 'error');
    return;
  }

  if (!confirm('Are you sure you want to clear ALL history?\n\nThis will permanently delete:\n• All alerts\n• All analysis results\n• All stats data\n\nThis cannot be undone!')) {
    return;
  }

  const clearBtn = document.getElementById('clear-history-btn');
  const originalText = clearBtn.innerText;
  clearBtn.innerText = 'CLEARING...';
  clearBtn.disabled = true;
  
  try {
    const res = await fetch(`${apiUrl()}/clear-all`, { 
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    
    if (!res.ok) {
      const errorData = await res.json();
      throw new Error(errorData.detail || 'Failed to clear history');
    }
    
    const data = await res.json();
    
    S.alerts = [];
    document.getElementById('log-stream').innerHTML = '<div class="log-placeholder">AWAITING CHAOS\nGENERATE ALERTS TO BEGIN</div>';
    updateStatus();
    
    document.getElementById('results').innerHTML = '';
    showIdleState();
    document.getElementById('an-badge').textContent = 'STANDBY';
    
    resetStatsUI();
    
    document.getElementById('dr-hist-body').innerHTML = '<div style="color:var(--text-muted);font-size:11px;text-align:center;padding:20px">No analyses yet</div>';
    
    document.getElementById('dr-stats-body').innerHTML = '<div style="color:var(--text-muted);font-size:11px;text-align:center;padding:20px">No data yet — generate alerts first</div>';
    
    document.getElementById('dr-pct').innerText = '—%';
    document.getElementById('dr-bar').style.width = '0%';
    document.getElementById('dr-raw').innerText = '0 raw';
    document.getElementById('dr-clean').innerText = '0 clean';
    
    toast('All history cleared successfully', 'ok');
    
    setTimeout(() => {
      closeDrawer();
    }, 1500);
    
  } catch (e) {
    toast(`Clear failed: ${e.message}`, 'error');
    console.error('Clear history error:', e);
  } finally {
    clearBtn.innerText = originalText;
    clearBtn.disabled = false;
  }
}

// ═══ FETCH STATS - ALERT FATIGUE REDUCTION ═══════════════════════════════════
async function fetchStats() {
    if (!S.backendOnline) {
        console.log("Backend offline, skipping stats fetch");
        return;
    }
    
    try {
        const response = await fetch(`${apiUrl()}/stats`);
        if (!response.ok) throw new Error('Failed to fetch stats');
        const data = await response.json();
        updateStatsUI(data);
        return data;
    } catch (error) {
        console.error("Error fetching stats:", error);
    }
}

function updateStatsUI(data) {
    const reduction = data.reduction_percent || 0;
    const reductionEl = document.getElementById("reductionPercent");
    const progressFill = document.getElementById("progressFill");
    const efficiencyBadge = document.getElementById("efficiencyBadge");
    
    reductionEl.innerText = reduction + "%";
    document.getElementById("totalAlerts").innerText = data.total_raw_alerts || 0;
    document.getElementById("noiseRemoved").innerText = data.total_noise_removed || 0;
    document.getElementById("cleanAlerts").innerText = data.total_clean_alerts || 0;
    
    if (progressFill) {
        progressFill.style.width = reduction + "%";
    }
    
    if (reduction > 70) {
        reductionEl.style.color = "var(--green)";
        reductionEl.style.textShadow = "0 0 20px var(--green)";
        if (efficiencyBadge) {
            efficiencyBadge.style.background = "var(--green-dark)";
            efficiencyBadge.style.color = "var(--green)";
            efficiencyBadge.style.borderColor = "var(--green)";
            efficiencyBadge.innerText = "EXCELLENT";
        }
    } else if (reduction > 40) {
        reductionEl.style.color = "var(--yellow)";
        reductionEl.style.textShadow = "0 0 20px var(--yellow)";
        if (efficiencyBadge) {
            efficiencyBadge.style.background = "var(--yellow-dark)";
            efficiencyBadge.style.color = "var(--yellow)";
            efficiencyBadge.style.borderColor = "var(--yellow)";
            efficiencyBadge.innerText = "MODERATE";
        }
    } else if (reduction > 0) {
        reductionEl.style.color = "var(--orange)";
        reductionEl.style.textShadow = "0 0 20px var(--orange)";
        if (efficiencyBadge) {
            efficiencyBadge.style.background = "var(--orange-dark)";
            efficiencyBadge.style.color = "var(--orange)";
            efficiencyBadge.style.borderColor = "var(--orange)";
            efficiencyBadge.innerText = "LOW";
        }
    } else {
        reductionEl.style.color = "var(--text-muted)";
        reductionEl.style.textShadow = "none";
        if (efficiencyBadge) {
            efficiencyBadge.style.background = "var(--surface2)";
            efficiencyBadge.style.color = "var(--text-muted)";
            efficiencyBadge.style.borderColor = "var(--border2)";
            efficiencyBadge.innerText = "NO DATA";
        }
    }
    
    reductionEl.classList.add('reduction-updated');
    setTimeout(() => {
        reductionEl.classList.remove('reduction-updated');
    }, 500);
}

// ═══ RESULTS RENDERING ════════════════════════════════════════════════════════
function renderResults(r) {
  showResultsState();
  const wrap = document.getElementById('results');
  wrap.innerHTML = '';

  if (r.noise_removed !== undefined) {
    const noiseDiv = document.createElement('div');
    noiseDiv.className = 'card';
    noiseDiv.innerHTML = `
      <div class="card-body" style="color:var(--orange)">
        Noise Reduction Active<br>
        Removed: <strong>${r.noise_removed}</strong> duplicates<br>
        Processed: <strong>${r.filtered_alerts}</strong> clean signals from 
        <strong>${r.total_alerts}</strong> raw alerts
      </div>
    `;
    wrap.appendChild(noiseDiv);
  }

  const summaryDiv = document.createElement('div');
  summaryDiv.className = 'ai-summary';
  summaryDiv.innerHTML = `
    <div class="ai-summary-label">AI Incident Narrative</div>
    <div class="ai-summary-text" id="ai-summary-text"><span class="cursor-blink"></span></div>
  `;
  wrap.appendChild(summaryDiv);

  if (r.security_threats && r.security_threats.length > 0) {
    const securityCard = renderSecurityThreats(r.security_threats);
    if (securityCard) {
      wrap.appendChild(securityCard.card);
    }
  } else {
    const securityCard = makeCard('Security Status', '');
    securityCard.body.innerHTML = `
      <div style="display:flex; align-items:center; gap:12px; padding:8px;">
        <div style="font-size:24px;">✓</div>
        <div>
          <div style="color:var(--green); font-size:12px; font-weight:600;">NO ACTIVE THREATS DETECTED</div>
          <div style="color:var(--text-muted); font-size:11px; margin-top:4px;">System appears secure - continuing normal monitoring</div>
        </div>
      </div>
    `;
    wrap.appendChild(securityCard.card);
  }

  if (r.future_prediction) {
    const pred = r.future_prediction;
    const predCard = makeCard('System Forecast', '');
    
    const statusColor = pred.prediction === 'CRITICAL_FAILURE' ? 'var(--critical)' : 
                        pred.prediction === 'MAJOR_DEGRADATION' ? 'var(--orange)' : 
                        pred.prediction === 'INSTABILITY' ? 'var(--yellow)' : 'var(--green)';
    
    predCard.body.innerHTML = `
      <div style="display:flex; align-items:center; gap:12px;">
        <div style="font-size:32px;">
          ${pred.prediction === 'CRITICAL_FAILURE' ? '⚠' : 
            pred.prediction === 'MAJOR_DEGRADATION' ? '⚠' : 
            pred.prediction === 'INSTABILITY' ? '~' : '✓'}
        </div>
        <div style="flex:1;">
          <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
            <span style="color:${statusColor}; font-size:14px; font-weight:600;">${pred.prediction.replace('_', ' ')}</span>
            <span style="background:${statusColor}; color:var(--bg); padding:2px 6px; font-size:10px;">${pred.confidence}</span>
          </div>
          <div style="color:var(--text); font-size:12px; margin-bottom:4px;">${pred.message}</div>
          <div style="color:var(--orange); font-size:11px;">ETA: ${pred.eta}</div>
          
          <div style="margin-top:8px; display:grid; grid-template-columns:repeat(3,1fr); gap:4px;">
            <div style="background:var(--surface2); padding:4px; text-align:center;">
              <div style="color:${pred.risk_factors?.critical_alerts > 0 ? 'var(--critical)' : 'var(--text-muted)'}; font-size:12px;">${pred.risk_factors?.critical_alerts || 0}</div>
              <div style="font-size:8px; color:var(--text-muted);">CRITICAL</div>
            </div>
            <div style="background:var(--surface2); padding:4px; text-align:center;">
              <div style="color:${pred.risk_factors?.high_alerts > 0 ? 'var(--high)' : 'var(--text-muted)'}; font-size:12px;">${pred.risk_factors?.high_alerts || 0}</div>
              <div style="font-size:8px; color:var(--text-muted);">HIGH</div>
            </div>
            <div style="background:var(--surface2); padding:4px; text-align:center;">
              <div style="color:var(--text); font-size:12px;">${pred.risk_factors?.affected_services || 0}</div>
              <div style="font-size:8px; color:var(--text-muted);">SERVICES</div>
            </div>
          </div>
        </div>
      </div>
    `;
    
    wrap.appendChild(predCard.card);
  }

  const rc = makeCard('Root Cause', '');
  const cascade = (r.cascade_chain || []);
  const rcData = typeof r.root_cause === 'object' ? r.root_cause : {
    service: r.root_cause,
    confidence: r.confidence || 'MEDIUM',
    affected: []
  };

  rc.body.innerHTML = `
    <div class="rc-box">
      <div class="rc-label">Primary Cause Identified</div>
      <div class="rc-name">${rcData.service || 'Unknown'}</div>
      <div class="rc-service">
        Affected: ${(rcData.affected || []).join(', ') || 'N/A'}
      </div>
      <span class="rc-confidence ${rcData.confidence || 'MEDIUM'}">
        ${rcData.confidence || 'MEDIUM'} CONFIDENCE
      </span>
    </div>
    <div class="cascade">
      ${cascade.map(step => `<span class="cascade-step">${step}</span>`).join('<span class="cascade-arr">→</span>')}
    </div>
  `;
  wrap.appendChild(rc.card);

  if (r.top_alerts) {
    const top = makeCard('Top Alerts (Scored)', '');

    r.top_alerts.forEach(a => {
      const item = document.createElement('div');
      item.className = 'cluster-item';
      item.innerHTML = `
        <div class="cluster-name">${a.service}</div>
        <div class="cluster-tags">
          <span class="cluster-tag">${a.type}</span>
          <span class="cluster-tag">${a.severity}</span>
          <span class="cluster-tag">Score: ${a.score}</span>
        </div>
      `;
      top.body.appendChild(item);
    });

    wrap.appendChild(top.card);
  }

  const cl = makeCard('Alert Clusters', '');
  (r.clusters || []).forEach(c => {
    const item = document.createElement('div');
    item.className = 'cluster-item';
    item.innerHTML = `
      <div class="cluster-name">${c.service} - ${c.type}</div>
      <div class="cluster-tags">
        <span class="cluster-tag">Count: ${c.count}</span>
        <span class="cluster-tag">Score: ${c.total_score}</span>
      </div>
      <div class="cluster-sev ${c.dominant_severity}">
        ${c.dominant_severity}
      </div>
    `;
    cl.body.appendChild(item);
  });
  wrap.appendChild(cl.card);

  const pr = makeCard('Priority Ranking', '');
  const maxScore = Math.max(1, ...(r.priority_ranking||[]).map(p=>p.score||1));
  (r.priority_ranking || []).forEach((p, i) => {
    const color = p.severity==='CRITICAL'?'var(--critical)':p.severity==='HIGH'?'var(--high)':'var(--yellow)';
    const pct = Math.round((p.score/maxScore)*100);
    const item = document.createElement('div');
    item.className = 'pri-item';
    item.innerHTML = `
      <span class="pri-num">${i+1}</span>
      <div class="pri-wrap">
        <div class="pri-name">${p.type}</div>
        <div class="pri-reason">${p.reason||''}</div>
        <div class="pri-bar"><div class="pri-bar-fill" style="width:0%;background:${color}" data-w="${pct}%"></div></div>
      </div>
      <span class="pri-sev" style="color:${color}">${p.severity}</span>
    `;
    pr.body.appendChild(item);
  });
  wrap.appendChild(pr.card);

  const rec = makeCard('Recommendations', '');
  (r.recommendations || []).forEach(r2 => {
    const item = document.createElement('div');
    item.className = `rec-item ${r2.urgency}`;
    item.innerHTML = `
      <div class="rec-action">${r2.action}</div>
      <div class="rec-detail">${r2.detail}</div>
      <div class="rec-urgency ${r2.urgency}">${r2.urgency}</div>
    `;
    rec.body.appendChild(item);
  });
  wrap.appendChild(rec.card);

  const ch = makeCard('Visualization', '');
  ch.body.innerHTML = `
    <div class="chart-grid">
      <div class="chart-box">
        <div class="chart-label">Severity Distribution</div>
        <canvas id="c-sev" height="140"></canvas>
      </div>
      <div class="chart-box">
        <div class="chart-label">Alert Types</div>
        <canvas id="c-type" height="140"></canvas>
      </div>
    </div>
  `;
  wrap.appendChild(ch.card);
  document.getElementById('results').classList.add('show');

  setTimeout(() => {
    document.querySelectorAll('.pri-bar-fill').forEach(el => { el.style.width = el.dataset.w; });
  }, 100);

  setTimeout(() => renderCharts(r), 200);
}

function renderSecurityThreats(threats) {
  if (!threats || threats.length === 0) {
    return null;
  }

  const threatCard = makeCard('ACTIVE SECURITY THREATS', '');
  
  let threatHtml = '<div style="display:flex; flex-direction:column; gap:12px;">';
  
  threats.forEach(threat => {
    const severityColor = threat.severity === 'CRITICAL' ? 'var(--critical)' : 'var(--high)';
    
    threatHtml += `
      <div style="border:1px solid ${severityColor}; background:rgba(255,59,59,0.1); padding:12px;">
        <div style="display:flex; align-items:center; gap:8px; margin-bottom:8px;">
          <span style="background:${severityColor}; color:var(--bg); padding:2px 8px; font-size:10px; font-weight:600;">${threat.type.replace('_', ' ').toUpperCase()}</span>
          <span style="color:${severityColor}; font-size:11px;">${threat.confidence} CONFIDENCE</span>
          <span style="margin-left:auto; color:var(--text-muted); font-size:10px;">${threat.evidence} indicators</span>
        </div>
        
        <div style="color:var(--text); font-size:12px; margin-bottom:6px;">${threat.description}</div>
        
        <div style="color:var(--orange); font-size:11px; margin:8px 0;">Attack pattern: ${threat.time_pattern || 'Analyzing...'}</div>
        
        <div style="margin:10px 0;">
          <div style="color:var(--text-muted); font-size:10px; margin-bottom:4px;">DETECTED INDICATORS:</div>
          ${(threat.indicators || []).map(ind => `
            <div style="background:var(--surface2); padding:4px 8px; margin:2px 0; font-size:11px; border-left:2px solid ${severityColor};">${ind}</div>
          `).join('')}
        </div>
        
        <div style="margin:10px 0; padding:8px; background:rgba(0,0,0,0.3);">
          <div style="color:var(--purple); font-size:10px; margin-bottom:4px;">PREDICTED NEXT ACTIONS:</div>
          <ul style="margin:0; padding-left:16px; color:var(--text-dim); font-size:11px;">
            ${(threat.next_steps || []).map(step => `<li>${step}</li>`).join('')}
          </ul>
        </div>
        
        <div style="margin-top:10px;">
          <div style="color:var(--blue); font-size:10px; margin-bottom:4px;">RECOMMENDATIONS:</div>
          <div style="display:flex; flex-wrap:wrap; gap:4px;">
            ${(threat.recommendations || []).map(rec => `
              <span style="background:var(--surface2); border:1px solid var(--blue); color:var(--blue); padding:2px 6px; font-size:10px;">${rec}</span>
            `).join('')}
          </div>
        </div>
        
        <div style="margin-top:8px; font-size:10px; color:var(--text-muted);">
          Affected: ${(threat.affected_services || []).join(', ')}
        </div>
      </div>
    `;
  });
  
  threatHtml += '</div>';
  threatCard.body.innerHTML = threatHtml;
  return threatCard;
}

function makeCard(title, icon) {
  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML = `
    <div class="card-hdr" onclick="this.closest('.card').classList.toggle('collapsed')">
      <span style="font-size:14px">${icon}</span>
      <span class="card-title">${title}</span>
      <span class="card-chevron">▾</span>
    </div>
    <div class="card-body"></div>
  `;
  return { card, body: card.querySelector('.card-body') };
}

function renderCharts(r) {
  Object.values(S.charts).forEach(c => { 
    try { 
      if (c && typeof c.destroy === 'function') c.destroy(); 
    } catch {} 
  });
  S.charts = {};

  const sev = r.severity_distribution || {};
  const types = r.type_counts || {};

  const opts = {
    color: '#6b8fa3',
    plugins: { 
      legend: { 
        labels: { 
          color: '#6b8fa3', 
          font: { family: 'JetBrains Mono', size: 10 }, 
          boxWidth: 10, 
          padding: 8 
        } 
      }
    }
  };

  const sevCtx = document.getElementById('c-sev');
  if (sevCtx) {
    S.charts.sev = new Chart(sevCtx, {
      type: 'doughnut',
      data: {
        labels: ['CRITICAL', 'HIGH', 'MEDIUM'],
        datasets: [{ 
          data: [sev.CRITICAL||0, sev.HIGH||0, sev.MEDIUM||0],
          backgroundColor: ['rgba(255,59,59,.65)', 'rgba(255,140,0,.65)', 'rgba(255,215,0,.65)'],
          borderColor: ['#ff3b3b', '#ff8c00', '#ffd700'], 
          borderWidth: 1 
        }]
      },
      options: { ...opts, cutout: '60%' }
    });
  }

  const typeCtx = document.getElementById('c-type');
  if (typeCtx && Object.keys(types).length) {
    const labels = Object.keys(types);
    const vals   = labels.map(l => types[l]);
    S.charts.type = new Chart(typeCtx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{ 
          data: vals, 
          backgroundColor: 'rgba(0,180,216,.3)', 
          borderColor: '#00b4d8', 
          borderWidth: 1 
        }]
      },
      options: {
        ...opts,
        indexAxis: 'y',
        scales: {
          x: { 
            ticks: { color: '#3d5a6b', font: { size: 9, family: 'JetBrains Mono' } }, 
            grid: { color: '#1e2d38' } 
          },
          y: { 
            ticks: { color: '#3d5a6b', font: { size: 9, family: 'JetBrains Mono' } }, 
            grid: { color: '#1e2d38' } 
          }
        },
        plugins: { legend: { display: false } }
      }
    });
  }
}

// ═══ AI SUMMARY TYPEWRITER ════════════════════════════════════════════════════
function streamAiSummary(text) {
  const el = document.getElementById('ai-summary-text');
  if (!el) return;
  el.innerHTML = '';
  let i = 0;
  function type() {
    if (i < text.length) {
      el.textContent += text[i++];
      el.innerHTML += '<span class="cursor-blink"></span>';
      const cursors = el.querySelectorAll('.cursor-blink');
      cursors.forEach((c, idx) => { if (idx < cursors.length - 1) c.remove(); });
      setTimeout(type, CONFIG.analyzeStreamDelay);
    } else {
      const cursors = el.querySelectorAll('.cursor-blink');
      cursors.forEach(c => c.remove());
    }
  }
  type();
}

// ═══ VIEW STATE ═══════════════════════════════════════════════════════════════
function showIdleState() {
  document.getElementById('idle-state').style.display = 'flex';
  document.getElementById('scan-state').classList.remove('show');
  document.getElementById('results').classList.remove('show');
}
function showScanState() {
  document.getElementById('idle-state').style.display = 'none';
  document.getElementById('scan-state').classList.add('show');
  document.getElementById('results').classList.remove('show');
  ['step-1','step-2','step-3','step-4'].forEach(id => {
    const el = document.getElementById(id); if(el) el.className = 'scan-step';
  });
}
function showResultsState() {
  document.getElementById('idle-state').style.display = 'none';
  document.getElementById('scan-state').classList.remove('show');
  document.getElementById('results').classList.add('show');
}

// ═══ CLEAR ════════════════════════════════════════════════════════════════════
function clearAll() {
  S.alerts = [];
  document.getElementById('log-stream').innerHTML = '<div class="log-placeholder">AWAITING CHAOS\nGENERATE ALERTS TO BEGIN</div>';
  updateStatus();
  Object.values(S.charts).forEach(c => { 
    try { 
      if (c && typeof c.destroy === 'function') c.destroy(); 
    } catch {} 
  });
  S.charts = {};
  document.getElementById('results').innerHTML = '';
  showIdleState();
  document.getElementById('an-badge').textContent = 'STANDBY';
  
  resetStatsUI();
}

// ═══ PAUSE ════════════════════════════════════════════════════════════════════
function togglePause() {
  S.isPaused = !S.isPaused;
  const btn = document.getElementById('pause-btn');
  btn.textContent = S.isPaused ? 'RESUME' : 'PAUSE';
  btn.classList.toggle('paused', S.isPaused);
}

// ═══ TOGGLE FILTERS ══════════════════════════════════════════════════════════
function toggleFilter(row, key) {
  const sw = row.querySelector('.tgl-sw');
  sw.classList.toggle('on');
  S[key] = sw.classList.contains('on');
  if (key === 'autoScroll' && S.autoScroll) {
    const stream = document.getElementById('log-stream');
    stream.scrollTop = stream.scrollHeight;
  }
  applyFilters();
}

// ═══ HELPERS ═════════════════════════════════════════════════════════════════
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function setBtnLoading(id, loading) {
  const btn = document.getElementById(id);
  if (!btn) return;
  btn.disabled = loading;
}

let toastTimer;
function toast(msg, type = 'info') {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();
  clearTimeout(toastTimer);
  const div = document.createElement('div');
  div.className = `toast ${type}`;
  div.textContent = msg;
  document.body.appendChild(div);
  toastTimer = setTimeout(() => div.remove(), 4000);
}

// ═══ DRAWER — STATS & HISTORY ════════════════════════════════════════════════
let _drawerOpen = false;

function toggleDrawer() {
  _drawerOpen = !_drawerOpen;
  const drawer = document.getElementById('drawer');
  if (drawer) {
    drawer.classList.toggle('open', _drawerOpen);
    if (_drawerOpen) loadStats();
  }
}
function closeDrawer() {
  _drawerOpen = false;
  const drawer = document.getElementById('drawer');
  if (drawer) drawer.classList.remove('open');
}
function switchDrawerTab(name) {
  document.querySelectorAll('.dtab').forEach(t => t.classList.toggle('active', t.dataset.dt === name));
  document.querySelectorAll('.dtab-content').forEach(c => c.classList.toggle('show', c.id === `dt-${name}`));
  if (name === 'history') loadHistory();
  if (name === 'stats')   loadStats();
}

async function loadStats() {
  if (!S.backendOnline) {
    document.getElementById('dr-stats-body').innerHTML = 
      '<div style="color:var(--orange);font-size:11px;text-align:center;padding:20px">Backend offline</div>';
    return;
  }
  
  try {
    const res  = await fetch(`${apiUrl()}/stats`);
    const data = await res.json();

    const pct = data.reduction_percent || 0;
    document.getElementById('dr-pct').textContent   = pct + '%';
    document.getElementById('dr-raw').textContent   = data.total_raw_alerts + ' raw';
    document.getElementById('dr-clean').textContent = data.total_clean_alerts + ' clean';
    
    const bar = document.getElementById('dr-bar');
    if (bar) bar.style.width = pct + '%';

    const body = document.getElementById('dr-stats-body');
    const sev  = data.by_severity || {};
    const types = data.top_alert_types || {};
    const svcs  = data.by_service || {};

    if (data.total_raw_alerts === 0) {
      body.innerHTML = '<div style="color:var(--text-muted);font-size:11px;text-align:center;padding:20px">No data yet — generate alerts first</div>';
      return;
    }

    body.innerHTML = `
      <div style="font-size:10px;color:var(--text-muted);letter-spacing:2px;margin-bottom:8px">CUMULATIVE COUNTS</div>
      <div class="stat2-row"><span class="stat2-lbl">Total Raw Alerts</span>  <span class="stat2-val">${data.total_raw_alerts}</span></div>
      <div class="stat2-row"><span class="stat2-lbl">Noise Removed</span>    <span class="stat2-val" style="color:var(--green)">${data.total_noise_removed}</span></div>
      <div class="stat2-row"><span class="stat2-lbl">Clean Alerts</span>     <span class="stat2-val" style="color:var(--blue)">${data.total_clean_alerts}</span></div>
      <div class="stat2-row"><span class="stat2-lbl">Critical</span>         <span class="stat2-val" style="color:var(--critical)">${sev.CRITICAL||0}</span></div>
      <div class="stat2-row"><span class="stat2-lbl">High</span>             <span class="stat2-val" style="color:var(--high)">${sev.HIGH||0}</span></div>
      <div class="stat2-row"><span class="stat2-lbl">Medium</span>           <span class="stat2-val" style="color:var(--medium)">${sev.MEDIUM||0}</span></div>
      <div style="font-size:10px;color:var(--text-muted);letter-spacing:2px;margin:12px 0 8px">TOP ALERT TYPES</div>
      ${Object.entries(types).map(([t,n]) => `<div class="stat2-row"><span class="stat2-lbl">${t}</span><span class="stat2-val">${n}</span></div>`).join('')}
      <div style="font-size:10px;color:var(--text-muted);letter-spacing:2px;margin:12px 0 8px">BY SERVICE</div>
      ${Object.entries(svcs).map(([s,n]) => `<div class="stat2-row"><span class="stat2-lbl">${s}</span><span class="stat2-val">${n}</span></div>`).join('')}
    `;
  } catch(e) {
    document.getElementById('dr-stats-body').innerHTML = `<div style="color:var(--red);font-size:11px">${e.message}</div>`;
  }
}

async function loadHistory() {
  if (!S.backendOnline) return;
  const wrap = document.getElementById('dr-hist-body');
  wrap.innerHTML = '<div style="color:var(--text-muted);font-size:11px;padding:10px">Loading…</div>';
  try {
    const res  = await fetch(`${apiUrl()}/history?limit=20`);
    const data = await res.json();
    if (!data.analyses.length) {
      wrap.innerHTML = '<div style="color:var(--text-muted);font-size:11px;text-align:center;padding:20px">No analyses yet</div>';
      return;
    }
    wrap.innerHTML = data.analyses.map(a => `
      <div class="hist-row" onclick="loadPastAnalysis(${a.id})">
        <span class="hist-id">#${a.id}</span>
        <span class="hist-rc">${a.root_cause || '?'}</span>
        <span class="hist-noise">-${a.noise_removed} noise</span>
        <span class="hist-conf ${a.confidence}">${a.confidence}</span>
      </div>
    `).join('');
  } catch(e) {
    wrap.innerHTML = `<div style="color:var(--red);font-size:11px">${e.message}</div>`;
  }
}

async function loadPastAnalysis(id) {
  try {
    const res  = await fetch(`${apiUrl()}/history/${id}`);
    const data = await res.json();
    renderResults(data);
    streamAiSummary(data.ai_summary || '');
    document.getElementById('an-badge').textContent = `LOADED #${id}`;
    closeDrawer();
    toast(`Loaded analysis #${id}`, 'info');
  } catch(e) {
    toast(`Load failed: ${e.message}`, 'error');
  }
}

// ═══ NARRATIVE HELPER ═══════════════════════════════════════════════════════
function getReductionNarrative(reduction) {
    if (reduction > 70) {
        return {
            level: "EXCELLENT",
            message: "Our AI is effectively filtering out 70%+ of noise, allowing engineers to focus on what matters.",
            impact: "Reduced MTTR by 65%, increased team productivity by 3x"
        };
    } else if (reduction > 40) {
        return {
            level: "MODERATE",
            message: "System is reducing noise, but there's room for improvement in pattern recognition.",
            impact: "40% fewer false alerts, saving 20+ engineer hours weekly"
        };
    } else {
        return {
            level: "POOR",
            message: "Alert fatigue is high - consider tuning thresholds or investigating root causes.",
            impact: "Engineers overwhelmed - 80% of alerts are non-actionable"
        };
    }
}

// ═══ SIDEBAR TOGGLE ═════════════════════════════════════════════════════════
function toggleSidebar() {
  const layout = document.getElementById('main-layout');
  const btn    = document.getElementById('sidebar-toggle');
  layout.classList.toggle('sidebar-collapsed');
  btn.classList.toggle('collapsed');
}

function toggleIntelPanel() {
  const layout = document.getElementById('main-layout');
  const btn    = document.getElementById('center-toggle');
  layout.classList.toggle('intel-collapsed');
  btn.classList.toggle('collapsed');
}

function toggleAlertPanel() {
  const layout = document.getElementById('main-layout');
  const btn = document.getElementById('log-toggle');  // Use log-toggle button
  layout.classList.toggle('log-collapsed');  // Toggle log-collapsed class
  if (btn) {
    btn.classList.toggle('collapsed');
  }
}

document.addEventListener('DOMContentLoaded', function() {
  const qtyBtn = document.querySelector('.qty-btn[data-v="1"]');
  if (qtyBtn) qtyBtn.classList.add('active');
  
  const scrollToggle = document.getElementById('tf-scroll');
  if (scrollToggle) scrollToggle.classList.add('on');
  
  updateStatus();
  
  resetStatsUI();
  
  document.getElementById('search').addEventListener('input', applyFilters);
  
  console.log("Ready - generate alerts to see stats");
});

class ThreatMonitor {
  constructor() {
    this.monitoring = false;
    this.baseline = {...S};
  }
  
  start() {
    if (this.monitoring) return;
    this.monitoring = true;
    this.interval = setInterval(() => this.checkForAnomalies(), 5000);
  }
  
  stop() {
    clearInterval(this.interval);
    this.monitoring = false;
  }
  
  checkForAnomalies() {
    const recentAlerts = S.alerts.slice(-10);
    const timeWindow = 60000;
    const now = Date.now();
    
    const recentCount = recentAlerts.filter(a => 
      now - new Date(a.timestamp).getTime() < timeWindow
    ).length;
    
    if (recentCount > 5) {
      this.triggerAlert('HIGH_VELOCITY', `Alert storm detected: ${recentCount} alerts in last minute`);
    }
    
    const serviceFailures = {};
    recentAlerts.forEach(a => {
      serviceFailures[a.service] = (serviceFailures[a.service] || 0) + 1;
    });
    
    Object.entries(serviceFailures).forEach(([service, count]) => {
      if (count > 3) {
        this.triggerAlert('SERVICE_FLOOD', `${service} is failing rapidly (${count} alerts)`);
      }
    });
  }
  
  triggerAlert(type, message) {
    toast(`THREAT DETECTED: ${message}`, 'error');
    
    if (!S.isPaused) {
      appendSep(`THREAT: ${type} - ${message}`);
    }
  }
}