(() => {
  const $ = (id) => document.getElementById(id);
  const qsa = (s, r=document) => Array.from(r.querySelectorAll(s));
  const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  const state = {
    current: null, // {result, case, content, source}
    history: [],
    batch: [],
    batchReports: null,
    currentTab: 'findings',
    view: 'scan',
    logs: ['Ready.'],
    defangObs: false,
  };

  function saveHistory() { try { localStorage.setItem('pg_history', JSON.stringify(state.history.slice(0, 30))); } catch {} }
  function loadHistory() {
    try { const h = JSON.parse(localStorage.getItem('pg_history')||'[]'); if (Array.isArray(h)) state.history = h; } catch {}
  }

  function log(msg) {
    const ts = new Date().toLocaleTimeString();
    state.logs.push(`[${ts}] ${msg}`);
    if (state.logs.length > 800) state.logs.shift();
    const el = $('activityLog'); if (el) el.textContent = state.logs.join('\n');
    setStatus(msg);
  }
  function setStatus(msg) { const el = $('statusMsg'); if (el) el.textContent = msg || ''; }
  function busy(msg) { setStatus(msg || 'Working...'); }

  async function api(path, opts={}) {
    const res = await fetch(path, Object.assign({ headers: { 'Content-Type': 'application/json' } }, opts));
    const ctype = res.headers.get('content-type') || '';
    if (!ctype.includes('application/json')) {
      const text = await res.text();
      if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
      return { text };
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
    return data;
  }

  function verdictColor(verdict) {
    const v = (verdict || '').toLowerCase();
    if (v.includes('critical') || v.includes('high')) return { fg: '#b42318', bg: '#fef3f2', border: '#fecdca', bar: '#d92d20', pillIcon: 'ti-bug' };
    if (v.includes('suspicious') || v.includes('medium')) return { fg: '#b54708', bg: '#fffaeb', border: '#fedf89', bar: '#f79009', pillIcon: 'ti-alert-triangle' };
    return { fg: '#067647', bg: '#ecfdf3', border: '#abefc6', bar: '#12b76a', pillIcon: 'ti-shield-check' };
  }
  function authClass(val) {
    const v = String(val || 'unknown').toLowerCase();
    if (['pass','passed'].includes(v)) return 'auth-pass';
    if (['fail','failed','softfail','hardfail','temperror','permerror'].includes(v)) return 'auth-fail';
    return 'auth-warn';
  }
  function authIcon(val) {
    const v = String(val || 'unknown').toLowerCase();
    if (['pass','passed'].includes(v)) return 'ti-check';
    if (['fail','failed','softfail','hardfail','temperror','permerror'].includes(v)) return 'ti-x';
    return 'ti-minus';
  }
  function defangStr(s) { return String(s||'').replace(/https?:\/\//g, m=>m.replace(/t/g,'x')).replace(/\./g,'[.]').replace(/@/g,'[@]').replace(/:/g,'[:]'); }

  function setVerdictPill(verdict, score) {
    const el = $('verdictPill'), txt = $('verdictPillText'), c = verdictColor(verdict);
    txt.textContent = verdict ? `${verdict} · ${score}` : 'No scan';
    el.style.background = verdict ? c.bg : 'var(--bg-warning)';
    el.style.color = verdict ? c.fg : 'var(--text-warning)';
    el.style.borderColor = verdict ? c.border : '#fedf89';
    el.querySelector('i').className = `ti ${verdict ? c.pillIcon : 'ti-shield'}`;
    const n = Number(score)||0;
    $('riskBarFill').style.width = verdict ? `${Math.max(0, Math.min(100, n))}%` : '0%';
    $('riskBarFill').style.background = verdict ? c.bar : 'var(--fill-danger)';
    $('riskBarNum').textContent = verdict ? `${n} / 100` : '-- / 100';
    $('riskBarNum').style.color = verdict ? c.fg : 'var(--text-danger)';
  }

  function renderAuth(auth={}, attachCount=0, ml={}) {
    [['badgeSpf','SPF',auth.spf],['badgeDkim','DKIM',auth.dkim],['badgeDmarc','DMARC',auth.dmarc]].forEach(([id,label,val])=>{
      const el=$(id); el.className=`auth-badge ${authClass(val)}`; el.innerHTML=`<i class="ti ${authIcon(val)}"></i> ${esc(label)} ${esc(val ?? '--')}`;
    });
    const a=$('badgeAttach'); a.className='auth-badge'+(attachCount>0?' auth-fail':''); a.innerHTML=`<i class="ti ti-paperclip"></i> ${attachCount} attachment${attachCount===1?'':'s'}`;
    const m=$('badgeMl');
    if (ml && ml.label && ml.label !== 'disabled') {
      const p = Math.round((Number(ml.phishing_probability)||0)*100);
      m.className='auth-badge ' + (p>=50?'auth-fail':p>=25?'auth-warn':'auth-pass');
      m.innerHTML=`<i class="ti ti-sparkles"></i> ML ${esc(ml.label)} ${p}%`;
    } else if (ml && ml.label === 'disabled') {
      m.className='auth-badge'; m.innerHTML=`<i class="ti ti-sparkles"></i> ML off`;
    } else { m.className='auth-badge'; m.innerHTML=`<i class="ti ti-sparkles"></i> ML --`; }
  }

  function filteredFindings() {
    const cur = state.current; if (!cur) return [];
    const q = ($('findingsSearch')?.value||'').toLowerCase().trim();
    const sev = $('findingsSeverity')?.value || '';
    return (cur.result.findings||[]).filter(f=>{
      const s = String(f.severity||'').toLowerCase();
      let sevOk = true;
      if (sev==='critical') sevOk = (s==='critical'||s==='high');
      else if (sev==='medium') sevOk = (s==='medium'||s==='suspicious');
      else if (sev==='low') sevOk = (s==='low');
      const text = `${f.title||''} ${f.detail||''} ${f.severity||''}`.toLowerCase();
      return sevOk && (!q || text.includes(q));
    });
  }

  function renderFindings() {
    const cur = state.current; const list = $('findingsList'); const title = $('findingsTitle');
    if (!list || !title) return;
    const all = cur ? (cur.result.findings||[]) : [];
    const findings = filteredFindings();
    if (!all.length) {
      title.innerHTML = `<i class="ti ti-alert-triangle"></i> 0 findings`;
      list.innerHTML = cur ? `<div class="empty-hint"><i class="ti ti-circle-check"></i>No phishing indicators detected by current heuristics.</div>` : `<div class="empty-hint"><i class="ti ti-scan"></i>Paste an email and scan to see findings.</div>`;
      return;
    }
    let high=0, med=0, low=0;
    for (const f of all) { const s=String(f.severity||'').toLowerCase(); if(s==='critical'||s==='high') high++; else if(s==='medium'||s==='suspicious') med++; else if(s==='low') low++; }
    const parts=[]; if(high) parts.push(`${high} high`); if(med) parts.push(`${med} medium`); if(low) parts.push(`${low} low`);
    title.innerHTML = `<i class="ti ti-alert-triangle"></i> ${all.length} finding${all.length===1?'':'s'}${parts.length?` — ${parts.join(', ')}`:''}${findings.length!==all.length?` (showing ${findings.length})`:''}`;
    if (!findings.length) { list.innerHTML = `<div class="empty-hint">No findings match the current filter.</div>`; return; }
    list.innerHTML = findings.map(f=>{
      const sev=String(f.severity||'Info'); const cls=(sev==='Critical'||sev==='High')?'high':(sev==='Medium'||sev==='Suspicious')?'med':'low';
      const sevCls=cls==='high'?'h':cls==='med'?'m':'l';
      const text=`${f.title||''} ${f.detail||''}`; const m=text.match(/https?:\/\/[^\s"'<>]+/i); const url=m?m[0]:'';
      return `<div class="finding-card ${cls}" data-copy="${esc(`[${sev} +${f.score}] ${f.title}: ${f.detail}`)}" title="Click to copy finding">
        <div class="finding-title"><span class="sev ${sevCls}">${esc(sev)}</span> ${esc(f.title||'')} <span class="hint-inline">(+${esc(f.score)})</span></div>
        <div class="finding-desc">${esc(f.detail||'')}</div>
        ${url ? `<div class="finding-url">${esc(state.defangObs?defangStr(url):url)}</div>` : ''}
      </div>`;
    }).join('');
    qsa('.finding-card', list).forEach(el=>el.addEventListener('click', async ()=>{ try{ await navigator.clipboard.writeText(el.dataset.copy||''); log('Finding copied.'); }catch{ log('Copy failed.'); } }));
  }

  async function addWhitelist(kind, value) {
    try {
      const data = await api('/api/whitelist/add', { method:'POST', body: JSON.stringify({ kind, value }) });
      log(data.message || (data.changed ? `Added ${kind} to whitelist.` : 'Whitelist unchanged.'));
      if ($('whitelistStatus')) $('whitelistStatus').textContent = data.validation || data.message || $('whitelistStatus').textContent;
      return data;
    } catch(e){ log(`Whitelist add failed: ${e.message}`); alert(e.message); }
  }

  function renderObservables() {
    const cur = state.current; const el = $('observablesList');
    if (!el) return;
    if (!cur) { el.innerHTML = `<div class="empty-hint">No observables yet.</div>`; return; }
    const obs = cur.result.observables || {};
    const groups = [['urls','URLs (active)','url'],['emails','Email addresses','email'],['ips','IP addresses','ip'],['domains','Domains','domain']];
    const wl = obs.whitelisted || {};
    let html = '';
    for (const [key,name,kind] of groups) {
      const items = obs[key]||[];
      html += `<div class="obs-group"><h4><span>${esc(name)} (${items.length})</span></h4>`;
      html += items.length ? items.map(v=>{
        const show = (key==='urls' && state.defangObs) ? defangStr(v) : v;
        return `<div class="obs-item"><span>${esc(show)}</span><span class="obs-actions">
          <button data-copy="${esc(String(v))}">Copy</button>
          <button data-wl-kind="${esc(kind)}" data-wl-val="${esc(String(v))}">Whitelist</button>
        </span></div>`;
      }).join('') : `<div class="obs-item" style="color:var(--text-muted)"><span>(none)</span></div>`;
      html += `</div>`;
    }
    const wsum = ['urls','emails','ips','domains'].map(k=>`${k}=${(wl[k]||[]).length}`).join(', ');
    html += `<div class="obs-group"><h4>Whitelisted (filtered)</h4><div class="obs-item"><span>${esc(wsum)}</span></div></div>`;
    el.innerHTML = html;
    qsa('[data-copy]', el).forEach(b=>b.addEventListener('click', async (e)=>{ e.stopPropagation(); try{ await navigator.clipboard.writeText(b.dataset.copy); log('Copied.'); }catch{} }));
    qsa('[data-wl-kind]', el).forEach(b=>b.addEventListener('click', async (e)=>{ e.stopPropagation(); await addWhitelist(b.dataset.wlKind, b.dataset.wlVal); }));
  }

  function categoryBarsHtml(cat={}) {
    const entries = Object.entries(cat || {}).sort((a,b)=> (b[1]||0)-(a[1]||0));
    if (!entries.length) return '<div class="hint-inline">No category data.</div>';
    const max = Math.max(10, ...entries.map(e=>Number(e[1])||0));
    return `<div class="cat-bars">` + entries.map(([k,v])=>{
      const n = Number(v)||0; const w = Math.max(0, Math.min(100, (n/max)*100));
      return `<div class="cat-bar-row"><div>${esc(k)}</div><div class="cat-bar-track"><div class="cat-bar-fill" style="width:${w}%"></div></div><div class="cat-bar-val">${n}</div></div>`;
    }).join('') + `</div>`;
  }

  function renderSummary() {
    const cur = state.current;
    if (!cur) {
      if ($('statRisk')) $('statRisk').textContent='--';
      if ($('statFindings')) $('statFindings').textContent='0';
      if ($('statUrls')) $('statUrls').textContent='0';
      if ($('statAttach')) $('statAttach').textContent='0';
      if ($('urlList')) $('urlList').innerHTML = `<div class="url-item"><div class="url-text">(no active URLs)</div></div>`;
      if ($('summaryExtra')) $('summaryExtra').innerHTML = 'No scan yet.';
      return;
    }
    const r = cur.result; const score=Number(r.score)||0; const findings=r.findings||[]; const urls=r.urls||[]; const attach=(r.metadata?.attachments||[]).length;
    $('statRisk').textContent=String(score); $('statRisk').className='stat-val '+(score>=40?'danger':'');
    $('statFindings').textContent=String(findings.length); $('statFindings').className='stat-val '+(findings.length?'danger':'');
    $('statUrls').textContent=String(urls.length);
    $('statAttach').textContent=String(attach); $('statAttach').className='stat-val '+(attach?'danger':'');
    const rec = (r.recommendations||[])[0];
    const cat = r.category_scores || {};
    $('summaryExtra').innerHTML = `<div>${esc(rec ? `Top action: ${rec}` : (r.summary || ''))}</div><div style="margin-top:6px;font-weight:600">Category risk</div>${categoryBarsHtml(cat)}`;
    if (!urls.length) $('urlList').innerHTML = `<div class="url-item"><div class="url-text">(no active URLs)</div></div>`;
    else $('urlList').innerHTML = urls.map(u=>{
      const ustr=String(u); const suspicious = score>=40 || /login|verify|secure|account|update|signin|password/i.test(ustr);
      const show = state.defangObs ? defangStr(ustr) : ustr;
      return `<div class="url-item" data-url="${esc(ustr)}" title="Click to copy URL"><div class="url-text">${esc(show)}</div><span class="url-badge ${suspicious?'url-sus':'url-safe'}">${suspicious?'Suspicious':'Active'}</span></div>`;
    }).join('');
    qsa('#urlList .url-item[data-url]').forEach(el=>el.addEventListener('click', async ()=>{ try{ await navigator.clipboard.writeText(el.dataset.url); log('URL copied.'); }catch{} }));
  }

  function renderDetails() {
    const cur = state.current; const el = $('detailsView');
    if (!el) return;
    if (!cur) { el.innerHTML = `<div class="empty-hint">No scan yet.</div>`; return; }
    const r = cur.result, c = cur.case, meta = r.metadata || {}, auth = r.auth_analysis || {}, sec = r.security_assessment || {}, cvss = sec.cvss_estimate || {};
    const fields = [
      ['Case ID', c?.case_id], ['Automated verdict', `${r.verdict} (${r.score}/100)`], ['Analyst verdict', c?.analyst_verdict || '(none)'],
      ['Source', cur.source], ['Subject', meta.subject], ['From', meta.from], ['Reply-To', meta.reply_to], ['Return-Path', meta.return_path],
      ['To', meta.to], ['Date', meta.date], ['Message-ID', meta.message_id], ['Received hops', meta.received_count],
      ['SPF (claim)', auth.spf], ['DKIM (claim)', auth.dkim], ['DMARC (claim)', auth.dmarc],
      ['Attachments', (meta.attachments||[]).join(', ') || 'None'], ['Attachment count', (meta.attachments||[]).length],
      ['URLs (active)', (r.urls||[]).length], ['ML', (r.ml_analysis||{}).label], ['ML phishing prob', r.ml_analysis?.phishing_probability != null ? `${Math.round(Number(r.ml_analysis.phishing_probability)*100)}%` : '--'],
      ['Evidence SHA-256', c?.evidence?.[0]?.sha256],
    ];
    const kv = fields.map(([k,v])=>`<div>${esc(k)}</div><div>${esc(v ?? '--')}</div>`).join('');
    const recs = (r.recommendations||[]).map(x=>`<li>${esc(x)}</li>`).join('') || '<li>None</li>';
    const timeline = (c?.timeline||[]).map(t=>`<li><b>${esc(t.event_type||'event')}</b> <span class="hint-inline">${esc(t.timestamp||'')}</span> — ${esc(t.message||'')}</li>`).join('') || '<li>No timeline events.</li>';
    el.innerHTML = `
      <div class="tool-card">
        <h4>Analyst actions</h4>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0;">
          <button class="action-btn report" id="detailConfirm" style="width:auto;padding:6px 10px;">Confirm phishing</button>
          <button class="action-btn" id="detailBenign" style="width:auto;padding:6px 10px;">Mark benign</button>
          <button class="action-btn" id="detailClearVerdict" style="width:auto;padding:6px 10px;">Clear verdict</button>
          <button class="action-btn" id="detailRescan" style="width:auto;padding:6px 10px;">Rescan source</button>
        </div>
        <textarea id="analystNote" class="note-area" placeholder="Analyst note...">${esc(c?.analyst_notes || '')}</textarea>
        <div style="margin-top:6px"><button class="action-btn" id="btnSaveNote" style="width:auto;padding:6px 10px;">Save note</button></div>
        <div class="hint-inline" style="margin-top:6px">Analyst verdict: <b>${esc(c?.analyst_verdict || '(none)')}</b></div>
      </div>
      <div class="tool-card"><h4>Category risk breakdown</h4>${categoryBarsHtml(r.category_scores||{})}</div>
      <div class="tool-card"><h4>Case & metadata</h4><div class="kv">${kv}</div></div>
      <div class="tool-card"><h4>Recommendations</h4><ul style="padding-left:18px;font-size:12px;color:var(--text-secondary);line-height:1.5">${recs}</ul></div>
      <div class="tool-card"><h4>Security assessment</h4>
        <div style="font-size:12px;color:var(--text-secondary);line-height:1.5">
          <div><b>CVSS triage:</b> ${esc(cvss.base_score ?? '--')} ${esc(cvss.severity||'')} ${esc(cvss.vector||'')}</div>
          <div><b>MITRE ATT&CK:</b> ${esc((sec.mitre_attack||[]).map(m=>m.id).join(', ') || '--')}</div>
          <div><b>CWE:</b> ${esc((sec.cwe||[]).map(x=>x.id).join(', ') || '--')}</div>
          <div class="hint-inline" style="margin-top:4px">${esc(cvss.note || (sec.notes||[]).join(' ') || '')}</div>
        </div></div>
      <div class="tool-card"><h4>Timeline</h4><ul style="padding-left:18px;font-size:12px;color:var(--text-secondary);line-height:1.5">${timeline}</ul></div>`;
    const setVerd = (v) => { if(!state.current) return; state.current.case.analyst_verdict = v; const now=new Date().toISOString(); (state.current.case.timeline = state.current.case.timeline||[]).push({event_type:'analyst_verdict', timestamp:now, message:`Analyst verdict set to ${v||'(cleared)'}`}); renderDetails(); renderHistory(); saveHistory(); log(`Analyst verdict: ${v||'cleared'}`); };
    $('detailConfirm').onclick=()=>setVerd('confirmed_phishing');
    $('detailBenign').onclick=()=>setVerd('marked_benign');
    $('detailClearVerdict').onclick=()=>setVerd(null);
    $('detailRescan').onclick=()=>runScan(state.current.content||$('sourceInput')?.value||'', state.current.source||'rescan');
    $('btnSaveNote').onclick=()=>{ if(!state.current) return; state.current.case.analyst_notes = $('analystNote').value; const now=new Date().toISOString(); (state.current.case.timeline = state.current.case.timeline||[]).push({event_type:'analyst_note', timestamp:now, message:'Analyst note updated'}); renderDetails(); saveHistory(); log('Analyst note saved.'); };
  }

  function historyFiltered() {
    const q = ($('historySearch')?.value || '').toLowerCase().trim();
    if (!q) return state.history.map((h,i)=>({h,i}));
    return state.history.map((h,i)=>({h,i})).filter(({h})=>{
      const r=h.result||{}; const txt = `${r.verdict||''} ${r.summary||''} ${(r.metadata||{}).subject||''} ${h.source||''} ${h.case?.analyst_verdict||''}`.toLowerCase();
      return txt.includes(q);
    });
  }

  function renderHistoryStats() {
    const el = $('historyStats'); if (!el) return;
    if (!state.history.length) { el.innerHTML = '<span class="hint-inline">No history yet. Scans you run will appear here (stored locally in this browser).</span>'; return; }
    const counts = { 'Low Risk':0, 'Suspicious':0, 'High Risk':0, 'Critical':0, other:0 };
    let sum=0; let high=0;
    state.history.forEach(h=>{ const r=h.result||{}; const v=r.verdict||''; if (counts[v] != null) counts[v]++; else counts.other++; sum += Number(r.score)||0; if ((Number(r.score)||0)>=40) high++; });
    const avg = Math.round(sum / state.history.length);
    el.innerHTML = `<div style="display:flex;gap:10px;flex-wrap:wrap;font-size:12px;color:var(--text-secondary)">
      <div><b>Total:</b> ${state.history.length}</div>
      <div><b>Avg score:</b> ${avg}</div>
      <div><b>Suspicious+:</b> ${high}</div>
      <div><b>Critical:</b> ${counts.Critical}</div>
      <div><b>High:</b> ${counts['High Risk']}</div>
      <div><b>Suspicious:</b> ${counts.Suspicious}</div>
      <div><b>Low:</b> ${counts['Low Risk']}</div>
    </div>`;
  }

  function renderHistory() {
    const el = $('historyView');
    if (!el) return;
    renderHistoryStats();
    const items = historyFiltered();
    if (!state.history.length) { el.innerHTML = `<div class="empty-hint">No scans in this session yet.</div>`; return; }
    if (!items.length) { el.innerHTML = `<div class="empty-hint">No history items match the filter.</div>`; return; }
    el.innerHTML = items.map(({h,i})=>{
      const r=h.result||{}; const cls=(Number(r.score)||0)>=70?'high':(Number(r.score)||0)>=40?'med':'low'; const sev=(Number(r.score)||0)>=70?'h':(Number(r.score)||0)>=40?'m':'l';
      return `<div class="batch-row" data-hidx="${i}">
        <div class="finding-title"><span class="sev ${sev}">${esc(r.verdict||'')}</span> ${esc(r.score)}/100 — ${esc((r.metadata||{}).subject || h.source || 'Scan')}</div>
        <div class="finding-desc">${esc(r.summary||'')}</div>
        <div class="hint-inline" style="margin-top:4px">Analyst: ${esc(h.case?.analyst_verdict||'(none)')} · Click to load · <button class="mini-btn" data-del-h="${i}">Delete</button></div>
      </div>`;
    }).join('');
    qsa('[data-hidx]', el).forEach(n=>n.addEventListener('click', (e)=>{
      if (e.target && e.target.closest('[data-del-h]')) return;
      const item = state.history[Number(n.dataset.hidx)]; if(item){ state.current=item; renderCurrent(); showTab('findings'); log('Loaded from history.'); }
    }));
    qsa('[data-del-h]', el).forEach(b=>b.addEventListener('click', (e)=>{ e.stopPropagation(); const i=Number(b.dataset.delH); state.history.splice(i,1); saveHistory(); renderHistory(); log('History item deleted.'); }));
  }

  function renderBatch() {
    const el = $('batchResults');
    if (!el) return;
    if (!state.batch.length) { el.innerHTML = `<div class="empty-hint">No batch results yet. Scan all samples or selected files.</div>`; return; }
    const ok = state.batch.filter(x=>x.ok);
    const hi = ok.filter(x=>Number(x.result?.score||0)>=40).length;
    el.innerHTML = `<div class="tool-card"><b>${state.batch.length}</b> scanned, <b>${ok.length}</b> ok, <b>${hi}</b> suspicious/high/critical.</div>` + state.batch.map((b,i)=>{
      if(!b.ok) return `<div class="batch-row"><div class="finding-title"><span class="sev h">Error</span> ${esc(b.name)}</div><div class="finding-desc">${esc(b.error||'Scan failed')}</div></div>`;
      const r=b.result; const sev=(Number(r.score)||0)>=70?'h':(Number(r.score)||0)>=40?'m':'l';
      return `<div class="batch-row" data-bidx="${i}"><div class="finding-title"><span class="sev ${sev}">${esc(r.verdict)}</span> ${esc(r.score)}/100 — ${esc(b.name)}</div><div class="finding-desc">${esc(r.summary||'')}</div></div>`;
    }).join('');
    qsa('[data-bidx]', el).forEach(n=>n.addEventListener('click', ()=>{ const item=state.batch[Number(n.dataset.bidx)]; if(item&&item.ok){ state.current={result:item.result, case:item.case, content:item.content||'', source:item.name}; renderCurrent(); showTab('findings'); log(`Loaded batch result: ${item.name}`);} }));
  }

  function renderCurrent() {
    const cur = state.current;
    if (!cur) { renderSummary(); renderFindings(); renderObservables(); renderDetails(); renderHistory(); return; }
    const { result, content } = cur;
    const meta = result.metadata || {};
    $('epRoute').textContent = `${meta.from || '(unknown sender)'} → ${meta.to || '(unknown recipient)'}`;
    $('epSubject').textContent = meta.subject || '(no subject)';
    $('epDate').textContent = meta.date || '(no date)';
    setVerdictPill(result.verdict, result.score);
    renderAuth(result.auth_analysis || {}, (meta.attachments||[]).length, result.ml_analysis || {});
    $('messageBody').textContent = extractBody(content) || '(No readable text body found in this message.)';
    if ($('sourceInput') && $('sourceInput').value !== (content||'')) $('sourceInput').value = content || '';
    renderFindings(); renderObservables(); renderSummary(); renderDetails(); renderHistory();
  }

  function extractBody(raw) {
    if (!raw) return '';
    const norm = String(raw).replace(/\r\n/g,'\n');
    const idx = norm.indexOf('\n\n');
    if (idx >= 0) return norm.slice(idx+2).trim().slice(0, 30000) || norm.slice(0, 30000);
    return norm.slice(0, 30000);
  }

  async function runScan(content, sourceLabel='pasted content') {
    const text = String(content||'');
    if (!text.trim()) { setStatus('No content to scan.'); return; }
    try {
      busy('Scanning...'); log(`Scanning (${sourceLabel})...`);
      const payload = { content: text, source: sourceLabel, enable_ml: $('mlToggle') ? $('mlToggle').checked : true, use_default_whitelist: true };
      const data = await api('/api/scan', { method:'POST', body: JSON.stringify(payload) });
      state.current = { result: data.result, case: data.case, content: text, source: sourceLabel };
      state.history.unshift(state.current);
      if (state.history.length > 50) state.history.pop();
      saveHistory();
      log(`Scan complete: ${data.result.verdict} ${data.result.score}/100 (${(data.result.findings||[]).length} findings)`);
      renderCurrent(); showTab('findings');
    } catch(e) { log(`Scan error: ${e.message}`); alert(`Scan failed: ${e.message}`); }
  }

  async function loadSamples() {
    try {
      const data = await api('/api/samples');
      const sel = $('sampleSelect');
      if (sel) sel.innerHTML = (data.samples||[]).map(s=>`<option value="${esc(s.name)}">Sample: ${esc(s.name)}</option>`).join('') || '<option value="">(no samples)</option>';
      try { const wl = await api('/api/whitelist'); if ($('whitelistStatus')) $('whitelistStatus').textContent = wl.message || wl.path || 'whitelist.json'; } catch {}
      if (!state.history.length) {
        const def = (data.samples||[]).find(s=>s.name.includes('phishing_with_auth_fail')) || (data.samples||[])[0];
        if (def && sel) { sel.value = def.name; await loadSelectedSample(true); }
      } else { renderCurrent(); renderHistory(); }
    } catch(e){ log(`Failed to load samples: ${e.message}`); }
  }

  async function loadSelectedSample(autoScan=false) {
    const name = $('sampleSelect')?.value; if(!name) return;
    try { log(`Loading sample ${name}...`); const data = await api(`/api/sample?name=${encodeURIComponent(name)}`);
      if ($('sourceInput')) $('sourceInput').value = data.content || ''; log(`Sample loaded: ${name}`); if(autoScan) await runScan(data.content||'', name);
    } catch(e){ log(`Failed to load sample: ${e.message}`); }
  }

  const allPanels = ['findings','observables','source','message','activity','details','history','batch','tools','help'];
  function showTab(tab) {
    state.currentTab = tab;
    qsa('#emailTabs .tab').forEach(t=>t.classList.toggle('active', t.dataset.tab===tab));
    ['findings','observables','source','message','activity'].forEach(t=>{ const p=$(`panel-${t}`); if(p) p.classList.toggle('hidden', t!==tab); });
    ['details','history','batch','tools','help'].forEach(v=>{ const p=$(`panel-${v}`); if(p) p.classList.add('hidden'); });
    state.view = ['findings','observables','source'].includes(tab) ? tab : 'scan';
    syncNav();
  }
  function showView(view) {
    state.view = view;
    allPanels.forEach(p=>{ const el=$(`panel-${p}`); if(el) el.classList.add('hidden'); });
    if (view==='scan' || view==='findings') { $('panel-findings')?.classList.remove('hidden'); qsa('#emailTabs .tab').forEach(t=>t.classList.toggle('active', t.dataset.tab==='findings')); state.currentTab='findings'; }
    else if (view==='observables') { $('panel-observables')?.classList.remove('hidden'); qsa('#emailTabs .tab').forEach(t=>t.classList.toggle('active', t.dataset.tab==='observables')); state.currentTab='observables'; }
    else if (view==='source') { $('panel-source')?.classList.remove('hidden'); qsa('#emailTabs .tab').forEach(t=>t.classList.toggle('active', t.dataset.tab==='source')); state.currentTab='source'; }
    else if (view==='details') $('panel-details')?.classList.remove('hidden');
    else if (view==='history') { $('panel-history')?.classList.remove('hidden'); renderHistory(); }
    else if (view==='batch') { $('panel-batch')?.classList.remove('hidden'); renderBatch(); }
    else if (view==='tools') $('panel-tools')?.classList.remove('hidden');
    else if (view==='help') $('panel-help')?.classList.remove('hidden');
    syncNav();
  }
  function syncNav() { qsa('.nav-item').forEach(n=>n.classList.toggle('active', n.dataset.view===state.view || (state.view==='scan' && n.dataset.view==='scan'))); }

  function download(filename, content, type='application/octet-stream') {
    const blob = new Blob([content], { type }); const a=document.createElement('a');
    a.href=URL.createObjectURL(blob); a.download=filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(()=>URL.revokeObjectURL(a.href), 1500);
  }

  async function exportJson() {
    if (!state.current) return alert('No scan result to export.');
    try { const res = await fetch('/api/scan/export', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({content: state.current.content||'', source: state.current.source, enable_ml:$('mlToggle')?.checked, format:'json'})}); const txt = await res.text(); download('phishguard_report.json', txt, 'application/json'); log('Exported JSON report.'); }
    catch { download('phishguard_report.json', JSON.stringify(state.current.result, null, 2), 'application/json'); log('Exported JSON (local).'); }
  }
  async function exportHtml() {
    if (!state.current) return alert('No scan result to export.');
    try { const res = await fetch('/api/scan/export', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({content: state.current.content||'', source: state.current.source, enable_ml:$('mlToggle')?.checked, format:'html'})}); const txt = await res.text(); download('phishguard_report.html', txt, 'text/html'); log('Exported HTML report.'); }
    catch(e){ alert('HTML export failed: '+e.message); }
  }
  function saveCase() { if(!state.current) return alert('No case to save.'); download('phishguard_case.json', JSON.stringify(state.current.case, null, 2), 'application/json'); log('Saved investigation case JSON.'); }
  function summaryText() {
    if (!state.current) return '';
    const r=state.current.result; return `PhishGuard: ${r.verdict} (${r.score}/100)\n${r.summary||''}\nFindings: ${(r.findings||[]).length}\nURLs: ${(r.urls||[]).length}\nRecommendations:\n${(r.recommendations||[]).map(x=>'- '+x).join('\n')}`;
  }
  async function copySummary() {
    if (!state.current) return alert('No scan result to copy.');
    const text=summaryText();
    try { await navigator.clipboard.writeText(text); log('Summary copied.'); } catch { download('summary.txt', text, 'text/plain'); log('Downloaded summary.'); }
  }
  async function copyMarkdown() {
    if (!state.current) return alert('No scan result to copy.');
    const r=state.current.result, meta=r.metadata||{}, sec=r.security_assessment||{}, cvss=sec.cvss_estimate||{};
    const md = [
      `# PhishGuard Scan Report`, ``,
      `- **Verdict:** ${r.verdict} (${r.score}/100)`,
      `- **Subject:** ${meta.subject||'(none)'}`,
      `- **From:** ${meta.from||'(unknown)'}`,
      `- **To:** ${meta.to||'(unknown)'}`,
      `- **SPF/DKIM/DMARC:** ${r.auth_analysis?.spf||'--'} / ${r.auth_analysis?.dkim||'--'} / ${r.auth_analysis?.dmarc||'--'} (header claims)`,
      `- **URLs:** ${(r.urls||[]).length} | **Attachments:** ${(meta.attachments||[]).length} | **Findings:** ${(r.findings||[]).length}`,
      `` , `## Summary`, r.summary || '', ``,
      `## Recommendations`, ...(r.recommendations||[]).map(x=>`- ${x}`), ``,
      `## Findings`, ...(r.findings||[]).map(f=>`- **[${f.severity} +${f.score}] ${f.title}:** ${f.detail}`), ``,
      `## Security assessment`, `- CVSS triage: ${cvss.base_score ?? '--'} ${cvss.severity||''} ${cvss.vector||''}`,
      `- MITRE ATT&CK: ${(sec.mitre_attack||[]).map(m=>m.id).join(', ')||'--'}`,
      `- CWE: ${(sec.cwe||[]).map(x=>x.id).join(', ')||'--'}`,
    ].join('\n');
    try { await navigator.clipboard.writeText(md); log('Markdown report copied.'); } catch { download('phishguard_report.md', md, 'text/markdown'); log('Downloaded Markdown report.'); }
  }

  async function scanAllSamples() {
    try {
      busy('Scanning all samples...'); log('Batch scan: scanning all samples...');
      const data = await api('/api/samples/scan_all', { method:'POST', body: JSON.stringify({ enable_ml: $('mlToggle')?.checked, use_default_whitelist: true }) });
      state.batch = [];
      for (const item of (data.results||[])) {
        let content = '';
        if (item.ok) { try { const s = await api(`/api/sample?name=${encodeURIComponent(item.name)}`); content = s.content||''; } catch {} }
        state.batch.push({ ...item, content });
      }
      state.batchReports = data;
      log(`Batch complete: ${state.batch.length} item(s).`);
      showView('batch'); renderBatch();
    } catch(e){ log(`Batch scan failed: ${e.message}`); alert(e.message); }
  }

  async function scanFiles(files) {
    const items = [];
    for (const f of files) { try { items.push({ name: f.name, content: await f.text() }); } catch {} }
    if (!items.length) return;
    if (items.length === 1) { if($('sourceInput')) $('sourceInput').value = items[0].content; await runScan(items[0].content, items[0].name); return; }
    try {
      busy(`Scanning ${items.length} files...`); log(`Batch scan: ${items.length} file(s)...`);
      const data = await api('/api/scan/batch', { method:'POST', body: JSON.stringify({ items, enable_ml: $('mlToggle')?.checked, use_default_whitelist: true, include_batch_report_json:true, include_batch_report_html:true }) });
      state.batch = (data.results||[]).map((r,i)=>({ ...r, content: (items[i]||{}).content || '' }));
      state.batchReports = { batch_report_json: data.batch_report_json, batch_report_html: data.batch_report_html };
      log(`Batch complete: ${state.batch.length} file(s).`);
      showView('batch'); renderBatch();
    } catch(e){ log(`Batch scan failed: ${e.message}`); alert(e.message); }
  }

  function applyDarkMode(on) {
    document.body.classList.toggle('dark', !!on);
    localStorage.setItem('pg_dark', on ? '1' : '0');
    if ($('btnDarkMode')) $('btnDarkMode').innerHTML = on ? '<i class="ti ti-sun"></i>' : '<i class="ti ti-moon"></i>';
  }

  async function sha256Hex(text) {
    const enc = new TextEncoder().encode(String(text||''));
    const buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  }
  function b64EncodeUtf8(str) { return btoa(unescape(encodeURIComponent(String(str||'')))); }
  function b64DecodeUtf8(b64) { return decodeURIComponent(escape(atob(String(b64||'').replace(/\s+/g,'')))); }
  function extractIocs(text) {
    const s = String(text||'');
    const urls = Array.from(new Set((s.match(/https?:\/\/[^\s"'<>]+/gi)||[])));
    const emails = Array.from(new Set((s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi)||[])));
    const ips = Array.from(new Set((s.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)||[])));
    const domains = Array.from(new Set((s.match(/\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+\b/gi)||[]))).filter(d=>!d.match(/^\d+\./));
    return { urls, emails, ips, domains };
  }

  function wire() {
    qsa('#emailTabs .tab').forEach(t=>t.addEventListener('click', ()=>showTab(t.dataset.tab)));
    qsa('.nav-item').forEach(n=>n.addEventListener('click', ()=>showView(n.dataset.view)));

    $('btnHelp').onclick = ()=>showView('help');
    $('btnRescan').onclick = ()=>runScan(($('sourceInput')?.value || state.current?.content || ''), state.current?.source || 'rescan');
    $('btnLoadSample').onclick = ()=>loadSelectedSample(true);
    $('btnScanAllSamples').onclick = scanAllSamples;
    $('btnScanSource').onclick = ()=>runScan($('sourceInput').value, 'source input');
    $('btnClearSource').onclick = ()=>{ $('sourceInput').value=''; $('sourceStatsBox').classList.add('hidden'); setStatus('Source cleared.'); };
    $('btnOpenFile').onclick = ()=>$('fileInput').click();
    $('fileInput').onchange = async (e)=>{ const files = Array.from(e.target.files||[]); if(files.length) await scanFiles(files); e.target.value=''; };
    $('btnPasteScan').onclick = async ()=>{
      try { const text = await navigator.clipboard.readText(); if(!text||!text.trim()) return alert('Clipboard is empty. Copy raw email source first (Gmail: Show original > Copy).'); $('sourceInput').value=text; await runScan(text,'clipboard'); }
      catch { showView('source'); showTab('source'); alert('Clipboard access unavailable. Paste into Source and click Scan source.'); }
    };
    $('btnPasteIntoSource').onclick = async ()=>{ try{ $('sourceInput').value = await navigator.clipboard.readText(); log('Pasted into source.'); }catch{ alert('Clipboard access unavailable.'); } };

    $('btnSourceStats').onclick = ()=>{
      const txt = $('sourceInput').value || '';
      const lines = txt ? txt.replace(/\r\n/g,'\n').split('\n').length : 0;
      const chars = txt.length; const words = (txt.trim().match(/\S+/g)||[]).length;
      const hdrEnd = txt.replace(/\r\n/g,'\n').indexOf('\n\n');
      const hdrCount = hdrEnd>0 ? (txt.slice(0,hdrEnd).match(/^[A-Za-z0-9-]+:/gm)||[]).length : 0;
      const box = $('sourceStatsBox');
      box.classList.remove('hidden');
      box.innerHTML = `<h4>Source stats</h4><div class="kv"><div>Characters</div><div>${chars}</div><div>Words</div><div>${words}</div><div>Lines</div><div>${lines}</div><div>Header fields (approx)</div><div>${hdrCount}</div><div>Looks like raw email</div><div>${/^(From:|Return-Path:|Delivered-To:|Received:|MIME-Version:)/im.test(txt) ? 'Yes' : 'Maybe not'}</div></div>`;
      log('Computed source stats.');
    };

    $('btnExportJson').onclick = exportJson; $('btnExportHtml').onclick = exportHtml; $('btnCopySummary').onclick = copySummary; $('btnCopyMarkdown').onclick = copyMarkdown; $('btnSaveCase').onclick = saveCase;
    $('btnReportPhishing').onclick = ()=>{ if(!state.current) return alert('Scan a message first.'); state.current.case.analyst_verdict='confirmed_phishing'; renderDetails(); renderHistory(); saveHistory(); log('Marked as phishing.'); };
    $('btnMarkBenign').onclick = ()=>{ if(!state.current) return alert('Scan a message first.'); state.current.case.analyst_verdict='marked_benign'; renderDetails(); renderHistory(); saveHistory(); log('Marked benign.'); };
    $('btnAddWhitelist').onclick = ()=>{ const url = (state.current?.result?.urls||[])[0]; if(!url) return alert('No active URL to whitelist. Use Observables to whitelist specific items.'); addWhitelist('url', url); };

    $('btnWhitelistInfo').onclick = async ()=>{ try{ const wl=await api('/api/whitelist'); $('whitelistStatus').textContent=wl.message||wl.path; log(`Whitelist: ${wl.message}`);}catch(e){log(e.message);} };
    $('btnWhitelistValidate').onclick = async ()=>{ try{ const wl=await api('/api/whitelist'); alert(wl.valid ? `Valid: ${wl.message}` : `Invalid: ${wl.message}`); }catch(e){alert(e.message);} };

    $('findingsSearch').oninput = renderFindings; $('findingsSeverity').onchange = renderFindings;
    $('defangToggle').onchange = (e)=>{ state.defangObs = e.target.checked; renderObservables(); renderSummary(); renderFindings(); };
    $('btnCopyAllObs').onclick = async ()=>{ const obs = state.current?.result?.observables||{}; const text = JSON.stringify(obs, null, 2); try{ await navigator.clipboard.writeText(text); log('Observables copied.'); }catch{} };
    $('btnCopySource').onclick = async ()=>{ try{ await navigator.clipboard.writeText($('sourceInput').value||''); log('Source copied.'); }catch{} };
    $('btnCopyBody').onclick = async ()=>{ try{ await navigator.clipboard.writeText($('messageBody').textContent||''); log('Message body copied.'); }catch{} };
    $('btnClearLog').onclick = ()=>{ state.logs=['Log cleared.']; $('activityLog').textContent = state.logs.join('\n'); };

    $('historySearch').oninput = renderHistory;
    $('btnClearHistory').onclick = ()=>{ if(confirm('Clear all scan history?')){ state.history=[]; saveHistory(); renderHistory(); log('History cleared.'); } };
    $('btnExportHistory').onclick = ()=>{ if(!state.history.length) return alert('No history to export.'); download('phishguard_history.json', JSON.stringify(state.history, null, 2), 'application/json'); log('Exported history.'); };

    $('btnBatchSamples').onclick = scanAllSamples;
    $('btnBatchFiles').onclick = ()=>$('batchFileInput').click();
    $('batchFileInput').onchange = async (e)=>{ const files=Array.from(e.target.files||[]); if(files.length) await scanFiles(files); e.target.value=''; };
    $('btnBatchExportJson').onclick = ()=>{ const j = state.batchReports?.batch_report_json || JSON.stringify({results: state.batch}, null, 2); download('phishguard_batch.json', typeof j==='string'?j:JSON.stringify(j,null,2), 'application/json'); log('Exported batch JSON.'); };
    $('btnBatchExportHtml').onclick = ()=>{ const h = state.batchReports?.batch_report_html; if(!h) return alert('Run a batch scan first (includes batch report).'); download('phishguard_batch.html', h, 'text/html'); log('Exported batch HTML.'); };

    $('btnCalcCvss').onclick = async ()=>{ try{ const d = await api('/api/cvss', {method:'POST', body: JSON.stringify({vector:$('cvssInput').value})}); $('cvssOutput').textContent = JSON.stringify(d.cvss || d, null, 2); log('CVSS calculated.'); }catch(e){ $('cvssOutput').textContent = `Error: ${e.message}`; } };
    $('btnDefang').onclick = async ()=>{ try{ const d = await api('/api/defang', {method:'POST', body: JSON.stringify({text:$('defangInput').value, mode:'defang'})}); $('defangOutput').textContent = d.output||''; }catch(e){ $('defangOutput').textContent = e.message; } };
    $('btnRefang').onclick = async ()=>{ try{ const d = await api('/api/defang', {method:'POST', body: JSON.stringify({text:$('defangInput').value, mode:'refang'})}); $('defangOutput').textContent = d.output||''; }catch(e){ $('defangOutput').textContent = e.message; } };
    $('btnCopyDefang').onclick = async ()=>{ try{ await navigator.clipboard.writeText($('defangOutput').textContent||''); log('Copied.'); }catch{} };

    $('btnB64Encode').onclick = ()=>{ try{ $('b64Output').textContent = b64EncodeUtf8($('b64Input').value||''); log('Base64 encoded.'); }catch(e){ $('b64Output').textContent = 'Error: '+e.message; } };
    $('btnB64Decode').onclick = ()=>{ try{ $('b64Output').textContent = b64DecodeUtf8($('b64Input').value||''); log('Base64 decoded.'); }catch(e){ $('b64Output').textContent = 'Error: invalid base64 or decode failure.'; } };
    $('btnCopyB64').onclick = async ()=>{ try{ await navigator.clipboard.writeText($('b64Output').textContent||''); log('Copied.'); }catch{} };

    $('btnHashText').onclick = async ()=>{ try{ const h = await sha256Hex($('hashInput').value||''); $('hashOutput').textContent = h; log('SHA-256 computed.'); }catch(e){ $('hashOutput').textContent = 'Error: '+e.message; } };
    $('btnHashSource').onclick = async ()=>{ try{ const src = $('sourceInput').value || state.current?.content || ''; const h = await sha256Hex(src); $('hashOutput').textContent = h || '(empty)'; log('SHA-256 of source computed.'); }catch(e){ $('hashOutput').textContent = 'Error: '+e.message; } };
    $('btnCopyHash').onclick = async ()=>{ try{ await navigator.clipboard.writeText($('hashOutput').textContent||''); log('Hash copied.'); }catch{} };

    $('btnExtractFromSource').onclick = ()=>{ const src = $('sourceInput').value || state.current?.content || ''; const iocs = extractIocs(src); $('iocOutput').textContent = JSON.stringify(iocs, null, 2); log(`Extracted IOCs: ${iocs.urls.length} URLs, ${iocs.emails.length} emails, ${iocs.ips.length} IPs, ${iocs.domains.length} domains.`); };
    $('btnCopyIocs').onclick = async ()=>{ try{ await navigator.clipboard.writeText($('iocOutput').textContent||''); log('IOCs copied.'); }catch{} };

    $('btnDarkMode').onclick = ()=>applyDarkMode(!document.body.classList.contains('dark'));

    // drag & drop
    let dragN = 0;
    const overlay = $('dropOverlay');
    window.addEventListener('dragenter', (e)=>{ e.preventDefault(); dragN++; overlay.classList.remove('hidden'); });
    window.addEventListener('dragleave', (e)=>{ e.preventDefault(); dragN=Math.max(0,dragN-1); if(dragN===0) overlay.classList.add('hidden'); });
    window.addEventListener('dragover', (e)=>e.preventDefault());
    window.addEventListener('drop', async (e)=>{ e.preventDefault(); dragN=0; overlay.classList.add('hidden'); const files=Array.from(e.dataTransfer?.files||[]).filter(f=>/\.(eml|txt|mail)$/i.test(f.name)||f.type.startsWith('text/')); if(files.length) await scanFiles(files); });

    // keyboard shortcuts
    document.addEventListener('keydown', (e)=>{
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key === 'Enter') { e.preventDefault(); runScan($('sourceInput').value, 'source input'); }
      else if (mod && (e.key === 'o' || e.key === 'O')) { e.preventDefault(); $('fileInput').click(); }
      else if (mod && (e.key === 'b' || e.key === 'B')) { e.preventDefault(); scanAllSamples(); }
      else if (mod && (e.key === 's' || e.key === 'S')) { e.preventDefault(); saveCase(); }
      else if (e.key === 'Escape') { setStatus(''); }
    });
  }

  loadHistory();
  applyDarkMode(localStorage.getItem('pg_dark') === '1');
  wire();
  showTab('findings');
  renderBatch();
  renderHistory();
  loadSamples();
})();