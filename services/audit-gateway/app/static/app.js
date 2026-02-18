const out = document.getElementById('out');
const apiBase = location.origin; // same host

function log(obj){
  out.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

async function call(path, opts={}){
  const res = await fetch(`${apiBase}${path}`, {
    headers: {'Content-Type':'application/json', ...(opts.headers||{})},
    ...opts,
  });
  const txt = await res.text();
  let data;
  try{ data = JSON.parse(txt); } catch { data = txt; }
  if(!res.ok){
    throw new Error(`HTTP ${res.status}: ${typeof data==='string'?data:JSON.stringify(data)}`);
  }
  return data;
}

async function runScenario(){
  // Minimal "site" scenario: two workers, one hazard-entry, one near-miss.
  const events = [
    {event_type:'worker_position', site_id:'SITE-01', worker_id:'W-001', ts:new Date().toISOString(), payload:{x:12.1,y:7.4,zone:'Z-A'}},
    {event_type:'hazard_entry', site_id:'SITE-01', worker_id:'W-001', ts:new Date().toISOString(), payload:{zone:'Z-H1',hazard:'restricted_area'}},
    {event_type:'near_miss', site_id:'SITE-01', worker_id:'W-002', ts:new Date().toISOString(), payload:{hazard:'struck_by',distance_m:1.3,asset_id:'FORKLIFT-2'}},
  ];
  const results=[];
  for(const e of events){
    results.push(await call('/events', {method:'POST', body: JSON.stringify(e)}));
  }
  return {submitted: results};
}

document.getElementById('btnScenario').onclick = async () => {
  try{
    log('Running scenario...');
    const r = await runScenario();
    log(r);
  } catch(e){ log(String(e)); }
};

document.getElementById('btnFlush').onclick = async () => {
  try{
    log('Flushing...');
    const r = await call('/batches/close', {method:'POST'});
    log(r);
  } catch(e){ log(String(e)); }
};

document.getElementById('btnLatest').onclick = async () => {
  try{
    const r = await call('/batches?limit=10');
    log(r);
  } catch(e){ log(String(e)); }
};

document.getElementById('btnVerify').onclick = async () => {
  const id = document.getElementById('batchId').value.trim();
  if(!id){ log('Please provide a batch_id.'); return; }
  try{
    const r = await call(`/verify/batch/${encodeURIComponent(id)}`);
    log(r);
  } catch(e){ log(String(e)); }
};

document.getElementById('btnSendEvent').onclick = async () => {
  try{
    const e = {event_type:'hazard_entry', site_id:'SITE-01', worker_id:'W-003', ts:new Date().toISOString(), payload:{zone:'Z-H2',hazard:'restricted_area'}};
    const r = await call('/events', {method:'POST', body: JSON.stringify(e)});
    log({submitted:r, event:e});
  } catch(e){ log(String(e)); }
};
