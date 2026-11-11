(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const state = {token:'', epoch:0, section:'evidence', q:'', filter:'', offset:0, limit:40, total:0, records:[], selected:'', listSeq:0, detailSeq:0};
  const requests = new Set();
  let searchTimer;
  const sections = {
    risks:{title:'Risk register',caption:'Likelihood, impact and treatment status',filter:'All statuses',columns:['Risk / owner','Title / asset','Score','Status'],empty:'No risks recorded yet',hint:'Registered risks will appear here with their treatment status and evidence links.'},
    controls:{title:'Control catalogue',caption:'Implementation status and supporting evidence',filter:'All statuses',columns:['Control / domain','Title / framework','Owner','Status'],empty:'No controls recorded',hint:'Controls in the GRC catalogue will appear here.'},
    evidence:{title:'Evidence library',caption:'Trace each record to its source and security incident',filter:'All sources',columns:['Evidence / source','Description / reference','Control','Collected'],empty:'No evidence records',hint:'Evidence synchronized from SOC incidents and human reviews will appear here.'},
    approvals:{title:'Human approvals',caption:'Requests and recorded decisions',filter:'All statuses',columns:['Approval / requester','Requested action','Reference','Status'],empty:'No approval requests',hint:'Approval requests will appear here. Recorded approval does not execute a response.'},
    audit:{title:'Audit trail',caption:'Recorded changes, actors and before / after snapshots',filter:'All actions',columns:['Time / actor','Action','Record','Type'],empty:'No audit events',hint:'Recorded GRC changes will appear in this audit trail.'}
  };
  function el(tag, text, cls) {const node=document.createElement(tag); if(text!==undefined)node.textContent=String(text); if(cls)node.className=cls; return node;}
  function pretty(value) {return String(value ?? '—').replace(/_/g,' ').replace(/^./,c=>c.toUpperCase());}
  function date(value) {if(!value)return '—'; const d=new Date(value); return Number.isNaN(d.valueOf())?String(value):d.toISOString().replace('T',' ').slice(0,19)+' UTC';}
  function message(text='', error=false) {$('grc-message').textContent=text; $('grc-message').hidden=!text; $('grc-message').classList.toggle('error',error);}
  function empty(target,title,hint='') {target.replaceChildren(el('strong',title),el('span',hint));}
  function tag(value) {const v=String(value||'unknown'); const cls=/^(implemented|approved|closed|accepted)$/.test(v)?'good':/^(rejected|Critical)$/.test(v)?'bad':/^(pending|not_assessed|in_progress|High|open)$/.test(v)?'warn':''; return el('span',pretty(v),'grc-tag '+cls);}
  function clearAccess(reason='') {
    state.epoch++; state.listSeq++; state.detailSeq++; state.token=''; state.records=[]; state.selected=''; state.total=0;
    state.q=''; state.filter=''; state.offset=0;
    requests.forEach(c=>c.abort()); requests.clear(); clearTimeout(searchTimer);
    $('grc-token').value=''; $('grc-content').hidden=true; $('grc-unlock').hidden=false;
    $('grc-refresh').hidden=true; $('grc-lock').hidden=true; $('grc-session').textContent='Locked'; $('grc-session').classList.remove('unlocked');
    $('grc-table-body').replaceChildren(); $('grc-detail').replaceChildren(); $('grc-page-label').textContent='—';
    ['risks','controls','evidence','approvals'].forEach(k=>$('grc-kpi-'+k).textContent='—');
    document.querySelectorAll('[data-grc-count]').forEach(n=>n.textContent='—');
    $('grc-progress-bar').style.width='0%'; $('grc-assessment-note').textContent='Assessment required'; $('grc-sync-time').textContent='—';
    $('grc-filter').replaceChildren(el('option','All statuses')); $('grc-search').value=''; message(reason,!!reason);
  }
  async function get(path, params={}) {
    const epoch=state.epoch, token=state.token;
    if(!token)throw new Error('Unlock GRC to view records.');
    const controller=new AbortController(); requests.add(controller);
    const timeout=setTimeout(()=>controller.abort(),20000);
    try {
      const query=new URLSearchParams(params).toString();
      const response=await fetch('/api/grc/workspace/'+path+(query?'?'+query:''),{headers:{'X-GRC-Token':token},cache:'no-store',signal:controller.signal});
      if(response.status===401 || response.status===403){if(epoch===state.epoch)clearAccess('Access token was not accepted. Enter a valid GRC token.');throw new Error('Access denied');}
      if(response.status===503)throw new Error('GRC access is not configured on this server.');
      if(response.status===404)throw new Error('This GRC record is no longer available.');
      if(!response.ok)throw new Error('Could not load GRC records (HTTP '+response.status+').');
      return await response.json();
    } finally {clearTimeout(timeout);requests.delete(controller);}
  }
  function showSummary(data) {
    $('grc-kpi-risks').textContent=data.open_risks.toLocaleString();
    $('grc-kpi-controls').textContent=data.implemented_controls+' / '+data.applicable_controls;
    $('grc-kpi-evidence').textContent=data.counts.evidence.toLocaleString();
    $('grc-kpi-approvals').textContent=data.pending_approvals.toLocaleString();
    $('grc-progress-bar').style.width=Math.max(0,Math.min(100,data.implementation_rate_percent))+'%';
    const unassessed=data.control_status_counts.not_assessed||0;
    $('grc-assessment-note').textContent=unassessed?unassessed+' controls await assessment':data.implementation_rate_percent+'% of applicable controls implemented';
    document.querySelectorAll('[data-grc-count]').forEach(node=>node.textContent=Number(data.counts[node.dataset.grcCount]||0).toLocaleString());
    $('grc-sync-time').textContent='Updated '+date(new Date().toISOString());
  }
  async function refresh() {
    if(!state.token)return;
    const epoch=state.epoch; $('grc-refresh').disabled=true; message();
    try{const data=await get('summary');if(epoch!==state.epoch)return;showSummary(data);await loadList();}
    catch(error){if(epoch===state.epoch)message(error.name==='AbortError'?'Request timed out. Try refreshing.':error.message,true);}
    finally{$('grc-refresh').disabled=false;}
  }
  function sectionUI() {
    const config=sections[state.section];
    $('grc-list-title').textContent=config.title; $('grc-list-caption').textContent=config.caption;
    $('grc-records').setAttribute('aria-labelledby','grc-tab-'+state.section);
    document.querySelectorAll('[data-grc-section]').forEach(node=>{const selected=node.dataset.grcSection===state.section;node.setAttribute('aria-selected',String(selected));node.tabIndex=selected?0:-1;});
    const tr=el('tr'); config.columns.forEach(text=>{const th=el('th',text);th.scope='col';tr.appendChild(th);}); $('grc-table-head').replaceChildren(tr);
  }
  window.showGrcRoute=(section='evidence',record='')=>{
    section=sections[section]?section:'evidence';
    const changed=state.section!==section || state.q!==record;
    state.section=section;
    if(changed){state.q=record;state.filter='';state.offset=0;state.selected='';}
    $('grc-search').value=state.q;sectionUI();
    if(state.token && (changed || !state.records.length))loadList();
  };
  function go(section,record=''){location.hash='grc/'+section+(record?'?record='+encodeURIComponent(record):'');}
  document.querySelectorAll('[data-grc-section]').forEach(button=>button.addEventListener('click',()=>go(button.dataset.grcSection)));
  function cells(record) {
    if(state.section==='risks')return [[record.id,record.owner||'Unassigned'],[record.title,record.asset||'No asset specified'],[record.inherent_score+' / 25',record.inherent_level],tag(record.status)];
    if(state.section==='controls')return [[record.id,record.domain],[record.title,record.framework],[record.owner||'Unassigned',''],tag(record.implementation_status)];
    if(state.section==='evidence')return [[record.id,pretty(record.source)],[record.description||'Evidence record',record.reference_id],[record.control_id||'—',record.risk_id||''],[date(record.collected_at),'']];
    if(state.section==='approvals')return [[record.id,record.requested_by],[record.requested_action,''],[record.reference_id,pretty(record.reference_type)],tag(record.status)];
    return [[date(record.created_at),record.actor],[pretty(record.action),''],[record.entity_id,''],tag(record.entity_type)];
  }
  function renderRows() {
    const fragment=document.createDocumentFragment();
    state.records.forEach(record=>{
      const row=el('tr'); row.dataset.recordId=record.id; row.classList.toggle('selected',record.id===state.selected);
      row.addEventListener('click',()=>selectRecord(record.id));
      cells(record).forEach((cell,index)=>{
        const td=el('td');
        if(cell instanceof Node)td.appendChild(cell);
        else{
          const main=el(index===0?'button':'span',cell[0],index===0?'grc-record-button':'grc-cell-title');
          if(index===0){main.type='button';main.setAttribute('aria-label','Inspect '+record.id);main.setAttribute('aria-pressed',String(record.id===state.selected));}
          td.appendChild(main);if(cell[1])td.appendChild(el('span',cell[1],'grc-cell-sub'));
        }
        row.appendChild(td);
      });fragment.appendChild(row);
    });$('grc-table-body').replaceChildren(fragment);
  }
  async function loadList() {
    if(!state.token)return;
    const seq=++state.listSeq,epoch=state.epoch;state.detailSeq++;
    $('grc-table-body').replaceChildren();$('grc-list-empty').hidden=false;empty($('grc-list-empty'),'Loading records…');
    $('grc-prev').disabled=true;$('grc-next').disabled=true;$('grc-records').setAttribute('aria-busy','true');
    $('grc-detail').replaceChildren(el('div','Loading the selected record…','grc-empty'));
    try{
      const params={offset:state.offset,limit:state.limit,q:state.q};if(state.filter)params.status=state.filter;
      const data=await get(state.section,params);if(seq!==state.listSeq || epoch!==state.epoch)return;
      state.records=data.items;state.total=data.total;
      if(state.offset>=data.total && state.offset>0){state.offset=Math.max(0,Math.floor((data.total-1)/state.limit)*state.limit);return loadList();}
      const config=sections[state.section], filter=$('grc-filter'); const first=el('option',config.filter);first.value='';filter.replaceChildren(first);
      data.status_options.forEach(value=>{const option=el('option',pretty(value));option.value=value;filter.appendChild(option);});filter.value=state.filter;
      $('grc-page-label').textContent=data.total?(state.offset+1)+'–'+(state.offset+data.items.length)+' of '+data.total.toLocaleString()+' records':'0 records';
      $('grc-prev').disabled=state.offset===0;$('grc-next').disabled=state.offset+data.items.length>=data.total;
      $('grc-list-empty').hidden=!!data.items.length;
      if(!data.items.length){state.selected='';empty($('grc-list-empty'),state.q||state.filter?'No matching records':config.empty,state.q||state.filter?'Try another search or filter.':config.hint);$('grc-detail').replaceChildren(el('div','Select a record to inspect its details and related incidents.','grc-empty'));}
      else{state.selected=data.items.some(x=>x.id===state.selected)?state.selected:data.items[0].id;renderRows();selectRecord(state.selected);}
      $('grc-table-scroll').scrollTop=0;
    }catch(error){if(seq===state.listSeq && epoch===state.epoch){state.records=[];empty($('grc-list-empty'),'Records could not be loaded','Refresh to try again.');$('grc-detail').replaceChildren();message(error.name==='AbortError'?'Request timed out. Try refreshing.':error.message,true);}}
    finally{if(seq===state.listSeq)$('grc-records').setAttribute('aria-busy','false');}
  }
  function link(section,id,label) {const a=el('a',label||id,'grc-link');a.href='#grc/'+section+'?record='+encodeURIComponent(id);return a;}
  function fields(parent,record,names) {
    const dl=el('dl');names.forEach(([key,label])=>{if(record[key]===undefined || record[key]===null || record[key]==='')return;const div=el('div');div.append(el('dt',label),el('dd',key.endsWith('_at')?date(record[key]):String(record[key])));dl.appendChild(div);});parent.appendChild(dl);
  }
  async function openIncident(event,id) {
    event.preventDefault();
    if(allIncidents.some(x=>x.case_id===id)){location.hash='soc/incident/'+encodeURIComponent(id);return;}
    const epoch=state.epoch;
    try{
      const response=await fetch('/api/incidents',{cache:'no-store'});if(!response.ok)throw new Error('Could not check the SOC incident store.');
      const data=await response.json();if(epoch!==state.epoch)return;
      if(data.incidents.some(x=>x.case_id===id)){location.hash='soc/incident/'+encodeURIComponent(id);location.reload();}
      else message('This incident is no longer available in SOC. Its GRC evidence is retained.');
    }catch(error){if(epoch===state.epoch)message(error.message,true);}
  }
  function renderDetail(data) {
    const record=data.record,target=$('grc-detail'); target.replaceChildren();
    target.append(el('div',pretty(state.section)+' / RECORD','grc-eyebrow'),el('h2',record.title||record.requested_action||record.description||pretty(record.action)||record.id),el('div',record.id,'grc-detail-id'));
    if(record.status||record.implementation_status||record.source)target.appendChild(tag(record.status||record.implementation_status||record.source));
    if(record.description && (record.title||record.requested_action))target.appendChild(el('p',record.description));
    fields(target,record,[['category','Category'],['asset','Asset'],['owner','Owner'],['domain','Domain'],['framework','Framework'],['framework_ref','Framework reference'],['review_frequency','Review frequency'],['likelihood','Likelihood / 5'],['impact','Impact / 5'],['inherent_score','Inherent risk score'],['inherent_level','Risk level'],['residual_score','Residual score'],['residual_level','Residual level'],['requested_by','Requested by'],['decided_by','Decided by'],['collected_by','Collected by'],['actor','Actor'],['action','Action'],['reference_type','Reference type'],['reference_id','Reference ID'],['entity_type','Record type'],['entity_id','Record ID'],['collected_at','Collected'],['created_at','Created'],['updated_at','Updated'],['decided_at','Decided']]);
    [['treatment','Treatment'],['decision_note','Decision note'],['reason','Reason']].forEach(([key,label])=>{if(record[key])target.append(el('h3',label),el('p',record[key]));});
    const refs=[];
    if(record.risk_id)refs.push(link('risks',record.risk_id));if(record.control_id)refs.push(link('controls',record.control_id));
    data.linked_controls.forEach(c=>refs.push(link('controls',c.id,c.id+' · '+c.title)));
    if(state.section==='audit' || state.section==='approvals'){
      const kind=record.entity_type||record.reference_type,id=record.entity_id||record.reference_id,section={risk:'risks',control:'controls',control_change:'controls',evidence:'evidence',approval:'approvals'}[kind];
      if(section&&id)refs.push(link(section,id));
    }
    if(refs.length)target.append(el('h3','Linked GRC records'),...refs);
    const related=data.related_incidents;target.appendChild(el('h3','Related SOC incidents · '+related.total));
    if(!related.ids.length)target.appendChild(el('p','No incident references are attached to this record or its linked evidence.'));
    related.ids.forEach(id=>{const a=el('a',id,'grc-link');a.href='#soc/incident/'+encodeURIComponent(id);a.addEventListener('click',event=>openIncident(event,id));a.appendChild(el('small','Open incident investigation ↗'));target.appendChild(a);});
    if(related.total>related.limit){const pager=el('div',undefined,'grc-related-pages'),prev=el('button','Previous','grc-button'),next=el('button','Next','grc-button');prev.disabled=related.offset===0;next.disabled=related.offset+related.ids.length>=related.total;prev.onclick=()=>selectRecord(record.id,Math.max(0,related.offset-related.limit));next.onclick=()=>selectRecord(record.id,related.offset+related.limit);pager.append(prev,el('span',(related.offset+1)+'–'+(related.offset+related.ids.length)+' of '+related.total),next);target.appendChild(pager);}
    [['metadata','Evidence metadata'],['before','Before change'],['after','After change']].forEach(([key,label])=>{if(record[key]){const details=el('details');details.append(el('summary',label),el('pre',JSON.stringify(record[key],null,2)));target.appendChild(details);}});
    if(record.sha256){const details=el('details');details.append(el('summary','Evidence fingerprint (SHA-256)'),el('pre',record.sha256));target.appendChild(details);}
    if(state.section==='approvals')target.appendChild(el('p','Approval records document human decisions. They do not execute containment.'));
  }
  async function selectRecord(id,incidentOffset=0) {
    if(!state.token)return;const seq=++state.detailSeq,epoch=state.epoch;state.selected=id;renderRows();
    $('grc-detail').replaceChildren(el('div','Loading record…','grc-empty'));
    try{const data=await get(state.section+'/'+encodeURIComponent(id),{incident_offset:incidentOffset});if(seq!==state.detailSeq||epoch!==state.epoch)return;renderDetail(data);$('grc-detail').scrollTop=0;}
    catch(error){if(seq===state.detailSeq&&epoch===state.epoch){$('grc-detail').replaceChildren(el('div',error.message,'grc-empty'));}}
  }
  $('grc-access-form').addEventListener('submit',async event=>{
    event.preventDefault();const token=$('grc-token').value.trim();if(!token){message('Enter your GRC access token.',true);return;}
    state.token=token;const epoch=++state.epoch;$('grc-token').value='';$('grc-unlock-button').disabled=true;message();
    try{const data=await get('summary');if(epoch!==state.epoch)return;showSummary(data);$('grc-unlock').hidden=true;$('grc-content').hidden=false;$('grc-refresh').hidden=false;$('grc-lock').hidden=false;$('grc-session').textContent='GRC unlocked';$('grc-session').classList.add('unlocked');await loadList();}
    catch(error){if(epoch===state.epoch){clearAccess();message(error.name==='AbortError'?'Connection timed out. Try again.':error.message,true);}}
    finally{$('grc-unlock-button').disabled=false;}
  });
  $('grc-lock').onclick=()=>clearAccess();$('grc-refresh').onclick=refresh;
  $('grc-search').addEventListener('input',()=>{clearTimeout(searchTimer);searchTimer=setTimeout(()=>{state.q=$('grc-search').value.trim();state.offset=0;state.selected='';loadList();},250);});
  $('grc-filter').addEventListener('change',()=>{state.filter=$('grc-filter').value;state.offset=0;state.selected='';loadList();});
  $('grc-prev').onclick=()=>{state.offset=Math.max(0,state.offset-state.limit);loadList();};$('grc-next').onclick=()=>{state.offset+=state.limit;loadList();};
  document.querySelector('.grc-nav').addEventListener('keydown',event=>{
    const buttons=[...document.querySelectorAll('[data-grc-section]')],index=buttons.indexOf(document.activeElement);
    if(index<0||!['ArrowLeft','ArrowRight','Home','End'].includes(event.key))return;event.preventDefault();
    const next=event.key==='Home'?0:event.key==='End'?buttons.length-1:(index+(event.key==='ArrowRight'?1:-1)+buttons.length)%buttons.length;buttons[next].focus();buttons[next].click();
  });
  sectionUI();
})();
