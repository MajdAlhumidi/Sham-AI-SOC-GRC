(() => {
  'use strict';
  const $=id=>document.getElementById(id), el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;};
  const s={token:'',epoch:0,seq:0,detailSeq:0,evidenceSeq:0,section:'cases',q:'',band:'',offset:0,total:0,selected:'',items:[],assets:[],changes:[],auditOffset:0,contextSeq:0};
  const requests=new Set();let searchTimer;
  const date=(v,legacy=false)=>{if(!v)return 'Time unavailable';let text=String(v);if(!/(Z|[+-]\d{2}:?\d{2})$/.test(text)){if(!legacy)return text+' · timezone unavailable';text+='Z';}const d=new Date(text);return Number.isNaN(d.valueOf())?String(v):d.toISOString().replace('T',' ').slice(0,19)+' UTC';};
  const chip=(value)=>el('span',value,'iw-chip '+String(value).toLowerCase());
  const msg=(text='',error=false)=>{$('iw-message').textContent=text;$('iw-message').hidden=!text;$('iw-message').classList.toggle('error',error);};
  function lock(reason=''){
    s.token='';s.epoch++;s.seq++;s.detailSeq++;s.evidenceSeq++;s.contextSeq++;
    requests.forEach(c=>c.abort());requests.clear();clearTimeout(searchTimer);
    s.items=[];s.assets=[];s.changes=[];s.selected='';s.offset=0;s.auditOffset=0;
    $('iw-content').hidden=true;$('iw-unlock').hidden=false;$('iw-lock').hidden=true;$('iw-refresh').hidden=true;$('iw-token').value='';$('iw-session').textContent='Locked';
    ['iw-case-list','iw-detail','iw-audit-list','iw-evidence-body','iw-asset','iw-change-asset','iw-change-select'].forEach(id=>$(id).replaceChildren());
    $('iw-asset-form').reset();$('iw-change-form').reset();$('iw-evidence-dialog').close();msg(reason,!!reason);
  }
  async function api(path,options={}){
    if(!s.token)throw new Error('Unlock investigations first.');
    const epoch=s.epoch,controller=new AbortController();requests.add(controller);const timer=setTimeout(()=>controller.abort(),20000);
    try{
      const response=await fetch('/api/investigations/'+path,{...options,headers:{'X-GRC-Token':s.token,'Content-Type':'application/json'},cache:'no-store',signal:controller.signal});
      if(response.status===401||response.status===403){if(epoch===s.epoch)lock('Access token was not accepted.');throw new Error('Access denied');}
      const data=await response.json();
      if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:response.status===422?'Check exact identifiers and dates. Approval must precede a window of at most seven days.':'Request failed (HTTP '+response.status+').');
      if(epoch!==s.epoch)throw new DOMException('Session changed','AbortError');
      return data;
    }finally{clearTimeout(timer);requests.delete(controller);}
  }
  const guarded=fn=>async(...args)=>{try{await fn(...args);}catch(e){if(s.token)msg(e.name==='AbortError'?'Request timed out or was cancelled. Refresh to retry.':e.message,true);}};
  function sectionUI(){
    ['cases','context','audit'].forEach(k=>$('iw-'+k).hidden=s.section!==k);
    document.querySelectorAll('[data-iw-section]').forEach(b=>{b.classList.toggle('active',b.dataset.iwSection===s.section);b.setAttribute('aria-current',b.dataset.iwSection===s.section?'page':'false');});
  }
  window.showInvestigationRoute=guarded(async()=>{
    const hash=location.hash.slice(1),parts=hash.split('/');s.section=['context','audit'].includes(parts[1])?parts[1]:'cases';sectionUI();
    if(!s.token)return;
    if(s.section==='context')return loadContext();
    if(s.section==='audit')return loadAudit();
    await loadCases();
    if(parts[1]==='incident'&&parts[2]){const epoch=s.epoch,data=await api('incidents/'+encodeURIComponent(decodeURIComponent(parts[2])));if(epoch===s.epoch)await selectCase(data.case_id);}
    else if(parts[1]==='case'&&parts[2])await selectCase(decodeURIComponent(parts[2]));
  });
  document.querySelectorAll('[data-iw-section]').forEach(b=>b.onclick=()=>location.hash='investigations/'+b.dataset.iwSection);
  async function loadCases(){
    const seq=++s.seq,epoch=s.epoch;msg();
    const data=await api('cases?'+new URLSearchParams({q:s.q,band:s.band,offset:s.offset,limit:30}));
    if(seq!==s.seq||epoch!==s.epoch)return;
    s.items=data.items;s.total=data.total;
    Object.entries(data.summary).forEach(([k,v])=>$('iw-count-'+k).textContent=v.toLocaleString());
    $('iw-total').textContent=s.total.toLocaleString();$('iw-page').textContent=s.total?(s.offset+1)+'–'+Math.min(s.offset+30,s.total)+' / '+s.total:'0 cases';
    $('iw-prev').disabled=s.offset===0;$('iw-next').disabled=s.offset+30>=s.total;
    rows();
    if(s.selected)await selectCase(s.selected);
    else if(s.items.length)await selectCase(s.items[0].id);
    else $('iw-detail').replaceChildren(el('p','No matching investigations. Original incidents remain in the SOC tab.','iw-empty'));
  }
  function rows(){
    const list=$('iw-case-list');list.replaceChildren();
    if(!s.items.length){list.append(el('p','No investigations match this view.','iw-empty'));return;}
    s.items.forEach(x=>{const b=el('button',undefined,'iw-case'+(s.selected===x.id?' selected':''));b.type='button';b.setAttribute('aria-label','Inspect investigation '+x.id);b.setAttribute('aria-pressed',String(s.selected===x.id));
      const top=el('div',undefined,'iw-case-top');top.append(el('span',x.id,'iw-case-meta mono'),chip(x.priority.band));
      b.append(top,el('div',x.title,'iw-case-title'),el('div',x.asset.name+' · '+x.count+' incident'+(x.count===1?'':'s')+(x.legacy?' · archive':''),'iw-case-meta'),el('div',date(x.last_time,x.legacy),'iw-case-meta'));b.onclick=()=>location.hash='investigations/case/'+encodeURIComponent(x.id);list.append(b);});
  }
  function link(text,hash){const a=el('a',text,'iw-link');a.href='#'+hash;return a;}
  async function selectCase(id){
    const seq=++s.detailSeq,epoch=s.epoch;s.selected=id;rows();$('iw-detail').replaceChildren(el('p','Loading investigation…','iw-empty'));
    const data=await api('cases/'+encodeURIComponent(id));if(seq!==s.detailSeq||epoch!==s.epoch)return;detail(data);
  }
  function detail(data){
    const root=$('iw-detail');root.replaceChildren();
    const head=el('div',undefined,'iw-detail-head');head.append(el('h2',data.id),chip(data.priority.band+' · '+data.priority.score));root.append(head,el('p',data.title,'iw-detail-title'));
    const meta=el('div',undefined,'iw-chips');meta.append(chip(data.count+' original incident'+(data.count===1?'':'s')),chip(data.legacy?'Archive · evidence incomplete':'Source events captured'));if(!data.asset.id.startsWith('unresolved:'))meta.append(link('Edit asset context ↗','investigations/context'));root.append(meta);
    root.append(el('p','Owner: '+(data.asset.owner||'Unassigned')+' · Service: '+(data.asset.service||'Unassessed'),'iw-muted'));
    const priority=el('details',undefined,'iw-priority');priority.append(el('summary','Why this priority? · '+data.priority.score+'/100'));const reasons=el('ul');data.priority.reasons.forEach(r=>reasons.append(el('li',r)));priority.append(reasons,el('p',data.priority.basis+' '+data.priority.policy,'iw-muted'));root.append(priority);
    const tickets=[...new Set(data.priority.change_matches.map(x=>x.ticket))];if(tickets.length)priority.append(el('p','Matching approval references: '+tickets.join(', ')+' · '+data.priority.change_matches.length+' matching incidents.','iw-muted'));
    root.append(el('h3','Observed relationships'));
    const graph=el('div',undefined,'iw-graph');graph.setAttribute('role','group');graph.setAttribute('aria-label','Observed source, target asset and account relationships');
    [['Source address',data.relationships.source||'Unavailable'],['Target asset',data.relationships.asset],['Account',data.relationships.account||'Unavailable']].forEach(([label,value],i)=>{if(i)graph.append(el('span','—','iw-edge'));const node=el('div',undefined,'iw-node');node.append(el('span',label),el('strong',value));graph.append(node);});root.append(graph,el('p',data.relationships.meaning,'iw-muted'));
    root.append(el('h3','Timeline & evidence · newest first'));
    const timeline=el('ol',undefined,'iw-timeline'),pager=el('div',undefined,'iw-pager');root.append(timeline,pager);
    let offset=Math.max(0,data.events.length-10);
    function page(){timeline.replaceChildren();data.events.slice(offset,offset+10).reverse().forEach((event,n)=>timeline.append(eventCard(event,n===0)));pager.replaceChildren();const prev=el('button','Earlier','iw-button'),next=el('button','Later','iw-button');prev.disabled=offset===0;next.disabled=offset+10>=data.events.length;prev.onclick=()=>{offset=Math.max(0,offset-10);page();};next.onclick=()=>{offset+=10;page();};pager.append(prev,el('span',(offset+1)+'–'+Math.min(offset+10,data.events.length)+' / '+data.events.length),next);}
    page();
  }
  function evidenceButton(id,ref){const b=el('button',ref,'iw-ref');b.type='button';b.setAttribute('aria-label','Inspect evidence '+ref+' for '+id);b.onclick=()=>showEvidence(id,ref);return b;}
  function reportWithLinks(text,id){const pre=el('div',undefined,'iw-report');const re=/\[(?:A1|T\d+)(?:,\s*(?:A1|T\d+))*\]/g;let last=0;for(const match of text.matchAll(re)){pre.append(document.createTextNode(text.slice(last,match.index)));match[0].slice(1,-1).split(/,\s*/).forEach(ref=>pre.append(evidenceButton(id,ref)));last=match.index+match[0].length;}pre.append(document.createTextNode(text.slice(last)));return pre;}
  function eventCard(e,opened){
    const item=el('li',undefined,'iw-event');item.append(el('h4',e.incident_id),el('p',date(e.event_time,e.time_basis==='report_created_utc')+(e.time_basis==='report_created_utc'?' · report creation time':' · source event time'),'iw-muted'),el('p',e.join_reason,'iw-muted'));
    const links=el('div',undefined,'iw-chips');links.append(link('Open SOC report ↗','soc/incident/'+encodeURIComponent(e.incident_id)),link('Related GRC evidence ↗','grc/evidence?record='+encodeURIComponent(e.incident_id)));item.append(links);
    const content=el('details');content.open=opened;content.append(el('summary','Findings, source evidence & limitations'));
    if(!e.findings.length)content.append(el('p','Archived narrative: factual findings cannot be verified against original evidence here.','iw-muted'));
    e.findings.forEach(f=>{const box=el('div',undefined,'iw-finding');box.append(el('p',f.observation),el('p',f.citation_status==='available_for_review'?'Evidence references available · analyst validation required':'Evidence missing or tool failed · do not treat as verified','iw-muted'));f.evidence.forEach(ref=>box.append(evidenceButton(e.incident_id,ref)));content.append(box);});
    content.append(el('h3','Recorded evidence'));e.evidence.forEach(ref=>{const wrap=el('span');wrap.append(evidenceButton(e.incident_id,ref.ref),el('span',ref.source+' · '+ref.status+' ','iw-muted'));content.append(wrap);});
    content.append(el('h3','Unresolved / missing evidence'));const gaps=el('ul',undefined,'iw-limitations');(e.limitations.length?e.limitations:['No additional limitations were recorded; this does not establish completeness.']).forEach(x=>gaps.append(el('li',x)));content.append(gaps);
    const report=el('details');report.append(el('summary','Original investigation report'),reportWithLinks(e.report,e.incident_id));content.append(report);item.append(content);return item;
  }
  const showEvidence=guarded(async(id,ref)=>{
    const seq=++s.evidenceSeq,dialog=$('iw-evidence-dialog');$('iw-evidence-title').textContent=ref+' · '+id;$('iw-evidence-body').replaceChildren(el('p','Loading original evidence…'));if(!dialog.open)dialog.showModal();
    try{const d=await api('evidence/'+encodeURIComponent(id)+'/'+encodeURIComponent(ref));if(seq!==s.evidenceSeq||!s.token)return;
      const body=$('iw-evidence-body');body.replaceChildren(el('p',d.integrity_ok?'Stored evidence fingerprint verified. This verifies stored bytes, not the truth of the source.':'Integrity check failed. Do not rely on this evidence.','iw-note'),el('p','SHA-256 · '+d.sha256,'iw-fingerprint'),el('p','Source: '+d.record.source+' · Status: '+d.record.status+' · Captured: '+date(d.record.captured_at),'iw-muted'));
      if(d.record.truncated||d.record.capture_limit)body.append(el('p',d.record.truncated?'Tool response was truncated at capture. '+d.record.capture_limit:d.record.capture_limit,'iw-muted'));
      body.append(el('pre',JSON.stringify(d.record,null,2)));
    }catch(error){if(seq===s.evidenceSeq&&s.token)$('iw-evidence-body').replaceChildren(el('p',error.message,'iw-message error'));}
  });
  $('iw-evidence-close').onclick=()=>{$('iw-evidence-dialog').close();s.evidenceSeq++;};
  function options(target,items,value,label){target.replaceChildren();items.forEach(x=>{const o=el('option',label(x));o.value=value(x);target.append(o);});}
  async function loadContext(){
    const seq=++s.contextSeq,oldAsset=$('iw-asset').value,oldChange=$('iw-change-select').value;
    const d=await api('context');if(seq!==s.contextSeq)return;s.assets=d.assets;s.changes=d.changes;
    ['iw-asset','iw-change-asset'].forEach(id=>options($(id),s.assets,x=>x.id,x=>x.name+' · '+x.id));
    if(s.assets.some(x=>x.id===oldAsset))$('iw-asset').value=oldAsset;
    options($('iw-change-select'),[{id:'',ticket:'Create a change record'},...s.changes],x=>x.id,x=>x.ticket+(x.status?' · '+x.status:''));
    if(s.changes.some(x=>x.id===oldChange))$('iw-change-select').value=oldChange;
    assetForm();changeForm();$('iw-timezone').textContent='Enter dates in your local timezone: '+Intl.DateTimeFormat().resolvedOptions().timeZone+'. Stored as UTC.';
    if(!s.assets.length)msg('No observed assets yet. New ingested incidents will populate the registry.');
  }
  function assetForm(){const a=s.assets.find(x=>x.id===$('iw-asset').value);if(!a)return;$('iw-asset-identity').textContent=a.id+' · '+(a.address||'Address unavailable')+' · revision '+a.revision;['owner','service','criticality','sensitivity'].forEach(k=>$('iw-'+k).value=a[k]);}
  const localTime=v=>{if(!v)return '';const d=new Date(v);return new Date(d-d.getTimezoneOffset()*60000).toISOString().slice(0,16);};
  function changeForm(){const c=s.changes.find(x=>x.id===$('iw-change-select').value);const map={'ticket':'ticket','approved-by':'approved_by','change-description':'description','rule-id':'rule_id','source-ip':'source_ip','account':'account'};Object.entries(map).forEach(([id,key])=>$('iw-'+id).value=c?.[key]||'');['start','end','approved-at'].forEach(id=>$('iw-'+id).value=localTime(c?.[id.replace('-','_')]));$('iw-change-status').value=c?.status||'approved';if(c)$('iw-change-asset').value=c.asset_id;}
  $('iw-asset').onchange=assetForm;$('iw-change-select').onchange=changeForm;
  $('iw-asset-form').onsubmit=guarded(async event=>{
    event.preventDefault();const a=s.assets.find(x=>x.id===$('iw-asset').value);if(!a)return;const body={revision:a.revision};['owner','service','criticality','sensitivity'].forEach(k=>body[k]=$('iw-'+k).value.trim());
    const button=event.submitter;button.disabled=true;try{await api('assets/'+encodeURIComponent(a.id),{method:'PUT',body:JSON.stringify(body)});await loadContext();msg('Asset profile saved. Case priorities use this context on refresh.');}finally{button.disabled=false;}
  });
  $('iw-change-form').onsubmit=guarded(async event=>{
    event.preventDefault();const existing=s.changes.find(x=>x.id===$('iw-change-select').value),id=existing?.id||'CHG-'+crypto.randomUUID();
    const body={id,revision:existing?.revision||0,asset_id:$('iw-change-asset').value,ticket:$('iw-ticket').value.trim(),approved_by:$('iw-approved-by').value.trim(),description:$('iw-change-description').value.trim(),rule_id:$('iw-rule-id').value.trim(),source_ip:$('iw-source-ip').value.trim(),account:$('iw-account').value.trim(),status:$('iw-change-status').value};
    ['start','end','approved-at'].forEach(k=>body[k.replace('-','_')]=new Date($('iw-'+k).value).toISOString());
    const button=event.submitter;button.disabled=true;try{await api('changes/'+encodeURIComponent(id),{method:'PUT',body:JSON.stringify(body)});await loadContext();$('iw-change-select').value=id;changeForm();msg('Change context saved with an audit record. No alert was suppressed and no response action was executed.');}finally{button.disabled=false;}
  });
  async function loadAudit(){const seq=++s.contextSeq,data=await api('audit?offset='+s.auditOffset);if(seq!==s.contextSeq)return;const root=$('iw-audit-list');root.replaceChildren();data.items.forEach(x=>{const d=el('details');d.append(el('summary',date(x.at)+' · '+x.action+' · '+x.reference),el('pre',JSON.stringify({before:JSON.parse(x.before_json),after:JSON.parse(x.after_json)},null,2)));root.append(d);});$('iw-audit-page').textContent=data.total?(s.auditOffset+1)+'–'+Math.min(s.auditOffset+40,data.total)+' / '+data.total:'No records';$('iw-audit-prev').disabled=s.auditOffset===0;$('iw-audit-next').disabled=s.auditOffset+40>=data.total;}
  $('iw-access-form').onsubmit=async event=>{event.preventDefault();s.token=$('iw-token').value.trim();$('iw-token').value='';const epoch=++s.epoch;$('iw-unlock-button').disabled=true;try{await api('cases?limit=1');if(epoch!==s.epoch)return;$('iw-unlock').hidden=true;$('iw-content').hidden=false;$('iw-lock').hidden=false;$('iw-refresh').hidden=false;$('iw-session').textContent='Workspace unlocked';await window.showInvestigationRoute();}catch(e){if(epoch===s.epoch)lock(e.message);}finally{$('iw-unlock-button').disabled=false;}};
  $('iw-lock').onclick=()=>lock();$('iw-refresh').onclick=()=>window.showInvestigationRoute();
  $('iw-search').oninput=()=>{clearTimeout(searchTimer);searchTimer=setTimeout(guarded(async()=>{s.q=$('iw-search').value.trim();s.offset=0;s.selected='';await loadCases();}),250);};
  $('iw-band').onchange=guarded(async()=>{s.band=$('iw-band').value;s.offset=0;s.selected='';await loadCases();});
  $('iw-prev').onclick=guarded(async()=>{s.offset=Math.max(0,s.offset-30);s.selected='';await loadCases();});$('iw-next').onclick=guarded(async()=>{s.offset+=30;s.selected='';await loadCases();});
  $('iw-audit-prev').onclick=guarded(async()=>{s.auditOffset=Math.max(0,s.auditOffset-40);await loadAudit();});$('iw-audit-next').onclick=guarded(async()=>{s.auditOffset+=40;await loadAudit();});
  window.addEventListener('soc-new-alert',()=>{if(!$('investigations-view').hidden&&s.token)msg('New incident received. Refresh to update cases; your current selection is preserved.');});
})();
