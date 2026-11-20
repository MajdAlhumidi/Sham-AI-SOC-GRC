;(() => {
  'use strict';
  const $=id=>document.getElementById(id),el=window.caseWorkspaceNode,api=window.caseWorkspaceApi;
  let selected='',epoch=0,poll=null,lastRender='';
  const visible=()=>!$('investigations-view').hidden&&!$('iw-comparison').hidden;
  const message=(text='',error=false)=>{const n=$('iw-lab-message');n.hidden=!text;n.textContent=text;n.classList.toggle('error',error);};
  const request=(path,body)=>api('comparison/'+path,body===undefined?{}:{method:'POST',body:JSON.stringify(body)});
  const num=value=>value===null||value===undefined?'Not measured':Number(value).toLocaleString(undefined,{maximumFractionDigits:1});
  const seconds=value=>value===null||value===undefined?'Not measured':num(value)+' s';
  function renderSummary(s){
    const root=$('iw-lab-summary');root.replaceChildren();
    root.append(el('p',num(s.trial_count)+' trials · '+num(s.unique_scenarios)+' unique scenarios · '+num(s.paired_completed)+' completed pairs · '+num(s.ai_only_trials)+' AI-only','iw-muted'));
    const table=el('table',undefined,'iw-lab-table'),head=el('tr'),body=el('tbody');['Measurement','Manual review','AI review'].forEach(x=>head.append(el('th',x)));const thead=el('thead');thead.append(head);table.append(thead,body);
    const rows=[['Completed / attempted',m=>num(m.completed)+' / '+num(m.attempted)],['Label agrees / differs',m=>num(m.correct)+' / '+num(m.incorrect)],['Failed / incomplete',m=>num(m.failed)+' / '+num(m.incomplete)],['Trials with citation errors',m=>num(m.reference_error_trials)],['Mean total wall time',m=>seconds(m.wall_seconds_mean)],['Recorded active time (self-reported)',m=>m.active_time_n?seconds(m.active_seconds_total_self_reported)+' across '+m.active_time_n+' trials':'Not recorded'],['Fallback runs',m=>num(m.fallback_count)]];
    rows.forEach(([label,fn])=>{const row=el('tr');row.append(el('td',label),el('td',fn(s.manual||{})),el('td',fn(s.ai||{})));body.append(row);});root.append(table);
    root.append(el('p',s.paired_completed?'Mean paired wall-time difference (manual minus AI): '+seconds(s.paired_wall_delta_seconds_mean)+'. This compares elapsed time on the same supplied evidence; it does not measure analyst active-time savings.':'A human baseline has not been established until paired reviews are completed.','iw-note'));
    (s.limitations||[]).forEach(x=>root.append(el('p',x,'iw-muted')));
  }
  function showDecision(parent,name,result){
    const panel=el('div',undefined,'iw-lab-result');panel.append(el('h3',name+' · '+result.status));
    if(result.wall_seconds!==undefined)panel.append(el('p','Total wall time: '+seconds(result.wall_seconds),'iw-muted'));
    if(result.model)panel.append(el('p',(result.provider||'ollama')+' · '+result.model,'iw-muted'));
    if(result.error)panel.append(el('p',result.error,'iw-message error'));
    if(result.decision){const d=result.decision;panel.append(el('p',d.classification+' · '+d.rationale));panel.append(el('p','Evidence: '+(d.evidence_refs||[]).join(', '),'iw-muted'));(d.limitations||[]).forEach(x=>panel.append(el('p',x,'iw-muted')));if(d.reference_errors?.length)panel.append(el('p','Citation validation errors: '+d.reference_errors.join('; '),'iw-message error'));}
    parent.append(panel);
  }
  function renderTrial(t,force=false){
    const key=t.id+':'+t.manual.status+':'+t.ai.status;
    if(!force&&key===lastRender)return;lastRender=key;selected=t.id;
    const root=$('iw-lab-trial');root.replaceChildren();root.append(el('h3',t.title),el('p',t.id+' · synthetic lab case · '+t.mode,'iw-muted'));
    if(t.analyst)root.append(el('p','Analyst name (self-reported, identity unverified): '+t.analyst,'iw-muted'));
    const evidence=el('details');evidence.open=true;evidence.append(el('summary','Review the supplied evidence'),el('pre',JSON.stringify(t.evidence,null,2)));root.append(evidence);
    if(t.manual.status==='running'){
      const form=el('form'),select=el('select'),choice=el('option','Choose your assessment');choice.value='';select.append(choice);select.required=true;select.id='iw-lab-decision';
      ['malicious','suspicious','benign','insufficient'].forEach(x=>{const o=el('option',x);o.value=x;select.append(o);});
      const label=el('label','Your classification');label.append(select);const why=el('textarea');why.required=true;why.minLength=3;why.maxLength=2000;why.id='iw-lab-rationale';const whyLabel=el('label','Reason and remaining uncertainty');whyLabel.append(why);form.append(label,whyLabel);
      const refs=el('fieldset');refs.append(el('legend','Supporting evidence'));
      Object.keys(t.evidence||{}).forEach(ref=>{const l=el('label',ref,'iw-lab-ref'),c=el('input');c.type='checkbox';c.value=ref;c.name='evidence_ref';l.prepend(c);refs.append(l);});form.append(refs);
      const active=el('input');active.type='number';active.min='0';active.max='86400';active.step='0.1';active.id='iw-lab-active';const activeLabel=el('label','Active analyst time in seconds (optional, self-reported)');activeLabel.append(active);form.append(activeLabel,el('p','Total wall time includes time away from the page. Active time is recorded separately and is not independently verified.','iw-muted'));
      const submit=el('button','Submit review & run AI','iw-button primary');submit.type='submit';form.append(submit);root.append(form);
      form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;message('Recording your review and starting the AI assessment…');try{
        const payload={classification:select.value,rationale:why.value.trim(),evidence_refs:[...refs.querySelectorAll('input:checked')].map(n=>n.value)};if(active.value!=='')payload.active_seconds=Number(active.value);
        await request('trials/'+encodeURIComponent(t.id)+'/complete',payload);lastRender='';await refresh();
      }catch(error){message(error.message,true);submit.disabled=false;}};
    }else showDecision(root,'Manual review',t.manual);
    if(t.ai.status==='pending'){
      root.append(el('p',t.manual.status==='running'?'AI assessment stays hidden until you finish your independent review.':'AI assessment queued. If another model job is running, retry after it finishes.','iw-note'));
      if(t.manual.status!=='running'){const retry=el('button','Run queued AI assessment','iw-button');retry.onclick=async()=>{retry.disabled=true;try{await request('trials/'+encodeURIComponent(t.id)+'/run-ai',{});await refresh();}catch(e){message(e.message,true);retry.disabled=false;}};root.append(retry);}
    }else showDecision(root,'AI review',t.ai);
    if(t.answer_key){const keyPanel=el('details');keyPanel.append(el('summary','Exercise answer key & rationale'),el('p',t.answer_key.classification+' · '+t.answer_key.rubric),el('p',t.answer_key.source||'Curated synthetic exercise','iw-muted'));root.append(keyPanel);}
  }
  async function refresh(){
    const myEpoch=epoch;if(!visible())return;clearTimeout(poll);
    try{
      const [summary,trials]=await Promise.all([request('summary'),request('trials')]);if(myEpoch!==epoch||!visible())return;
      renderSummary(summary);const list=$('iw-lab-trials');list.replaceChildren();
      if(!trials.items.length)list.append(el('p','No results recorded yet. Start an exercise to collect evidence.','iw-muted'));
      trials.items.forEach(t=>{const b=el('button',t.title+' · Manual: '+t.manual.status+' · AI: '+t.ai.status,'iw-button iw-lab-trial');b.onclick=()=>{selected=t.id;lastRender='';renderTrial(t,true);};list.append(b);});
      const trial=trials.items.find(t=>t.id===selected)||trials.items.find(t=>t.manual.status==='running')||trials.items[0];
      if(trial)renderTrial(trial);else $('iw-lab-trial').replaceChildren();
      if(trials.items.some(t=>t.ai.status==='running'||t.ai.status==='pending'&&t.manual.status!=='running'))poll=setTimeout(refresh,4000);
      message();
    }catch(e){if(visible())message(e.name==='AbortError'?'Request timed out. Refresh results to retry.':e.message,true);}
  }
  window.loadComparisonLab=async()=>{
    epoch++;lastRender='';message('Loading comparison exercises…');
    try{const d=await request('dataset');if(!visible())return;const select=$('iw-lab-scenario'),previous=select.value;select.replaceChildren();d.items.forEach(x=>{const o=el('option',x.title);o.value=x.id;select.append(o);});if(d.items.some(x=>x.id===previous))select.value=previous;await refresh();}catch(e){message(e.message,true);}
  };
  $('iw-lab-start').onsubmit=async event=>{event.preventDefault();const button=event.submitter||$('iw-lab-start').querySelector('button[type="submit"]');if(button)button.disabled=true;try{const t=await request('trials',{scenario_id:$('iw-lab-scenario').value,analyst:$('iw-lab-analyst').value.trim()});selected=t.id;lastRender='';await refresh();}catch(e){message(e.message,true);}finally{if(button)button.disabled=false;}};
  $('iw-lab-ai-only').onclick=async()=>{const button=$('iw-lab-ai-only');button.disabled=true;message('Starting an AI-only trial. No human result will be generated.');try{const t=await request('ai-trials',{scenario_id:$('iw-lab-scenario').value});selected=t.id;lastRender='';await refresh();}catch(e){message(e.message,true);}finally{button.disabled=false;}};
  $('iw-lab-refresh').onclick=()=>refresh();
})();
