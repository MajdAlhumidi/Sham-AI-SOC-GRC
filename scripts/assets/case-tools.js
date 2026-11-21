;(() => {
  'use strict';
  const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(cls)n.className=cls;return n;};
  async function api(path,options={}){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),20000);
    try{
      const response=await fetch('/api/investigations/'+path,{...options,cache:'no-store',headers:{'Content-Type':'application/json'},signal:controller.signal});
      if(options.download){if(!response.ok){const e=await response.json();throw new Error(typeof e.detail==='string'?e.detail:'Export failed.');}return response;}
      const data=await response.json();if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:'Request failed (HTTP '+response.status+').');return data;
    }finally{clearTimeout(timer);}
  }
  window.caseWorkspaceApi=api;
  window.caseWorkspaceNode=node;
  const terminal=new Set(['completed','limited','failed','unavailable']);
  let requestSequence = 0;
  function newRequestId() {
    if (typeof window.crypto?.getRandomValues === 'function') {
      const bytes = window.crypto.getRandomValues(new Uint8Array(16));
      return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
    }
    // The request ID deduplicates submissions. It grants no access.
    return ['followup', Date.now().toString(36), (++requestSequence).toString(36),
      Math.random().toString(36).slice(2)].join('-');
  }
  window.mountCaseTools=(data,root)=>{
    const casePath='cases/'+encodeURIComponent(data.id),box=node('section',undefined,'iw-case-tools');
    box.setAttribute('aria-label','Case follow-up and evidence export');
    const actions=node('div',undefined,'iw-detail-head'),download=node('button','Download evidence pack','iw-button');download.type='button';
    actions.append(node('h3','Continue this investigation'),download);box.append(actions,node('p','Ask a focused question. The agent can inspect available evidence and use permitted read-only tools. The original report stays unchanged.','iw-muted'));
    const exportStatus=node('p','','iw-inline-status');exportStatus.setAttribute('role','status');box.append(exportStatus);
    download.onclick=async()=>{download.disabled=true;exportStatus.textContent='Preparing redacted evidence pack…';try{
      const response=await api(casePath+'/export',{download:true}),blob=await response.blob(),url=URL.createObjectURL(blob),a=node('a');
      a.href=url;a.download=(response.headers.get('Content-Disposition')||'').match(/filename="([^"]+)"/)?.[1]||'case-evidence.zip';document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
      exportStatus.textContent='Evidence pack downloaded: printable report, structured records and fingerprint manifest. Review before sharing.';
    }catch(e){exportStatus.textContent=e.name==='AbortError'?'Export timed out. Retry the download.':e.message;}finally{download.disabled=false;}};
    const form=node('form',undefined,'iw-followup-form'),label=node('label','Follow-up question'),question=node('textarea');
    form.noValidate = true;
    question.required=true;question.minLength=3;question.maxLength=1200;question.placeholder='Was there a successful login after these failures? What evidence is missing?';label.append(question);
    const submit=node('button','Investigate question','iw-button primary');submit.type='submit';
    const status=node('p','','iw-inline-status');status.id='iw-followup-status';status.setAttribute('role','status');
    question.setAttribute('aria-describedby', status.id);
    question.addEventListener('input', () => {
      if (question.getAttribute('aria-invalid') === 'true') {
        question.removeAttribute('aria-invalid');
        status.textContent = '';
      }
    });
    const list=node('div',undefined,'iw-followup-list');list.setAttribute('aria-live','polite');form.append(label,submit,status);box.append(form,list);root.append(box);
    let requestId='',lastQuestion='',timer=null,active=false,submitting=false;
    const visible=()=>box.isConnected&&!document.getElementById('investigations-view').hidden&&!document.getElementById('iw-cases').hidden;
    async function load(){
      if(!visible())return;try{
        const result=await api(casePath+'/followups');if(!visible())return;
        list.replaceChildren();active=result.items.some(t=>!terminal.has(t.status));submit.disabled=active||submitting;list.setAttribute('aria-busy',String(active));
        if(!result.items.length)list.append(node('p','No follow-up questions recorded yet.','iw-muted'));
        result.items.forEach(turn=>{
          const item=node('article',undefined,'iw-turn');item.append(node('p',turn.status+' · '+(turn.elapsed_seconds===null||turn.elapsed_seconds===undefined?'timing pending':Number(turn.elapsed_seconds).toFixed(1)+' s'),'iw-tool-status'),node('h4',turn.question));
          let captured=null;
          const inspectReference=async ref=>{try{captured=captured||await api(casePath+'/followups/'+encodeURIComponent(turn.id));if(!item.isConnected)return;const record=captured.evidence?.[ref];if(!record){status.textContent='This evidence reference is unavailable.';return;}const panel=node('details');panel.open=true;panel.append(node('summary',ref+' · captured follow-up evidence'),node('pre',JSON.stringify(record,null,2)));item.append(panel);}catch(e){status.textContent=e.message;}};
          const references=(refs,labelText)=>{const row=node('div',undefined,'iw-chips');row.append(node('span',labelText,'iw-muted'));(refs||[]).forEach(ref=>{const b=node('button',ref,'iw-ref');b.type='button';b.setAttribute('aria-label','Inspect follow-up evidence '+ref);b.onclick=()=>inspectReference(ref);row.append(b);});return row;};
          if(turn.answer)item.append(node('p',turn.answer,'iw-turn-answer'));
          if(turn.answer_evidence?.length)item.append(references(turn.answer_evidence,'Answer evidence:'));
          if(turn.error)item.append(node('p',turn.error,'iw-message error'));
          (turn.findings||[]).forEach(f=>item.append(node('p',f.observation),references(f.evidence,'Finding evidence:')));
          if(turn.recommended_next_steps?.length){item.append(node('h3','Suggested next steps'));const ol=node('ol',undefined,'iw-limitations');turn.recommended_next_steps.forEach(x=>ol.append(node('li',x)));item.append(ol);}
          if(turn.limitations?.length){const ul=node('ul',undefined,'iw-limitations');turn.limitations.forEach(x=>ul.append(node('li',x)));item.append(ul);}
          item.append(node('p',(turn.provider||'ollama')+' · '+(turn.model||'model unavailable')+' · '+(turn.completed_at||turn.created_at||'')+' · Response actions: '+(turn.containment_status||'NOT_EXECUTED'),'iw-muted'));
          if(terminal.has(turn.status)){
            const inspect=node('button','Inspect captured evidence & tool trace','iw-button');inspect.type='button';inspect.onclick=async()=>{
              inspect.disabled=true;try{const full=await api(casePath+'/followups/'+encodeURIComponent(turn.id));if(!item.isConnected)return;
                const detail=node('details');detail.open=true;detail.append(node('summary','Captured follow-up evidence'),node('pre',JSON.stringify({evidence:full.evidence,tool_trace:full.tool_trace,limitations:full.limitations},null,2)));item.append(detail);inspect.remove();
              }catch(e){status.textContent=e.message;inspect.disabled=false;}
            };item.append(inspect);
          }list.append(item);
        });
        if(active){status.textContent='Question saved. Investigation is running. You can return to this case for the result.';clearTimeout(timer);timer=setTimeout(load,3000);}
        else if(result.items.length && !submitting)status.textContent='Follow-up results are saved with this case.';
      }catch(e){if(visible()){
        status.textContent=active
          ? 'Question saved. Could not check its progress. Retrying…'
          : 'Could not refresh follow-ups: '+(e.name==='AbortError'?'request timed out. Refresh to retry.':e.message);
        submit.disabled=active||submitting;
        if(active){clearTimeout(timer);timer=setTimeout(load,3000);}
      }}
    }
    form.onsubmit = async event => {
      event.preventDefault();
      if (active || submitting) return;
      const text = question.value.trim();
      if (text.length < 3 || text.length > 1200) {
        question.setAttribute('aria-invalid', 'true');
        status.textContent = text.length < 3
          ? 'Enter a question of at least 3 characters.'
          : 'Shorten the question to 1,200 characters or fewer.';
        question.focus();
        return;
      }
      question.removeAttribute('aria-invalid');
      submitting = true;
      submit.disabled = true;
      question.disabled = true;
      status.textContent = 'Saving question…';
      try {
        if (text !== lastQuestion || !requestId) {
          requestId = newRequestId();
          lastQuestion = text;
        }
        const turn = await api(casePath + '/followups', {
          method: 'POST',
          body: JSON.stringify({question: text, request_id: requestId}),
        });
        active = !terminal.has(turn.status);
        question.value = '';
        requestId = '';
        lastQuestion = '';
        status.textContent = active ? 'Question saved. Investigation is running.' : 'Question saved. Loading the result…';
        submitting = false;
        await load();
      } catch (error) {
        status.textContent = error.name === 'AbortError'
          ? 'Request timed out. Submit the same question to retry.'
          : 'Could not send the question. ' + error.message;
      } finally {
        submitting = false;
        question.disabled = false;
        submit.disabled = active;
      }
    };
    load();
  };
})();
