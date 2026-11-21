// Run after workspace_ui_fixture.py. All data and model responses are test doubles.
process.env.TZ = 'Asia/Damascus';
const {JSDOM,VirtualConsole}=require(process.env.SOC_JSDOM_PATH||'jsdom');
const fs=require('node:fs'),assert=require('node:assert/strict'),path=require('node:path');
const dir=process.argv[2],fixture=JSON.parse(fs.readFileSync(path.join(dir,'fixture.json'),'utf8'));
const html=fs.readFileSync(path.join(dir,'dashboard.html'),'utf8'),tick=()=>new Promise(r=>setTimeout(r,25));
(async()=>{
  const errors=[],calls=[],followupRequests=[];let fail=false,failFollowupOnce=true,turns=[],trials=[];
  const vc=new VirtualConsole();vc.on('jsdomError',e=>errors.push(e.message));
  const dom=new JSDOM(html,{url:'http://localhost:8000/#investigations/case/'+fixture.case,runScripts:'dangerously',virtualConsole:vc,beforeParse(w){
    const BrowserDate = w.Date;
    w.Date = class extends BrowserDate {
      constructor(...args) { super(...(args.length ? args : ['2026-11-21T07:29:28Z'])); }
    };
    w.WebSocket=class{};w.URL.createObjectURL=()=> 'blob:test-only';w.URL.revokeObjectURL=()=>{};
    Object.defineProperty(w.crypto,'randomUUID',{value:undefined});
    Object.defineProperty(w.crypto,'getRandomValues',{value:undefined});
    w.HTMLAnchorElement.prototype.click=function(){calls.push('download:'+this.download)};
    w.HTMLDialogElement.prototype.showModal=function(){this.open=true};w.HTMLDialogElement.prototype.close=function(){this.open=false};
    w.fetch=async(url,options={})=>{
      const p=new URL(url,w.location.href).pathname,body=options.body?JSON.parse(options.body):{};calls.push(p);
      if(fail)return {ok:false,status:503,json:async()=>({detail:'Temporary test outage'})};
      let data=fixture.responses[p];
      if(p.endsWith('/followups')){
        if(options.method==='POST'){
          followupRequests.push(body);
          if(failFollowupOnce){failFollowupOnce=false;return {ok:false,status:503,json:async()=>({detail:'Temporary follow-up outage'})};}
          turns=[{id:'TURN-UI',status:'completed',question:body.question,answer:'UI test answer: evidence is incomplete.',findings:[],limitations:['Synthetic UI test'],model:'test-double',provider:'test',elapsed_seconds:1,containment_status:'NOT_EXECUTED'}];
          return {ok:true,status:202,json:async()=>({...turns[0],status:'queued',answer:''})};
        }
        data={items:turns};
      }
      if(p.endsWith('/followups/TURN-UI'))data={...turns[0],evidence:{A1:{status:'observed',value:'UI evidence'}},tool_trace:[]};
      if(p.endsWith('/export'))return {ok:true,status:200,headers:{get:()=> 'attachment; filename="fixture-evidence.zip"'},blob:async()=>new w.Blob(['test'])};
      if(p.endsWith('/comparison/trials')){if(options.method==='POST')trials=[JSON.parse(JSON.stringify(fixture.trial))];data={items:trials};if(options.method==='POST')data=trials[0];}
      if(p.endsWith('/complete')){trials[0].manual={status:'completed',decision:{...body},wall_seconds:1};trials[0].ai={status:'completed',decision:{classification:'insufficient',rationale:'Test double, not measured model output.',evidence_refs:['A1']},wall_seconds:2};data=trials[0];}
      assert.notEqual(data,undefined,'Unexpected UI request '+p);
      return {ok:true,status:200,json:async()=>JSON.parse(JSON.stringify(data))};
    };
  }});
  const w=dom.window,d=w.document;await tick();await tick();
  assert.match(d.getElementById('clock-display').textContent,/^10:29:28\b/);
  assert.match(d.getElementById('iw-detail').textContent,/Continue this investigation/);
  const form=d.querySelector('.iw-followup-form'),question=form.querySelector('textarea'),submit=form.querySelector('button[type=submit]');
  submit.click();await tick();
  assert.match(form.textContent,/Enter a question of at least 3 characters/);
  assert.equal(followupRequests.length,0);
  question.value='What evidence is missing?';submit.click();await tick();
  assert.match(form.textContent,/Temporary follow-up outage/);
  assert.equal(question.value,'What evidence is missing?');
  submit.click();await tick();await tick();
  assert.equal(followupRequests.length,2);
  assert.match(followupRequests[0].request_id,/^[A-Za-z0-9_-]{8,100}$/);
  assert.equal(followupRequests[0].request_id,followupRequests[1].request_id);
  assert.match(d.getElementById('iw-detail').textContent,/UI test answer/);
  [...d.querySelectorAll('#iw-detail button')].find(x=>x.textContent==='Inspect captured evidence & tool trace').click();await tick();
  assert.match(d.getElementById('iw-detail').textContent,/UI evidence/);
  [...d.querySelectorAll('#iw-detail button')].find(x=>x.textContent==='Download evidence pack').click();await tick();
  assert.ok(calls.includes('download:fixture-evidence.zip'));
  w.location.hash='investigations/comparison';await tick();await tick();
  assert.equal(d.getElementById('iw-comparison').hidden,false);
  assert.match(d.getElementById('iw-lab-summary').textContent,/baseline has not been established/);
  d.getElementById('iw-lab-start').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await tick();await tick();
  d.getElementById('iw-lab-decision').value='insufficient';d.getElementById('iw-lab-rationale').value='Evidence is insufficient in this synthetic UI exercise.';
  d.querySelector('#iw-lab-trial form').dispatchEvent(new w.Event('submit',{bubbles:true,cancelable:true}));await tick();await tick();
  assert.match(d.getElementById('iw-lab-trial').textContent,/AI review · completed/);
  fail=true;d.getElementById('iw-lab-refresh').click();await tick();assert.match(d.getElementById('iw-lab-message').textContent,/Temporary test outage/);
  fail=false;d.getElementById('iw-lab-refresh').click();await tick();assert.equal(d.getElementById('iw-lab-message').hidden,true);
  assert.equal(errors.length,0,errors.join('\n'));console.log('PASS case follow-up, evidence download, blind manual→AI comparison, route changes and error recovery');dom.window.close();
})().catch(e=>{console.error(e);process.exit(1)});
