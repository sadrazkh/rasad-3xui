'use strict';
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname,'../dist/app.js'),'utf8');
function between(a,b){const start=source.indexOf(a),end=source.indexOf(b,start);assert.ok(start>=0&&end>start);return source.slice(start,end);}
const production=[between('function demoReport(', '\nfunction toast('),between('function stats(', '\nfunction chart('),between('function domainSummary(', '\nfunction usersTable('),between('function moduleNotice(', '\nfunction settingsView('),between('function csvCell(', '\nfunction loginScreen(')].join('\n');
function harness(report={}){
 const downloads=[];
 const ctx={state:{mode:'live',period:'today',user:null,domainQuery:'',domainSort:'bytes',query:'',filter:'all',report:{users:[],domains:[],...report},reportSelection:'["today",null]'},periodNames:{today:'امروز'},demoNames:['First','Second'],demoEmails:['first','second'],demoPrefs:{settings:{domains_enabled:true},enabled:[0,1],audit:[]},
 icon:()=>'',num:x=>String(x),bytes:x=>x==null?'—':`${x} B`,esc:x=>String(x).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;'),timeText:x=>String(x),button:()=>'',hero:()=>'',toolbar:()=>'',bottomNote:()=>'',empty:x=>`<div>${x}</div>`,reportKey:()=>JSON.stringify([ctx.state.period,ctx.state.user]),toast:()=>{},download:(content,type,name)=>downloads.push({content,type,name})};
 vm.createContext(ctx);vm.runInContext(production,ctx);return {...ctx,downloads};
}
test('known site totals exclude unknown and log-only destinations',()=>{
 const h=harness(),s=h.summarizeDestinations([{domain:'site.test',up:20,down:80,bytes:100,connections:1},{domain:'__unknown_udp__',up:5,down:45,bytes:50,connections:2},{domain:'log-only.test',bytes:null,connections:10}]);
 assert.equal(s.supported_bytes,100);assert.equal(s.unknown_bytes,50);assert.equal(s.measured_bytes,150);assert.equal(s.measured_up,25);assert.equal(s.measured_down,125);assert.equal(s.supported_domains,1);assert.equal(s.attribution_ratio,2/3);
});
test('site table sorts by byte volume, shows separate upload/download, and isolates unknown',()=>{
 const h=harness({metrics_status:'ready',domains:[{domain:'low.test',up:1,down:9,bytes:10,connections:900,last:1},{domain:'high.test',up:20,down:80,bytes:100,connections:1,last:1},{domain:'__unknown_tcp__',up:2,down:3,bytes:5,connections:1,last:1},{domain:'log-only.test',bytes:null,connections:10,last:1}]});
 const html=h.sitesTable();
 assert.ok(html.indexOf('high.test')<html.indexOf('low.test'));
 assert.match(html,/>80 B</);assert.match(html,/>20 B</);assert.match(html,/ترافیک با مقصد نامشخص/);assert.match(html,/حجم سایت موجود نیست/);
 const table=html.slice(html.indexOf('<tbody>'),html.indexOf('</tbody>'));
 assert.doesNotMatch(table,/__unknown_|log-only/);
 h.state.domainQuery='low';const filtered=h.sitesTable();const body=filtered.slice(filtered.indexOf('<tbody>'),filtered.indexOf('</tbody>'));assert.match(body,/low.test/);assert.doesNotMatch(body,/high.test/);
});
test('unconnected collector renders missing values and concrete setup instructions',()=>{
 const h=harness({metrics_status:'unavailable'});assert.match(h.stats(),/—/);assert.doesNotMatch(h.stats(),/>0 B</);assert.match(h.moduleNotice(),/شمارندهٔ ترافیک سایت‌ها را متصل کنید/);
});
test('server summary beyond the 100 row limit remains authoritative',()=>{
 const h=harness({metrics_status:'ready',destination_summary:{supported_bytes:10000,unknown_bytes:100,measured_bytes:10100,supported_domains:250},domains:[{domain:'site.test',up:1,down:9,bytes:10}]});
 assert.match(h.stats(),/10000/);assert.match(h.stats(),/250/);
});
test('CSV keeps the selected user, byte directions and missing measurements',()=>{
 const h=harness({domains:[{domain:'site.test',up:20,down:80,bytes:100,connections:1,last:2,source:'dispatcher_counter'},{domain:'unmeasured.test',bytes:null,connections:5,last:2,source:'access_log'}]});
 h.state.user='first';h.state.reportSelection='["today","first"]';h.exportCsv(true);
 assert.equal(h.downloads.length,1);assert.match(h.downloads[0].content,/download_bytes/);assert.match(h.downloads[0].content,/"first","today","site.test","80","20","100"/);assert.match(h.downloads[0].content,/"unmeasured.test","","",""/);
});
test('demo changes the actual destination report when the user changes',()=>{
 const h=harness();h.state.mode='demo';h.state.user='first';const first=h.demoReport();h.state.user='second';const second=h.demoReport();h.state.user=null;const all=h.demoReport();
 assert.ok(first.destination_summary.measured_bytes>0);assert.notEqual(first.domains[0].bytes,second.domains[0].bytes);assert.ok(Math.abs(all.destination_summary.measured_bytes-first.destination_summary.measured_bytes-second.destination_summary.measured_bytes)<1);
 h.demoPrefs.enabled=[];assert.equal(h.demoReport().destination_summary.measured_bytes,0);
});
