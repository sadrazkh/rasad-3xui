'use strict';
const $ = (q, root = document) => root.querySelector(q);
const icons = {
 grid:'<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
 users:'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2m20 0v-2a4 4 0 0 0-3-3.9"/><circle cx="9" cy="7" r="4"/><path d="M16 3.1a4 4 0 0 1 0 7.8"/>',
 globe:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18m-9-9c5 5 5 13 0 18-5-5-5-13 0-18Z"/>',
 shield:'<path d="m12 3 8 4v5c0 5-8 9-8 9s-8-4-8-9V7l8-4Z"/><path d="m8 12 3 3 5-6"/>',
 file:'<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6Z"/><path d="M14 2v6h6M8 13h8m-8 4h5"/>',
 settings:'<path d="m9 3 1-1h4l1 3 3 2 3-1 2 4-2 2v3l2 2-2 4-3-1-3 2-1 1h-4l-1-3-3-2-3 1-2-4 2-2v-3L1 8l2-4 3 1Z" transform="translate(1 0) scale(.92)"/><circle cx="12" cy="12" r="3"/>',
 server:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01m8-11h3m-3 11h3"/>',
 arrow:'<path d="m13 5-7 7 7 7m-7-7h15"/>',
 down:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
 activity:'<path d="M2 12h5l3-8 4 16 3-8h5"/>',
 refresh:'<path d="M20 7V3l-3 3a8 8 0 0 0-13 6m0 5v4l3-3a8 8 0 0 0 13-6M20 7h-4M4 17h4"/>',
 bell:'<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9m-11 13h4"/>',
 moon:'<path d="M20 13A8 8 0 1 1 11 4a6 6 0 0 0 9 9Z"/>',
 help:'<circle cx="12" cy="12" r="9"/><path d="M9 9a3 3 0 0 1 6 0c0 2-3 2-3 5m0 3h.01"/>',
 search:'<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/>',
 more:'<circle cx="5" cy="12" r=".7"/><circle cx="12" cy="12" r=".7"/><circle cx="19" cy="12" r=".7"/>',
 lock:'<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
 clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
 close:'<path d="m6 6 12 12M6 18 18 6"/>',
 menu:'<path d="M3 6h18M3 12h18M3 18h18"/>',
 logout:'<path d="M9 3H4v18h5m5-14 5 5-5 5m-6-5h13"/>',
 check:'<path d="m5 12 4 4L19 6"/>',
 filter:'<path d="M4 5h16l-6 7v7l-4 2v-9L4 5Z"/>'
};
const icon = name => `<svg class="icon" viewBox="0 0 24 24" aria-hidden="true">${icons[name] || icons.activity}</svg>`;
const esc = value => String(value ?? '').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num = n => new Intl.NumberFormat('fa-IR').format(n);
function bytes(value){if(value===null || value===undefined)return '—';const units=['B','KB','MB','GB','TB'];let n=Math.max(0,value),i=0;while(n>=1024 && i<4){n/=1024;i++;}return `${n.toLocaleString('en-US',{maximumFractionDigits:i?1:0})} ${units[i]}`;}
const timeText = t => t? new Date(t*1000).toLocaleTimeString('fa-IR',{hour:'2-digit',minute:'2-digit',timeZone:'Asia/Tehran'}):'—';
const state={mode:null,view:'overview',period:'today',query:'',filter:'all',page:1,user:null,csrf:'',report:null,reportSelection:null,busy:false};
let loadVersion=0,loadEpoch=0,loadPromise=null;
const periodNames={today:'امروز',yesterday:'دیروز',week:'۷ روز اخیر',month:'۳۰ روز اخیر'};
const viewNames={overview:'نمای کلی',users:'کاربران',domains:'تحلیل مقصدها',monitor:'مدیریت ثبت دامنه',reports:'گزارش‌ها',settings:'تنظیمات',audit:'رویدادها',detail:'گزارش کاربر'};
const demoNames=['علی رضایی','سارا احمدی','محمد کریمی','نیلوفر حسینی','آرمان مرادی','مریم محمدی','رضا موسوی','پریسا نوری','امیر صالحی','نگار صادقی','حامد عباسی','رها کاظمی'];
const demoEmails=['ali.rezaei','sara.ahmadi','mohammad.k','niloufar.h','arman.m','maryam.m','reza.m','parisa.n','amir.s','negar.s','hamed.a','raha.k'];
function readPrefs(){try{return JSON.parse(localStorage.getItem('rasad-demo')||'null');}catch{return null;}}
let demoPrefs=readPrefs() || {settings:{scope:'selected',interval:60,retention:7,domains_enabled:true},enabled:[0,1,2,4,7],audit:[]};
function demoSave(){localStorage.setItem('rasad-demo',JSON.stringify(demoPrefs));}
function demoReport(){
 const now=Math.floor(Date.now()/1000),midnight=new Date(new Date().toLocaleString('en-US',{timeZone:'Asia/Tehran'}));midnight.setHours(0,0,0,0);const start=Math.floor(midnight.getTime()/1000);
 const factor={today:1,yesterday:.82,week:5.7,month:18.4}[state.period];
 const users=demoNames.map((name,i)=>({email:demoEmails[i],name,inbound:i<7?'Reality · 443':'VLESS · 8443',protocol:'vless',enabled:i!==10,online:i<7,up:(i+1)*.23*2**30,down:(12-i)*5.3*2**30,total:(i%3?80:120)*2**30,expiry:(now+(i+7)*86400)*1000,consent:demoPrefs.enabled.includes(i),selected:demoPrefs.enabled.includes(i),monitored:demoPrefs.settings.domains_enabled&&demoPrefs.enabled.includes(i),period_up:(.22+i*.043)*factor*2**30,period_down:(18.1-i*1.21)*factor*2**30}));
 const domainBase=[['youtube.com',824,'ویدئو و رسانه'],['instagram.com',638,'شبکه اجتماعی'],['google.com',412,'جست‌وجو'],['telegram.org',297,'پیام‌رسان'],['github.com',186,'توسعه و کد'],['spotify.com',128,'صدا و رسانه']];
 const selectedUser=state.user?users.find(x=>x.email===state.user):null;
 const active=users.filter(u=>u.monitored).length;
 const domains=(!selectedUser||selectedUser.monitored)&&active?domainBase.map(([domain,n,category],i)=>({domain,connections:Math.round(n*factor*(selectedUser?.18:1)),last:now-i*360,category,bytes:null})):[];
 const source=selectedUser?[selectedUser]:users;
 const total=source.reduce((a,u)=>a+u.period_down,0),up=source.reduce((a,u)=>a+u.period_up,0);
 const weights=Array.from({length:24},(_,i)=>.3+Math.sin(i*.4)**2+(i>17?1.6:0));const sum=weights.reduce((a,b)=>a+b,0);const uploadWeights=weights.map((w,i)=>w*(.7+.3*Math.cos(i))),uploadSum=uploadWeights.reduce((a,b)=>a+b,0);
 return {mode:'demo',users,domains,series:weights.map((w,i)=>({bucket:start+i*3600,down:total*w/sum,up:up*uploadWeights[i]/uploadSum})),period:state.period,start,end:now,last_sync:now,started:now-8*86400,settings:demoPrefs.settings,error:null,log_status:active?'ready':'disabled',collector:{cycle_ms:24,api_bytes:428001,api_calls:46,log_budget:524288},timezone:'Asia/Tehran',audit:demoPrefs.audit,domain_source:'access_log',metrics_status:'unavailable'};
}
function toast(message){$('#toast').textContent=message;$('#toast').classList.add('show');clearTimeout(toast.timer);toast.timer=setTimeout(()=>$('#toast').classList.remove('show'),3500);}
async function api(path,data){
 const requestEpoch=loadEpoch;
 const opts={credentials:'same-origin',headers:{}};
 if(data!==undefined){opts.method='POST';opts.headers={'Content-Type':'application/json','X-CSRF-Token':state.csrf};opts.body=JSON.stringify(data);}
 const response=await fetch('/api/'+path,opts);
 if(response.status===401){if(path!=='login'&&requestEpoch===loadEpoch)loginScreen();throw new Error(path==='login'?'نام کاربری یا رمز عبور درست نیست.':'برای ادامه وارد شوید.');}
 if(!response.ok)throw new Error(response.status===429?'تلاش‌های زیاد؛ پنج دقیقه دیگر دوباره امتحان کنید.':'درخواست انجام نشد. اتصال و تنظیمات را بررسی کنید.');
 return response.json();
}
function reportKey(period=state.period,user=state.user){return JSON.stringify([period,user]);}
function load(){
 if(state.reportSelection!==reportKey()){state.report=null;state.reportSelection=null;}
 loadVersion++;
 if(state.busy)return loadPromise;
 state.busy=true;
 loadPromise=Promise.resolve().then(async()=>{
  let version;
  try{
   do{
    version=loadVersion;
    const period=state.period,user=state.user,epoch=loadEpoch;
    const current=()=>version===loadVersion&&period===state.period&&user===state.user&&epoch===loadEpoch;
    try{
     const report=state.mode==='demo'?demoReport():await api(`report?period=${period}${user?'&email='+encodeURIComponent(user):''}`);
     if(!current())continue;
     state.report=report;state.reportSelection=reportKey(period,user);render();
    }
    catch(e){if(!current())continue;toast(e.message);if(!state.report&&state.mode==='live'&&!$('.login'))$('#app').innerHTML=`<div class="login"><div class="card"><h1>اتصال برقرار نشد</h1><p>سرویس رصد در دسترس نیست. داده‌های واقعی هنوز دریافت نشده‌اند.</p><button class="btn primary" data-action="refresh">تلاش دوباره</button></div></div>`;}
   }while(version!==loadVersion);
  }
  finally{state.busy=false;loadPromise=null;}
 });
 return loadPromise;
}
function audit(action,target='server'){demoPrefs.audit.unshift({id:Date.now(),ts:Math.floor(Date.now()/1000),action,target});demoPrefs.audit=demoPrefs.audit.slice(0,60);demoSave();}
async function mutate(path,data){if(state.mode==='live')return api(path,data);if(path==='settings'){demoPrefs.settings=data;audit('settings_saved');}if(path==='monitor'){const i=demoEmails.indexOf(data.email);demoPrefs.enabled=demoPrefs.enabled.filter(x=>x!==i);if(data.enabled)demoPrefs.enabled.push(i);audit(data.enabled?'monitor_on':'monitor_off_and_erased',data.email);}if(path==='monitor-all'){demoPrefs.enabled=data.enabled?demoEmails.map((_,i)=>i):[];audit(data.enabled?'monitor_all_current_on':'monitor_all_off_and_erased');}demoSave();}
function button(label,action,ico,primary=false){return `<button class="btn${primary?' primary':''}" data-action="${action}">${icon(ico)}${label}</button>`;}
function switchButton(checked,action,extra=''){return `<button class="switch" type="button" role="switch" aria-checked="${!!checked}" aria-label="ثبت دامنه" data-action="${action}" ${extra}></button>`;}
function empty(message){return `<div class="empty">${icon('globe')}${message}</div>`;}
function shell(content){
 const r=state.report,nav=[['overview','grid'],['users','users'],['domains','globe'],['monitor','shield'],['reports','file']];
 return `<div class="layout"><aside class="sidebar"><a class="brand" href="#overview"><img src="/logo.svg" alt=""><div><strong>رصد</strong><small>RASAD PANEL</small></div></a><div class="nav-label">مدیریت فضای کاری</div><nav class="nav">${nav.map(([id,ico])=>`<button class="${state.view===id?'active':''}" data-view="${id}">${icon(ico)}${viewNames[id]}${id==='users'?`<span class="count">${num(r.users.length)}</span>`:''}</button>`).join('')}</nav><div class="nav-separator"></div><nav class="nav"><button class="${state.view==='settings'?'active':''}" data-view="settings">${icon('settings')}تنظیمات</button><button data-action="help">${icon('help')}راهنما و نصب</button></nav><div class="sidebar-bottom"><div class="edge-card"><div class="line">${icon('server')}پردازش روی سرور شما</div><p>آمار محلی · بدون انتقال محتوای کاربران</p></div><div class="profile"><div class="avatar">م</div><div><strong>مدیر سیستم</strong><small style="display:block">دسترسی مدیریت</small></div><button class="icon-btn" data-action="${state.mode==='demo'?'help':'logout'}" aria-label="خروج">${icon('logout')}</button></div></div></aside><section class="workspace"><header class="topbar"><div class="crumb"><button class="icon-btn mobile-menu" data-action="menu" aria-label="فهرست">${icon('menu')}</button>${icon('server')}فضای کاری<span>/</span><strong>سرور اصلی</strong></div><div class="top-actions"><span class="date">${new Date().toLocaleDateString('fa-IR',{weekday:'long',day:'numeric',month:'long',timeZone:'Asia/Tehran'})}</span><div class="vertical"></div><button class="icon-btn" data-action="theme" aria-label="تغییر پوسته">${icon('moon')}</button><button class="icon-btn" data-view="audit" aria-label="رویدادها">${icon('bell')}</button><span class="mode-badge"><i class="dot"></i>${state.mode==='demo'?'داده‌های نمایشی':r.error?'اتصال قطع شده':'سرویس فعال'}</span></div></header><main class="main">${content}<footer class="footer"><span>رصد؛ تصویری روشن از مصرف کاربران شما</span><span dir="ltr">RASAD 1.0 · ${state.mode==='demo'?'INTERACTIVE PREVIEW':'SELF-HOSTED'}</span></footer></main></section></div>`;
}
function hero(title,subtitle,actions=true){return `<div class="hero"><div><div class="eyebrow"><i class="dot"></i>3x-ui <span style="color:#becbcf;margin:0 5px">/</span> مرکز مدیریت ترافیک</div><h1>${title}</h1><p>${subtitle}</p></div>${actions?`<div class="hero-actions">${button('دریافت گزارش','export-users','down')}${button('مدیریت ثبت دامنه','open-monitor','shield',true)}</div>`:''}</div>`;}
function toolbar(){return `<div class="toolbar"><div class="periods">${Object.entries(periodNames).map(([key,name])=>`<button data-period="${key}" class="${state.period===key?'active':''}">${name}</button>`).join('')}</div><div class="caption">${icon('clock')}آخرین دریافت: ${timeText(state.report.last_sync)}<button class="icon-btn" data-action="refresh" aria-label="تازه‌سازی">${icon('refresh')}</button></div></div>`;}
function notices(){const r=state.report;return `${state.mode==='demo'?'<div class="warning">پیش‌نمایش تعاملی با داده‌های نمونه. اتصال واقعی پس از نصب روی Ubuntu انجام می‌شود.</div>':''}${r.error?'<div class="warning">ارتباط با 3x-ui قطع شده؛ مقادیر زیر از آخرین دریافت موفق هستند.</div>':''}${state.mode==='live'&&r.started&&(r.started>r.start||r.start<r.end-r.settings.retention*86400)?'<div class="warning">گزارش این بازه کامل نیست؛ زمان شروع جمع‌آوری یا مدت نگهداری فقط بخشی از بازه را پوشش می‌دهد. مصرف پیش از نصب قابل بازیابی نیست.</div>':''}`;}
function stats(){
 const r=state.report,users=state.user?r.users.filter(u=>u.email===state.user):r.users;
 const total=r.series.reduce((a,row)=>a+row.up+row.down,0),online=users.filter(u=>u.online===1||u.online===true).length,monitored=users.filter(u=>u.monitored).length;
 const cards=[['ترافیک مصرف‌شده',bytes(total),'activity','دانلود + آپلود',periodNames[state.period]],['کاربران آنلاین',users.length&&users.every(u=>u.online===null)?'—':num(online),'users','از '+num(users.length)+' کاربر','آخرین دریافت'],['مقصدهای گزارش‌شده',num(r.domains.length),'globe','تا ۱۰۰ مقصد پرتکرار','در این بازه'],['ثبت دامنه فعال',num(monitored),'shield','کاربران انتخاب‌شده توسط شما','قابل مدیریت']];
 return `<div class="stats">${cards.map(([label,value,ico,desc,foot])=>{const parts=value.split(' ');return `<div class="stat"><div class="stat-top">${label}<span class="stat-icon">${icon(ico)}</span></div><div class="stat-value"><bdi>${parts[0]}</bdi>${parts[1]?`<span class="unit">${parts[1]}</span>`:''}</div><div class="stat-foot"><span class="positive">${foot}</span><span>${desc}</span></div></div>`;}).join('')}</div>`;
}
function chart(){
 const r=state.report,series=r.series;
 let buckets;if(state.period==='today'||state.period==='yesterday'){buckets=Array.from({length:24},(_,i)=>({key:i,up:0,down:0,label:String(i).padStart(2,'0')+':00'}));for(const row of series){const i=Number(new Date(row.bucket*1000).toLocaleTimeString('en-GB',{hour:'2-digit',hourCycle:'h23',timeZone:'Asia/Tehran'}));buckets[i].up+=row.up;buckets[i].down+=row.down;}}
 else{const map=new Map();for(const row of series){const label=new Date(row.bucket*1000).toLocaleDateString('fa-IR',{month:'numeric',day:'numeric',timeZone:'Asia/Tehran'});const cur=map.get(label)||{label,up:0,down:0};cur.up+=row.up;cur.down+=row.down;map.set(label,cur);}buckets=[...map.values()];}
 if(!buckets.length)buckets=[{label:'—',up:0,down:0}];
 const max=Math.max(...buckets.map(b=>Math.max(b.up,b.down)),1)*1.2;
 const X=i=>45+i*615/Math.max(1,buckets.length-1),Y=v=>184-v/max*155;
 const line=k=>buckets.map((b,i)=>`${i?'L':'M'} ${X(i).toFixed(1)} ${Y(b[k]).toFixed(1)}`).join(' ');
 const down=buckets.reduce((a,b)=>a+b.down,0),up=buckets.reduce((a,b)=>a+b.up,0);
 const svg=`<svg viewBox="0 0 700 218" role="img" aria-label="نمودار دانلود و آپلود ${periodNames[state.period]}"><defs><linearGradient id="area" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#53b3a4" stop-opacity=".18"/><stop offset="100%" stop-color="#53b3a4" stop-opacity="0"/></linearGradient></defs>${[0,.25,.5,.75,1].map(v=>`<line x1="45" x2="660" y1="${Y(max*v)}" y2="${Y(max*v)}" stroke="var(--line)" stroke-dasharray="3 5"/><text x="18" y="${Y(max*v)+4}" fill="var(--muted)" font-size="9" text-anchor="middle" direction="ltr">${(max*v/2**30).toFixed(1)}</text>`).join('')}<text x="19" y="15" font-size="9" fill="var(--muted)">GB</text><path d="${line('down')} L ${X(buckets.length-1)} 184 L 45 184 Z" fill="url(#area)"/><path d="${line('down')}" fill="none" stroke="#2c9b88" stroke-width="2.7" stroke-linejoin="round"/><path d="${line('up')}" fill="none" stroke="#85a3e9" stroke-width="2" stroke-linejoin="round"/>${buckets.map((b,i)=>`<circle cx="${X(i)}" cy="${Y(b.down)}" r="8" fill="transparent"><title>${b.label} · دانلود ${bytes(b.down)} · آپلود ${bytes(b.up)}</title></circle>${i%Math.max(1,Math.ceil(buckets.length/7))===0?`<text x="${X(i)}" y="209" font-size="10" fill="var(--muted)" text-anchor="middle" direction="ltr">${b.label}</text>`:''}`).join('')}</svg>`;
 return `<section class="card"><div class="card-head"><div><h2>روند مصرف ترافیک</h2><small>تغییرات مصرف در طول ${periodNames[state.period]} · ساعت تهران</small></div><div class="chart-legend"><span><i class="legend-dot"></i>دانلود</span><span><i class="legend-dot blue"></i>آپلود</span></div></div><div class="chart-wrap">${svg}</div><div class="chart-foot"><span>دانلود <strong>${bytes(down)}</strong></span><span>آپلود <strong>${bytes(up)}</strong></span><span class="right">${icon('clock')}دقت زمانی تابع فاصلهٔ نمونه‌برداری</span></div></section>`;
}
function domainSummary(){const r=state.report,max=Math.max(...r.domains.map(d=>d.connections),1);return `<section class="card"><div class="card-head"><div><h2>مقصدهای پرتکرار</h2><small>بر اساس تعداد اتصال‌های مشاهده‌شده</small></div><span class="tag">${periodNames[state.period]}</span></div>${r.domains.length?`<div class="domain-list">${r.domains.slice(0,5).map((d,i)=>`<div class="domain-row"><div class="domain-logo" style="color:${['#c77979','#b798b8','#7d9bcd','#79acc2','#79959b'][i]}">${esc(d.domain[0].toUpperCase())}</div><div class="domain-info"><div class="domain-name">${esc(d.domain)}</div><div class="domain-sub">${d.bytes!=null?'حجم اندازه‌گیری‌شده: '+bytes(d.bytes):'حجم تفکیکی در منبع ثبت نشده'}</div></div><div><div class="domain-number">${num(d.connections)}</div><div class="mini-bar"><i style="width:${d.connections/max*100}%"></i></div></div></div>`).join('')}</div>`:empty('هنوز دامنه‌ای برای این بازه ثبت نشده است.')}<button class="card-link" data-view="domains">مشاهده گزارش مقصدها${icon('arrow')}</button></section>`;}
function usersTable(limit){
 const r=state.report,filtered=r.users.filter(u=>(u.name+' '+u.email).toLowerCase().includes(state.query.toLowerCase())&&(state.filter==='all'||state.filter==='online'&&u.online||state.filter==='monitored'&&u.monitored));
 const size=limit||8,maxPage=Math.max(1,Math.ceil(filtered.length/size));state.page=Math.min(state.page,maxPage);const rows=filtered.slice((state.page-1)*size,state.page*size);
 return `<section class="card table-card"><div class="card-head"><div><h2>${state.view==='monitor'?'انتخاب کاربران برای ثبت دامنه':'مصرف کاربران'}</h2><small>${num(filtered.length)} کاربر · مصرف در ${periodNames[state.period]}</small></div><div class="table-tools"><div class="search">${icon('search')}<input id="user-search" aria-label="جست‌وجوی کاربر" placeholder="جست‌وجوی نام یا شناسه…" value="${esc(state.query)}"></div><select class="select" id="user-filter" aria-label="فیلتر کاربران"><option value="all" ${state.filter==='all'?'selected':''}>همهٔ کاربران</option><option value="online" ${state.filter==='online'?'selected':''}>آنلاین</option><option value="monitored" ${state.filter==='monitored'?'selected':''}>ثبت دامنه فعال</option></select></div></div><div class="table-wrap"><table><thead><tr><th>کاربر</th><th>وضعیت</th><th>پروتکل</th><th>مصرف بازه</th><th>مصرف / سقف کانفیگ</th><th>ثبت دامنه</th><th></th></tr></thead><tbody>${rows.map((u,i)=>{const used=u.up===null||u.down===null?null:u.up+u.down,ratio=u.total&&used!=null?Math.min(100,used/u.total*100):0;return `<tr><td><button class="user-cell" data-user="${esc(u.email)}"><div class="avatar" style="background:${['#edf3f5','#f1edf6','#f6f1e9','#eaf4ef'][i%4]};color:#77919d">${esc(u.name.split(' ').map(s=>s[0]).slice(0,2).join(''))}</div><div><strong>${esc(u.name)}</strong><small>${esc(u.email)}</small></div></button></td><td><span class="status ${u.online?'':'off'}"><i class="dot"></i>${u.online===null?'نامشخص':u.online?'آنلاین':'آفلاین'}</span></td><td><span class="tag">${esc(u.protocol.toUpperCase())}</span></td><td class="traffic-cell">${bytes(u.period_up+u.period_down)}</td><td><div class="traffic-cell" style="font-weight:400;font-size:10px">${bytes(used)} <span style="color:var(--muted)">/ ${u.total?bytes(u.total):'∞'}</span></div><div class="progress"><i class="${ratio>80?'warn':''}" style="width:${ratio}%"></i></div></td><td>${switchButton(u.selected&&u.consent,'monitor-user',`data-email="${esc(u.email)}"`)}</td><td><button class="icon-btn" data-user="${esc(u.email)}" aria-label="گزارش ${esc(u.name)}">${icon('more')}</button></td></tr>`;}).join('')}</tbody></table>${!rows.length?empty('کاربری با این فیلتر پیدا نشد.'):''}</div><div class="table-footer"><span>نمایش ${num(rows.length)} از ${num(filtered.length)} کاربر</span><div class="page-buttons"><button data-page="${Math.max(1,state.page-1)}" aria-label="صفحه قبل">‹</button>${Array.from({length:maxPage},(_,i)=>`<button class="${state.page===i+1?'active':''}" data-page="${i+1}">${num(i+1)}</button>`).join('')}<button data-page="${Math.min(maxPage,state.page+1)}" aria-label="صفحه بعد">›</button></div></div></section>`;
}
function bottomNote(){return `<div class="bottom-note">${icon('shield')}<div><strong>کنترل داده‌ها دست شماست.</strong> ثبت دامنه فقط برای کاربران مورد تأیید شما انجام می‌شود؛ با خاموش‌کردن تیک کاربر، گزارش دامنه‌های او حذف می‌شود.</div><button data-action="help">دربارهٔ روش اندازه‌گیری${icon('arrow')}</button></div>`;}
function domainsView(){
 const r=state.report;
 const selector=`<select class="select" id="domain-user" aria-label="انتخاب کاربر برای گزارش مقصد"><option value="">همهٔ کاربران</option>${r.users.map(u=>`<option value="${esc(u.email)}" ${state.user===u.email?'selected':''}>${esc(u.name)}</option>`).join('')}</select>`;
 const label=d=>d==='__unknown_tcp__'?'مقصد نامشخص TCP':d==='__unknown_udp__'?'مقصد نامشخص UDP':d;
 return `${hero('مقصدها، با شفافیت بیشتر.','نام مقصد و حجم اندازه‌گیری‌شدهٔ مسیرهای پوشش‌داده‌شده.')} ${toolbar()}
 <div class="info-box" style="margin:0 0 20px">${r.metrics_status==='ready'?'ماژول شمارندهٔ مقصد متصل است. حجم‌ها بر اساس payload مسیر Dispatcher هستند و پوشش کامل کل کانفیگ را تضمین نمی‌کنند.':'لاگ معمول Xray حجم هر دامنه را ندارد. حجم تفکیکی فقط پس از نصب جداگانهٔ ماژول شمارندهٔ مقصد نمایش داده می‌شود.'} این گزارش از DNS حجم استخراج نمی‌کند. اتصال‌ها می‌توانند مربوط به فعالیت پس‌زمینه یا CDN باشند.</div>
 <div class="card"><div class="card-head"><h2>دامنه‌های مشاهده‌شده</h2><div class="table-tools">${selector}${button('خروجی CSV','export-domains','down')}</div></div>
 ${r.domains.length?`<div class="table-wrap"><table class="full-domain"><thead><tr><th>مقصد</th><th>تعداد اتصال</th><th>آخرین مشاهده</th><th>حجم تفکیکی</th><th>منبع</th></tr></thead><tbody>${r.domains.map(d=>`<tr><td><bdi>${esc(label(d.domain))}</bdi></td><td>${num(d.connections)}</td><td>${timeText(d.last)}</td><td><bdi>${d.bytes==null?'ثبت نشده':bytes(d.bytes)}</bdi></td><td><span class="tag">${d.bytes==null?'Access log':'شمارندهٔ مقصد'}</span></td></tr>`).join('')}</tbody></table></div>`:empty('دامنه‌ای موجود نیست. وضعیت ثبت و مسیر access.log را در تنظیمات بررسی کنید.')}
 <div class="notice">حداکثر ۱۰۰ مقصد پرتکرار. نام دامنه تضمین بازدید صفحه نیست. IP، ECH، تونل‌های تو‌در‌تو و برخی اتصال‌ها ممکن است نامشخص بمانند.</div></div>`;
}
function settingsView(){const r=state.report,s=r.settings;return `${hero('تنظیمات جمع‌آوری','تعادل بین جزئیات گزارش و مصرف منابع سرور.',false)}<div class="settings-grid"><section class="card"><div class="card-head"><h2>سیاست ثبت داده‌ها</h2><span class="pill">ذخیره روی سرور</span></div><form id="settings-form" class="card-body"><div class="setting-line"><div><h3>ثبت مقصدهای اتصال</h3><p>خاموش‌کردن این گزینه خواندن لاگ و شمارندهٔ دامنه را متوقف می‌کند.</p></div>${switchButton(s.domains_enabled,'setting-switch','id="master-switch"')}</div><div class="field" style="margin-top:20px"><label for="scope">دامنهٔ فعال‌سازی</label><select id="scope"><option value="selected" ${s.scope==='selected'?'selected':''}>کاربران انتخاب‌شده</option><option value="all" ${s.scope==='all'?'selected':''}>همهٔ کاربران دارای تأیید درخواست</option></select><small>در حالت «همه»، کاربران جدید پس از تأیید درخواستشان در پنل اضافه می‌شوند.</small></div><div class="field"><label for="interval">فاصلهٔ دریافت آمار</label><select id="interval">${[60,120,300].map(n=>`<option value="${n}" ${s.interval===n?'selected':''}>${num(n/60)} دقیقه</option>`).join('')}</select><small>هر چرخه معمولاً دو درخواست محلی به پنل؛ تازه‌سازی صفحه فقط داده‌های ذخیره‌شده را می‌خواند.</small></div><div class="field"><label for="retention">مدت نگهداری آمار و دامنه‌ها</label><select id="retention">${[3,7,14,30].map(n=>`<option value="${n}" ${s.retention===n?'selected':''}>${num(n)} روز</option>`).join('')}</select><small>کاهش این مقدار، داده‌های قدیمی‌تر را پاک می‌کند.</small></div><button class="btn primary" type="submit">${icon('check')}ذخیرهٔ تنظیمات</button></form></section><div><section class="card"><div class="card-head"><h2>وضعیت سرویس</h2>${icon('server')}</div><div class="card-body"><div class="info-list"><div><span>اتصال 3x-ui</span><strong>${r.error?'ناموفق':r.last_sync?'دریافت موفق':'در انتظار دریافت'}</strong></div><div><span>آخرین دریافت</span><strong>${timeText(r.last_sync)}</strong></div><div><span>خواندن لاگ</span><strong>${{ready:'آماده',disabled:'غیرفعال',unavailable:'فایل در دسترس نیست',backlog:'عقب‌ماندگی؛ سقف پردازش فعال',error:'خطای خواندن'}[r.log_status]||'نامشخص'}</strong></div><div><span>زمان چرخهٔ اخیر</span><strong><bdi>${r.collector.cycle_ms??'—'} ms</bdi></strong></div><div><span>دادهٔ API از شروع سرویس</span><strong><bdi>${bytes(r.collector.api_bytes)}</bdi></strong></div><div><span>سقف خواندن لاگ در هر چرخه</span><strong>۵۱۲ کیلوبایت</strong></div><div><span>منطقهٔ زمانی گزارش</span><strong><bdi>${esc(r.timezone)}</bdi></strong></div></div><div class="info-box">آمار از زمان نصب جمع می‌شود. فعال‌سازی از این پنل، تنظیمات Xray را تغییر نمی‌دهد و سرویس VPN را ری‌استارت نمی‌کند. برای دامنه‌ها، access.log موجود باید خواندنی باشد.</div></div></section><section class="card" style="margin-top:20px"><div class="card-body"><h2>اتصال و تنظیم مسیر لاگ</h2><p style="font-size:11px;color:var(--muted);margin:10px 0 17px">نشانی پنل و اطلاعات اتصال در فایل امن سرویس روی سرور تنظیم می‌شوند.</p>${button('مشاهدهٔ راهنما','help','file')}</div></section></div></div>`;}
const auditNames={settings_saved:'تنظیمات جمع‌آوری ذخیره شد',monitor_on:'ثبت دامنهٔ کاربر فعال شد',monitor_off_and_erased:'ثبت خاموش و گزارش دامنه حذف شد',monitor_all_current_on:'ثبت برای کاربران فعلی تأیید شد',monitor_all_off_and_erased:'ثبت همه خاموش و گزارش دامنه‌ها حذف شد',sampling_gap:'وقفه در نمونه‌برداری؛ تقسیم زمانی تخمینی',counter_reset:'ریست شمارنده؛ مبنای جدید ثبت شد'};
function auditView(){return `${hero('رویدادهای مدیریت','تغییرات ثبت دامنه و کیفیت جمع‌آوری داده‌ها.',false)}<section class="card"><div class="card-body"><div class="audit-list">${state.report.audit.length?state.report.audit.map(a=>`<div class="audit-item"><i class="audit-point"></i><div><strong>${esc(auditNames[a.action]||a.action)}</strong><small><bdi>${esc(a.target)}</bdi></small></div><time>${new Date(a.ts*1000).toLocaleDateString('fa-IR',{month:'short',day:'numeric',timeZone:'Asia/Tehran'})} · ${timeText(a.ts)}</time></div>`).join(''):empty('هنوز تغییری در تنظیمات ثبت نشده است.')}</div></div></section>`;}
function detailView(){const u=state.report.users.find(u=>u.email===state.user);if(!u)return empty('کاربر در پنل پیدا نشد.');return `<button class="back-btn" data-view="users">${icon('arrow')}بازگشت به کاربران</button>${hero(esc(u.name),'گزارش مصرف و مقصدهای مشاهده‌شدهٔ '+esc(u.email),false)}${toolbar()}${stats()}<div class="grid-mid">${chart()}<section class="card"><div class="detail-heading"><div class="avatar">${esc(u.name[0])}</div><div><h2>${esc(u.name)}</h2><small><bdi>${esc(u.email)}</bdi></small></div></div><div class="card-body"><div class="info-list"><div><span>ورودی</span><strong><bdi>${esc(u.inbound)}</bdi></strong></div><div><span>مصرف کل کانفیگ</span><strong><bdi>${bytes(u.up===null||u.down===null?null:u.up+u.down)}</bdi></strong></div><div><span>سقف حجم</span><strong><bdi>${u.total?bytes(u.total):'نامحدود'}</bdi></strong></div><div><span>انقضا</span><strong>${u.expiry>0?new Date(u.expiry).toLocaleDateString('fa-IR'):'بدون تاریخ ثابت'}</strong></div><div><span>ثبت دامنه</span>${switchButton(u.selected&&u.consent,'monitor-user',`data-email="${esc(u.email)}"`)}</div></div><div class="info-box">گزارش فقط پس از شروع جمع‌آوری موجود است. خاموش‌کردن تیک، داده‌های دامنهٔ کاربر را حذف می‌کند.</div></div></section></div>${domainSummary()}`;}
function render(){
 const r=state.report;if(!r)return;let content;
 if(state.view==='overview')content=`${hero('همه‌چیز، زیر نظر شما.','مصرف کاربران، روند ترافیک و مقصدهای اتصال در یک نگاه.')} ${toolbar()}${stats()}<div class="grid-mid">${chart()}${domainSummary()}</div>${usersTable(5)}${bottomNote()}`;
 else if(state.view==='users')content=`${hero('کاربران و مصرف آن‌ها','یک نمای روشن از وضعیت اتصال، مصرف و سقف هر کانفیگ.')} ${toolbar()}${usersTable()}${bottomNote()}`;
 else if(state.view==='monitor')content=`${hero('انتخاب با شما، ثبت با رصد.','با فعال‌سازی، تأیید می‌کنید این کاربران درخواست گزارش مقصدها را داشته‌اند.',false)}<div class="card report-card"><div><h2>فعال‌سازی گروهی</h2><p>${r.settings.domains_enabled?'ثبت کلی فعال است.':'ثبت کلی خاموش است؛ از تنظیمات فعال کنید.'} تیک‌های کاربر و سیاست کلی با هم اعمال می‌شوند.</p></div><div class="hero-actions">${button('خاموش‌کردن همه','bulk-off','shield')}${button('فعال‌سازی کاربران فعلی','bulk-on','users',true)}</div></div>${usersTable()}${bottomNote()}`;
 else if(state.view==='domains')content=domainsView();
 else if(state.view==='settings')content=settingsView();
 else if(state.view==='audit')content=auditView();
 else if(state.view==='detail')content=detailView();
 else content=`${hero('گزارش‌های قابل استفاده','خروجی استاندارد با همان فیلتر زمانی که انتخاب کرده‌اید.',false)}${toolbar()}<section class="card report-card"><div><h2>گزارش مصرف کاربران</h2><p>شناسه، دانلود و آپلود بازه، سقف حجم و وضعیت ثبت دامنه · CSV</p></div>${button('دریافت CSV','export-users','down',true)}</section><section class="card report-card"><div><h2>گزارش مقصدهای اتصال</h2><p>نام دامنه، تعداد اتصال و آخرین مشاهده. حجم ناموجود به‌صورت خالی خروجی می‌شود.</p></div>${button('دریافت CSV','export-domains','down',true)}</section><section class="card report-card"><div><h2>نمای کامل گزارش</h2><p>داده‌های ساختاریافته برای پردازش و نگهداری شخصی · JSON</p></div>${button('دریافت JSON','export-json','down')}</section>${bottomNote()}`;
 $('#app').innerHTML=shell(notices()+content);
}
function navigate(view,user=null){state.view=view;state.user=user;state.query='';state.filter='all';state.page=1;history.replaceState(null,'','#'+view);load();window.scrollTo({top:0,behavior:'smooth'});}
function closeModal(){$('#overlay').innerHTML='';if(closeModal.focus)closeModal.focus.focus();}
function modal(title,body,actions=''){closeModal.focus=document.activeElement;$('#overlay').innerHTML=`<div class="modal-backdrop"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-head"><h2 id="modal-title">${title}</h2><button class="icon-btn" data-action="close-modal" aria-label="بستن">${icon('close')}</button></div><div class="modal-content">${body}</div>${actions?`<div class="modal-actions">${actions}</div>`:''}</section></div>`;$('.modal button, .modal input')?.focus();}
function confirmMonitoring(email,enabled){
 const all=email===null;
 modal(enabled?(all?'فعال‌سازی کاربران فعلی':'فعال‌سازی ثبت دامنه'):'خاموش‌کردن ثبت دامنه',`<p>${enabled?(all?'برای همهٔ کاربران فعلی پنل ثبت دامنه فعال می‌شود. کاربران آینده به تأیید جداگانه نیاز دارند.':'فقط نام دامنه و زمان اتصال این کاربر ثبت می‌شود. محتوای صفحه‌ها و پیام‌ها خوانده نمی‌شود.'):'ثبت متوقف می‌شود و گزارش دامنه‌های '+(all?'همهٔ کاربران':'این کاربر')+' از سامانه حذف خواهد شد.'}</p>${enabled?'<label class="check"><input id="consent-check" type="checkbox">تأیید می‌کنم کاربران انتخاب‌شده درخواست این گزارش را داشته‌اند.</label>':''}`,`${button('انصراف','close-modal','close')}<button class="btn primary" id="confirm-monitor">${enabled?'فعال‌سازی':'خاموش و حذف'}</button>`);
 $('#confirm-monitor').onclick=async()=>{if(enabled&&!$('#consent-check').checked){toast('تأیید درخواست کاربر لازم است.');return;}try{await mutate(all?'monitor-all':'monitor',all?{enabled}:{email,enabled});closeModal();await load();toast('تغییر ذخیره شد.');}catch(e){toast(e.message);}};
}
function help(){modal('رصد چطور کار می‌کند؟',`<p><strong>مصرف کاربران:</strong> اختلاف شمارنده‌های دانلود و آپلود 3x-ui ذخیره می‌شود. قبل از شروع جمع‌آوری، آمار روزانه در دسترس نیست.</p><p><strong>گزارش مقصد:</strong> access.log، نام مقصد و تعداد اتصال را می‌دهد؛ حجم هر سایت را ندارد. DNS هم حجم را مشخص نمی‌کند. ماژول اختیاری شمارندهٔ مقصد به Xray سفارشی نیاز دارد.</p><p><strong>دقت:</strong> اتصال می‌تواند پس‌زمینه، CDN یا برنامه باشد. ECH، IP و تونل دیگر می‌توانند مقصد را نامشخص کنند. زمان‌بندی مصرف نزدیک مرز ساعت بر اساس فاصلهٔ نمونه‌برداری تخمین زده می‌شود.</p><p><strong>نصب Ubuntu:</strong> راهنمای ریپو شامل نصب‌کننده، سرویس systemd، تنظیم اتصال و Nginx است. ابتدا مصرف کلی فعال می‌شود؛ ثبت دامنه را از پنل انتخاب کنید.</p><p><strong>هزینه:</strong> درخواست‌ها به پنل روی لوپ‌بک و پردازش لاگ محلی انجام می‌شوند. صفر بودن مصرف CPU و دیسک تضمین نمی‌شود.</p>`,button('متوجه شدم','close-modal','check',true));}
function download(content,type,name){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);toast('گزارش دریافت شد.');}
function csvCell(v){let text=String(v??'');if(/^[=+\-@\t\r]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';}
function reportReady(){if(state.report&&state.reportSelection===reportKey())return true;toast('در حال دریافت گزارش انتخاب‌شده؛ کمی صبر کنید.');return false;}
function exportCsv(domains=false){if(!reportReady())return;const r=state.report;const headings=domains?['domain','connections','last_seen_utc','measured_bytes']:['email','name','period','upload_bytes','download_bytes','config_upload_bytes','config_download_bytes','quota_bytes','domain_monitoring'];let users=r.users.filter(u=>(!state.user||u.email===state.user)&&(u.name+' '+u.email).toLowerCase().includes(state.query.toLowerCase())&&(state.filter==='all'||state.filter==='online'&&u.online||state.filter==='monitored'&&u.monitored));const rows=domains?r.domains.map(d=>[d.domain,d.connections,new Date(d.last*1000).toISOString(),d.bytes]):users.map(u=>[u.email,u.name,state.period,u.period_up,u.period_down,u.up,u.down,u.total,u.monitored]);download('\uFEFF'+[headings,...rows].map(row=>row.map(csvCell).join(',')).join('\r\n'),'text/csv;charset=utf-8',`rasad-${domains?'domains':'users'}-${state.period}-${state.mode}.csv`);}
function exportJson(){if(!reportReady())return;download(JSON.stringify(state.report,null,2),'application/json',`rasad-report-${state.period}-${state.mode}.json`);}
function loginScreen(){loadEpoch++;state.report=null;state.reportSelection=null;state.csrf='';$('#app').innerHTML=`<div class="login"><form class="card" id="login-form"><img src="/logo.svg" alt="رصد"><h1>به رصد وارد شوید</h1><p>مرکز مدیریت مصرف و گزارش کاربران 3x-ui</p><div class="field"><label for="username">نام کاربری</label><input id="username" autocomplete="username" required dir="ltr"></div><div class="field"><label for="password">رمز عبور</label><input id="password" type="password" autocomplete="current-password" required></div><button type="submit" class="btn primary">${icon('lock')}ورود به داشبورد</button></form></div>`;}
document.addEventListener('click',async e=>{
 const b=e.target.closest('button,a.brand');if(!b)return;
 if(b.matches('a.brand')){e.preventDefault();navigate('overview');return;}
 if(b.dataset.view){navigate(b.dataset.view,b.dataset.view==='domains'&&state.view==='detail'?state.user:null);return;}
 if(b.dataset.user){navigate('detail',b.dataset.user);return;}
 if(b.dataset.period){state.period=b.dataset.period;state.page=1;load();return;}
 if(b.dataset.page){state.page=Number(b.dataset.page);render();return;}
 const action=b.dataset.action;
 if(action==='refresh'){await load();toast('اطلاعات تازه‌سازی شد.');}
 if(action==='open-monitor')navigate('monitor');
 if(action==='help')help();
 if(action==='theme'){document.body.classList.toggle('dark');localStorage.setItem('rasad-theme',document.body.classList.contains('dark')?'dark':'light');}
 if(action==='menu')$('.sidebar').classList.toggle('open');
 if(action==='close-modal')closeModal();
 if(action==='monitor-user'){if(!reportReady())return;const u=state.report.users.find(u=>u.email===b.dataset.email);if(!u){toast('کاربر در گزارش تازه پیدا نشد.');return;}confirmMonitoring(u.email,!(u.selected&&u.consent));}
 if(action==='bulk-on'||action==='bulk-off'){if(!reportReady())return;confirmMonitoring(null,action==='bulk-on');}
 if(action==='setting-switch')b.setAttribute('aria-checked',b.getAttribute('aria-checked')==='true'?'false':'true');
 if(action==='export-users')exportCsv();
 if(action==='export-domains')exportCsv(true);
 if(action==='export-json')exportJson();
 if(action==='logout'){try{await api('logout',{});state.report=null;state.csrf='';loginScreen();}catch(err){toast(err.message);}}
});
document.addEventListener('input',e=>{if(e.target.id==='user-search'){const cursor=e.target.selectionStart;state.query=e.target.value;state.page=1;render();const field=$('#user-search');field.focus();field.setSelectionRange(cursor,cursor);}});
document.addEventListener('change',e=>{if(e.target.id==='domain-user'){state.user=e.target.value||null;load();}if(e.target.id==='user-filter'){state.filter=e.target.value;state.page=1;render();}});
document.addEventListener('submit',async e=>{e.preventDefault();const submit=$('button[type=submit]',e.target);if(submit)submit.disabled=true;try{if(e.target.id==='settings-form'){await mutate('settings',{scope:$('#scope').value,interval:Number($('#interval').value),retention:Number($('#retention').value),domains_enabled:$('#master-switch').getAttribute('aria-checked')==='true'});await load();toast('تنظیمات ذخیره شد.');}if(e.target.id==='login-form'){const result=await api('login',{username:$('#username').value,password:$('#password').value});state.csrf=result.csrf;await load();}}catch(err){toast(err.message);}finally{if(submit)submit.disabled=false;}});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();if(e.key==='Tab'&&$('.modal')){const focusables=[...$('.modal').querySelectorAll('button,input,select,a')],first=focusables[0],last=focusables.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}});
async function init(){
 if(localStorage.getItem('rasad-theme')==='dark')document.body.classList.add('dark');
 $('#app').innerHTML='<div class="app-loading">در حال آماده‌سازی رصد…</div>';
 try{const response=await fetch('/runtime.json',{cache:'no-store'});if(!response.ok)throw new Error('سرویس در دسترس نیست.');state.mode=(await response.json()).mode;if(!['demo','live'].includes(state.mode))throw new Error('حالت اجرا نامعتبر است.');const hash=location.hash.slice(1);if(viewNames[hash]&&hash!=='detail')state.view=hash;if(state.mode==='live'){try{state.csrf=(await api('session')).csrf;}catch(e){return;}}await load();}
 catch(e){$('#app').innerHTML='<div class="app-loading">اتصال برقرار نشد؛ صفحه را دوباره بارگذاری کنید.</div>';}
}
init();
setInterval(()=>{if(state.mode==='live'&&state.report&&!document.hidden&&!$('#overlay').children.length&&state.view!=='settings')load();},60000);
