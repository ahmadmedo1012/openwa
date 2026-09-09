/**
 * Dashboard HTML pages — self-contained (no external assets), Arabic RTL,
 * WhatsApp-inspired dark theme. Rendered as template strings; the dynamic
 * dashboard shell hydrates via /dash/api/state polling.
 */
import { escapeHtml } from "./dashboard.js";
const BASE_CSS = `
:root{
  --bg:#0b141a; --panel:#111b21; --panel2:#202c33; --line:#2a3942;
  --text:#e9edef; --muted:#8696a0; --brand:#00a884; --brand-ink:#054339;
  --danger:#ef697a; --warn:#f0b232; --info:#53bdeb;
}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI",system-ui,-apple-system,"Noto Sans Arabic",sans-serif;
  background:var(--bg);color:var(--text);min-height:100vh}
a{color:var(--info)}
.card{background:var(--panel);border:1px solid var(--line);border-radius:16px}
.btn{border:none;border-radius:10px;padding:10px 16px;font-size:14px;font-weight:700;
  cursor:pointer;transition:filter .15s,transform .05s;display:inline-flex;gap:8px;align-items:center;justify-content:center}
.btn:active{transform:scale(.97)}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-primary{background:var(--brand);color:var(--brand-ink)}
.btn-primary:hover:not(:disabled){filter:brightness(1.1)}
.btn-danger{background:transparent;color:var(--danger);border:1px solid var(--danger)}
.btn-danger:hover:not(:disabled){background:rgba(239,105,122,.12)}
.btn-ghost{background:var(--panel2);color:var(--text)}
.btn-ghost:hover:not(:disabled){filter:brightness(1.15)}
input{background:var(--panel2);border:1px solid var(--line);border-radius:10px;color:var(--text);
  padding:11px 14px;font-size:15px;outline:none;width:100%}
input:focus{border-color:var(--brand)}
`;
export function disabledPage() {
    return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>OpenWA</title><style>${BASE_CSS}</style></head>
<body style="display:grid;place-items:center">
<div class="card" style="padding:32px;max-width:420px;text-align:center">
<h2>لوحة OpenWA غير مفعّلة</h2>
<p style="color:var(--muted)">عيّن المتغيرين <code>DASHBOARD_USERNAME</code> و
<code>DASHBOARD_PASSWORD</code> في خدمة Render لتفعيلها.</p>
</div></body></html>`;
}
export function loginPage(error) {
    return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>تسجيل الدخول — OpenWA</title><style>${BASE_CSS}
.wrap{min-height:100vh;display:grid;place-items:center;padding:20px}
.card{padding:36px 28px;width:100%;max-width:380px}
.logo{width:64px;height:64px;border-radius:18px;background:var(--brand);
  display:grid;place-items:center;margin:0 auto 18px}
h1{font-size:20px;margin:0 0 6px;text-align:center}
.sub{color:var(--muted);font-size:13px;text-align:center;margin:0 0 24px}
label{display:block;font-size:13px;color:var(--muted);margin:14px 0 6px}
.err{background:rgba(239,105,122,.12);border:1px solid var(--danger);color:var(--danger);
  border-radius:10px;padding:10px 14px;font-size:13px;margin-bottom:16px;display:none}
</style></head><body><div class="wrap"><form class="card" method="post" action="/login">
<div class="logo"><svg width="34" height="34" viewBox="0 0 24 24" fill="#054339">
<path d="M12 2a10 10 0 0 0-8.6 15.1L2 22l5-1.3A10 10 0 1 0 12 2Zm0 18.2a8.2 8.2 0 0 1-4.2-1.2l-.3-.2-3 .8.8-2.9-.2-.3A8.2 8.2 0 1 1 12 20.2Zm4.6-6.1c-.3-.1-1.5-.7-1.7-.8-.2-.1-.4-.1-.6.1l-.8 1c-.1.2-.3.2-.5.1a6.7 6.7 0 0 1-3.3-2.9c-.1-.2 0-.4.1-.5l.7-.8c.1-.2.1-.4 0-.6L9.7 7.9c-.2-.5-.4-.4-.6-.4h-.5c-.2 0-.5.1-.7.3a3 3 0 0 0-.9 2.2c0 1.3.9 2.6 1 2.7a11 11 0 0 0 4.2 3.7c1.6.6 2.2.5 2.7.4.5-.1 1.5-.6 1.7-1.2.2-.6.2-1.1.1-1.2 0-.1-.2-.2-.4-.3Z"/></svg></div>
<h1>لوحة إدارة OpenWA</h1>
<p class="sub">إدارة جلسات WhatsApp — SubNation</p>
<div class="err" id="err" role="alert">${error ? escapeHtml(error) : ""}</div>
<label for="u">اسم المستخدم</label>
<input id="u" name="username" autocomplete="username" autofocus required>
<label for="p">كلمة المرور</label>
<input id="p" name="password" type="password" autocomplete="current-password" required>
<button class="btn btn-primary" style="width:100%;margin-top:22px;height:46px" type="submit">دخول</button>
</form></div>
${error ? "<script>document.getElementById('err').style.display='block'</script>" : ""}
</body></html>`;
}
// ── Main dashboard shell ─────────────────────────────────────────────────────
// Status/delivery labels live INSIDE the page's JS (single source for the
// client render); the server template only provides the static shell.
export function dashboardPage() {
    return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>لوحة إدارة OpenWA</title><style>${BASE_CSS}
header{display:flex;align-items:center;gap:12px;padding:16px 22px;
  background:var(--panel);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:5}
header .logo{width:38px;height:38px;border-radius:11px;background:var(--brand);
  display:grid;place-items:center;margin:0}
header h1{font-size:16px;margin:0}
header .sub{font-size:11px;color:var(--muted);margin:2px 0 0}
header form{margin-inline-start:auto}
main{max-width:1060px;margin:0 auto;padding:22px 18px 60px}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.stat{padding:16px;border-radius:14px;background:var(--panel);border:1px solid var(--line)}
.stat .v{font-size:26px;font-weight:800}
.stat .k{font-size:12px;color:var(--muted);margin-top:2px}
.stat.ok .v{color:var(--brand)} .stat.warn .v{color:var(--warn)} .stat.bad .v{color:var(--danger)}
section.card{padding:20px;margin-bottom:18px}
section h2{font-size:15px;margin:0 0 14px;display:flex;align-items:center;gap:8px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
table{width:100%;border-collapse:collapse;font-size:14px}
th{color:var(--muted);font-size:12px;text-align:right;padding:10px 12px;
  border-bottom:1px solid var(--line);font-weight:600}
td{padding:13px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:4px 11px;border-radius:99px;font-size:12px;font-weight:700;white-space:nowrap}
.badge.ok{background:rgba(0,168,132,.15);color:var(--brand)}
.badge.warn{background:rgba(240,178,50,.15);color:var(--warn)}
.badge.info{background:rgba(83,189,235,.15);color:var(--info)}
.badge.bad{background:rgba(239,105,122,.15);color:var(--danger)}
.badge.n{background:var(--panel2);color:var(--muted)}
.mono{direction:ltr;text-align:left;font-family:ui-monospace,monospace;font-size:13px;color:var(--muted)}
.actions{display:flex;gap:6px;flex-wrap:wrap}
.actions .btn{padding:7px 12px;font-size:12.5px}
.empty{padding:38px;text-align:center;color:var(--muted);font-size:14px}
.toast{position:fixed;bottom:22px;right:22px;left:22px;max-width:420px;margin-inline:auto;
  background:var(--panel2);border:1px solid var(--line);border-radius:12px;padding:13px 18px;
  font-size:14px;box-shadow:0 8px 30px rgba(0,0,0,.5);opacity:0;pointer-events:none;
  transition:opacity .25s;z-index:50}
.toast.show{opacity:1}
.toast.err{border-color:var(--danger);color:var(--danger)}
.toast.ok{border-color:var(--brand);color:var(--brand)}
dialog{border:none;border-radius:16px;background:var(--panel);color:var(--text);
  padding:0;max-width:400px;width:92vw}
dialog::backdrop{background:rgba(0,0,0,.65)}
.modal{padding:24px}
.modal h3{margin:0 0 6px;font-size:17px}
.modal .hint{color:var(--muted);font-size:13px;margin:4px 0 16px;line-height:1.7}
.qrbox{display:grid;place-items:center;padding:14px;background:#fff;border-radius:12px;margin:6px 0 4px}
.qrbox img{width:280px;height:280px;display:block}
.codebox{direction:ltr;text-align:center;font-family:ui-monospace,monospace;font-size:24px;
  letter-spacing:4px;background:var(--panel2);border:1px dashed var(--line);
  border-radius:12px;padding:16px;margin:8px 0}
footer{color:var(--muted);font-size:11.5px;text-align:center;padding:18px}
.spin{width:16px;height:16px;border:2px solid var(--brand);border-top-color:transparent;
  border-radius:50%;animation:sp 1s linear infinite;display:inline-block}
@keyframes sp{to{transform:rotate(360deg)}}
@media(max-width:640px){
  .hidem{display:none}
  main{padding:14px 10px 50px}
  td,th{padding:9px 8px}
}
</style></head><body>
<header>
  <div class="logo"><svg width="22" height="22" viewBox="0 0 24 24" fill="#054339">
  <path d="M12 2a10 10 0 0 0-8.6 15.1L2 22l5-1.3A10 10 0 1 0 12 2Zm0 18.2a8.2 8.2 0 0 1-4.2-1.2l-.3-.2-3 .8.8-2.9-.2-.3A8.2 8.2 0 1 1 12 20.2Zm4.6-6.1c-.3-.1-1.5-.7-1.7-.8-.2-.1-.4-.1-.6.1l-.8 1c-.1.2-.3.2-.5.1a6.7 6.7 0 0 1-3.3-2.9c-.1-.2 0-.4.1-.5l.7-.8c.1-.2.1-.4 0-.6L9.7 7.9c-.2-.5-.4-.4-.6-.4h-.5c-.2 0-.5.1-.7.3a3 3 0 0 0-.9 2.2c0 1.3.9 2.6 1 2.7a11 11 0 0 0 4.2 3.7c1.6.6 2.2.5 2.7.4.5-.1 1.5-.6 1.7-1.2.2-.6.2-1.1.1-1.2 0-.1-.2-.2-.4-.3Z"/></svg></div>
  <div><h1>لوحة إدارة OpenWA</h1><p class="sub" id="hdr-sub">بوابة جلسات WhatsApp</p></div>
  <form method="post" action="/logout"><button class="btn btn-ghost" type="submit">خروج</button></form>
</header>
<main>
  <div class="stats">
    <div class="stat" id="st-total"><div class="v">—</div><div class="k">إجمالي الجلسات</div></div>
    <div class="stat ok" id="st-ready"><div class="v">—</div><div class="k">جاهزة</div></div>
    <div class="stat warn" id="st-pending"><div class="v">—</div><div class="k">تنتظر الربط</div></div>
    <div class="stat" id="st-delivery"><div class="v">—</div><div class="k">آخر حالة تسليم</div></div>
  </div>

  <section class="card">
    <h2>➕ إضافة جلسة جديدة</h2>
    <form class="row" id="add-form">
      <input id="add-name" placeholder="اسم الجلسة (إنجليزي، مثل: subnation-otp)"
        style="flex:1;min-width:220px" autocomplete="off" required>
      <button class="btn btn-primary" type="submit" id="add-btn" style="height:44px">إنشاء الجلسة</button>
    </form>
    <p class="hint" style="color:var(--muted);font-size:12.5px;margin:10px 0 0">
      بعد الإنشاء اضغط «تشغيل» ثم اربطها عبر QR أو رمز الهاتف. الجلسة تصبح «جاهزة» فور الربط.
    </p>
  </section>

  <section class="card">
    <h2>📱 الجلسات <button class="btn btn-ghost" id="refresh" style="margin-inline-start:auto;
      padding:6px 12px;font-size:12.5px">↻ تحديث</button></h2>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>الاسم</th><th>الحالة</th><th class="hidem">آخر ربط</th>
      <th class="hidem">آخر تسليم</th><th class="hidem">أُنشئت</th><th>إجراءات</th></tr></thead>
      <tbody id="rows"><tr><td colspan="6" class="empty"><span class="spin"></span></td></tr></tbody>
    </table></div>
    <div id="empty-state" class="empty" style="display:none">لا توجد جلسات — أضف واحدة من الأعلى</div>
  </section>

  <footer>OpenWA Gateway — إدارة الجلسات تتم عبر هذه اللوحة فقط؛ مفتاح API لا يظهر في المتصفح أبدًا.</footer>
</main>

<div class="toast" id="toast" role="status"></div>

<dialog id="qr-modal"><div class="modal">
  <h3>ربط عبر رمز QR</h3>
  <p class="hint" id="qr-modal-name"></p>
  <div class="qrbox" id="qr-box"><span class="spin"></span></div>
  <p class="hint" style="text-align:center">افتح واتساب في الهاتف ←<br>
  <b>الإعدادات ← الأجهزة المرتبطة ← ربط جهاز</b><br>ثم وجّه الكاميرا نحو الرمز. يُحدَّث تلقائيًا.</p>
  <button class="btn btn-primary" style="width:100%;height:44px" onclick="closeModal('qr-modal')">إغلاق</button>
</div></dialog>

<dialog id="pair-modal"><div class="modal">
  <h3>ربط برمز الهاتف</h3>
  <p class="hint">الأكثر موثوقية من QR: أدخل رقم الجلسة (بصيغة دولية) وسيظهر رمز من 8 أرقام تُدخله في الهاتف.</p>
  <form class="row" id="pair-form">
    <input id="pair-phone" placeholder="21891XXXXXXX" inputmode="numeric" dir="ltr"
      style="flex:1;min-width:180px" autocomplete="off" required>
    <button class="btn btn-primary" type="submit" id="pair-btn" style="height:44px">إصدار الرمز</button>
  </form>
  <p class="hint" id="pair-modal-name" style="margin-top:14px"></p>
  <div id="pair-result" style="display:none">
    <p class="hint" style="text-align:center">في واتساب افتح:<br>
    <b>الإعدادات ← الأجهزة المرتبطة ← ربط جهاز برقم الهاتف بدلاً من QR</b></p>
    <div class="codebox" id="pair-code"></div>
    <button class="btn btn-ghost" id="pair-copy" style="width:100%;margin-top:8px;height:42px">نسخ الرمز</button>
  </div>
  <button class="btn btn-primary" style="width:100%;height:44px;margin-top:14px"
    onclick="closeModal('pair-modal')">إغلاق</button>
</div></dialog>

<dialog id="del-modal"><div class="modal">
  <h3>حذف الجلسة</h3>
  <p class="hint">سيتم إيقاف الجلسة <b id="del-name"></b> ومسح اعتمادها نهائيًا —
  ستحتاج لربط رقم واتساب من جديد بعد الحذف. لا يمكن التراجع.</p>
  <div class="row">
    <button class="btn btn-danger" id="del-confirm" style="flex:1;height:46px">نعم، احذف نهائيًا</button>
    <button class="btn btn-primary" style="flex:1;height:46px"
      onclick="closeModal('del-modal')">إلغاء</button>
  </div>
</div></dialog>

<script>
const $=id=>document.getElementById(id);
let CURRENT=[],INFO={};
let target={qr:null,pair:null,del:null};
let pollTimer=null,qrTimer=null;

function esc(s){return String(s??"").replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function toast(msg,ok){const t=$('toast');t.textContent=msg;t.className='toast show '+(ok?'ok':'err');
  clearTimeout(t._t);t._t=setTimeout(()=>t.className='toast',3800)}
function closeModal(id){$(id).close()}

const STATUS={ready:'جاهزة ✓',qr_ready:'تنتظر الربط',authenticating:'جارٍ التحقق',
  initializing:'جارٍ التشغيل',connecting:'جارٍ الاتصال',disconnected:'منقطعة',failed:'فشلت',created:'أُنشئت'};
const STATUS_CLS={ready:'ok',qr_ready:'warn',authenticating:'info',initializing:'info',
  connecting:'info',disconnected:'bad',failed:'bad',created:'info'};
const DELIVERY={'1':'قيد الإرسال','2':'وصلت للخادم','3':'تم التسليم','4':'قُرئت'};

function fmtDate(iso){if(!iso)return '—';const d=new Date(iso);
  return d.toLocaleDateString('ar-LY',{day:'numeric',month:'short'})+' '+
  d.toLocaleTimeString('ar-LY',{hour:'2-digit',minute:'2-digit'})}
// عمر آخر snapshot محفوظ — عرض مختصر بالعربية
function fmtAge(ms){if(ms==null||isNaN(ms))return '—';const s=Math.max(0,Math.round(ms/1000));
  if(s<60)return s+' ث';const m=Math.floor(s/60);if(m<60)return m+' د';return Math.floor(m/60)+' س'}

async function api(path,opts){const r=await fetch(path,Object.assign({headers:{'Content-Type':'application/json'}},opts));
  let b=null;try{b=await r.json()}catch{}
  if(!r.ok)throw new Error((b&&b.error)||('HTTP '+r.status));
  return b}

async function load(){
  try{
    const d=await api('/dash/api/state');
    CURRENT=d.sessions;INFO=d.info||{};
    render();
  }catch(e){if(String(e.message).includes('401')||String(e.message).includes('unauthorized')){location.reload();return}
    toast('تعذر تحديث الحالة: '+e.message)}
}
function render(){
  const rows=$('rows'),empty=$('empty-state');
  $('st-total').querySelector('.v').textContent=CURRENT.length;
  $('st-ready').querySelector('.v').textContent=CURRENT.filter(s=>s.status==='ready').length;
  $('st-pending').querySelector('.v').textContent=CURRENT.filter(s=>['qr_ready','authenticating','initializing','connecting','created'].includes(s.status)).length;
  const lastDel=CURRENT.map(s=>s.lastDeliveryStatus).filter(Boolean).pop();
  $('st-delivery').querySelector('.v').textContent=lastDel?(DELIVERY[lastDel]||lastDel):'—';
  const up=INFO.uptimeSec?Math.floor(INFO.uptimeSec/3600)+'س '+Math.floor(INFO.uptimeSec%3600/60)+'د':'—';
  $('hdr-sub').textContent='بوابة جلسات WhatsApp — تشغيل '+up+(INFO.persist?' — حفظ الاعتمادات مفعّل':'');
  if(!CURRENT.length){rows.innerHTML='';empty.style.display='block';return}
  empty.style.display='none';
  rows.innerHTML=CURRENT.map(s=>{
    const st=STATUS[s.status]||s.status,cls=STATUS_CLS[s.status]||'n';
    const actions=[
      (s.status==='ready')?'':'<button class="btn btn-primary" data-a="start" data-id="'+esc(s.id)+'">▶ تشغيل</button>',
      '<button class="btn btn-ghost" data-a="qr" data-id="'+esc(s.id)+'">QR</button>',
      (s.status==='ready')?'':'<button class="btn btn-ghost" data-a="pair" data-id="'+esc(s.id)+'">رمز ربط</button>',
      '<button class="btn btn-danger" data-a="del" data-id="'+esc(s.id)+'">حذف</button>',
    ].filter(Boolean).join('');
    return '<tr><td><b>'+esc(s.name)+'</b><div class="mono" style="font-size:11px">'+esc(s.id)+'</div>'+
    (s.accountDigits?'<div class="mono" style="font-size:11px;margin-top:2px">👤 '+esc(s.accountDigits)+
      (s.accountName?' · '+esc(s.accountName):'')+
      (s.persistAgeMs!=null?' · لقطة: '+fmtAge(s.persistAgeMs):'')+'</div>':'')+
    '</td>'+
    '<td><span class="badge '+cls+'">'+esc(st)+'</span></td>'+
    '<td class="hidem mono">'+fmtDate(s.lastReadyAt)+'</td>'+
    '<td class="hidem">'+(s.lastDeliveryStatus?esc(DELIVERY[s.lastDeliveryStatus]||s.lastDeliveryStatus):'—')+'</td>'+
    '<td class="hidem mono">'+fmtDate(s.createdAt)+'</td>'+
    '<td><div class="actions">'+actions+'</div></td></tr>';
  }).join('');
}

document.addEventListener('click',async e=>{
  const btn=e.target.closest('[data-a]');if(!btn)return;
  const id=btn.getAttribute('data-id'),a=btn.getAttribute('data-a');
  const s=CURRENT.find(x=>x.id===id);if(!s)return;
  if(a==='start'){btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
    try{await api('/dash/api/sessions/'+encodeURIComponent(id)+'/start',{method:'POST'});
      toast('بدأ تشغيل «'+s.name+'» — انتظر ظهور QR',true);await load()}
    catch(err){toast(err.message)}
    btn.disabled=false;render()}
  if(a==='qr'){target.qr=s;$('qr-modal-name').textContent='الجلسة: '+s.name;
    $('qr-box').innerHTML='<span class="spin"></span>';$('qr-modal').showModal();refreshQr()}
  if(a==='pair'){target.pair=s;$('pair-modal-name').textContent='الجلسة: '+s.name;
    $('pair-result').style.display='none';$('pair-phone').value='';$('pair-modal').showModal()}
  if(a==='del'){target.del=s;$('del-name').textContent=s.name;$('del-modal').showModal()}
});

async function refreshQr(){
  if(!$('qr-modal').open){clearInterval(qrTimer);qrTimer=null;return}
  if(!target.qr)return;
  try{const d=await api('/dash/api/sessions/'+encodeURIComponent(target.qr.id)+'/qr');
    if(d.qrImage){$('qr-box').innerHTML='<img alt="QR" src="'+d.qrImage+'">';await load();return}
    $('qr-box').innerHTML='<span class="spin"></span><p style="color:#111;margin-top:8px;direction:rtl">'+
      (d.status==='ready'?'✓ الجلسة جاهزة — أغلق النافذة':'لا يوجد QR — اضغط «تشغيل» أولًا')+'</p>';
    await load();
  }catch{}
}
function startQrPolling(){if(qrTimer)clearInterval(qrTimer);qrTimer=setInterval(refreshQr,3000);refreshQr()}
$('qr-modal').addEventListener('close',()=>{clearInterval(qrTimer);qrTimer=null});

$('add-form').addEventListener('submit',async e=>{
  e.preventDefault();const name=$('add-name').value.trim();const btn=$('add-btn');
  btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
  try{await api('/dash/api/sessions',{method:'POST',body:JSON.stringify({name})});
    $('add-name').value='';toast('أُنشئت الجلسة «'+name+'» — اضغط تشغيل ثم اربطها',true);await load()}
  catch(err){toast(err.message)}
  btn.disabled=false;btn.textContent='إنشاء الجلسة';
});

$('pair-form').addEventListener('submit',async e=>{
  e.preventDefault();if(!target.pair)return;
  const phone=$('pair-phone').value.replace(/[^0-9]/g,'');
  if(phone.length<10){toast('أدخل رقمًا دوليًا صحيحًا مثل 21891XXXXXXX');return}
  const btn=$('pair-btn');btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
  try{const d=await api('/dash/api/sessions/'+encodeURIComponent(target.pair.id)+'/pair-code',
    {method:'POST',body:JSON.stringify({phone})});
    $('pair-code').textContent=d.code;$('pair-result').style.display='block';
    $('pair-copy').onclick=async()=>{try{await navigator.clipboard.writeText(d.code);
      $('pair-copy').textContent='تم النسخ ✓';setTimeout(()=>$('pair-copy').textContent='نسخ الرمز',2000)}catch{}};
    await load()}
  catch(err){toast(err.message)}
  btn.disabled=false;btn.textContent='إصدار الرمز';
});

$('del-confirm').addEventListener('click',async()=>{
  if(!target.del)return;const btn=$('del-confirm');btn.disabled=true;btn.innerHTML='<span class="spin"></span>';
  try{await api('/dash/api/sessions/'+encodeURIComponent(target.del.id),{method:'DELETE'});
    toast('حُذفت الجلسة «'+target.del.name+'» نهائيًا',true);closeModal('del-modal');await load()}
  catch(err){toast(err.message)}
  btn.disabled=false;btn.textContent='نعم، احذف نهائيًا';
});

$('refresh').addEventListener('click',()=>load());
document.addEventListener('dialog:qr',()=>startQrPolling());
const origShow=HTMLDialogElement.prototype.showModal;
HTMLDialogElement.prototype.showModal=function(){origShow.call(this);
  if(this.id==='qr-modal')startQrPolling()};
load();
pollTimer=setInterval(load,5000);
</script>
</body></html>`;
}
