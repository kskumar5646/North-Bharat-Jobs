import { runMonitor } from './monitor.js';
import { sha256Hex } from './verification.js';

const COOKIE = 'nbj_admin_session';
const SESSION_DAYS = 7;
const PUBLIC_TYPES = ['job','recruitment','admit_card','result','answer_key','syllabus','admission','scholarship','update'];

const htmlHeaders = { 'content-type':'text/html; charset=UTF-8', 'cache-control':'public, max-age=300' };
const jsonHeaders = { 'content-type':'application/json; charset=UTF-8', 'cache-control':'no-store' };

function json(data,status=200) { return new Response(JSON.stringify(data),{status,headers:jsonHeaders}); }
function nowIso(){return new Date().toISOString();}
function siteOrigin(request){return new URL(request.url).origin;}
function safeJson(request){ return request.json().catch(()=>({})); }
function esc(s=''){return String(s).replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2',salt:enc.encode(salt),iterations:120000,hash:'SHA-256'},key,256);
  return `${salt}$${[...new Uint8Array(bits)].map(b=>b.toString(16).padStart(2,'0')).join('')}`;
}
async function verifyPassword(password, stored) {
  if (!stored?.includes('$')) return false;
  const [salt, expected] = stored.split('$');
  const actual = await hashPassword(password,salt);
  return actual.split('$')[1] === expected;
}
function randomToken(){ const a=new Uint8Array(32); crypto.getRandomValues(a); return [...a].map(b=>b.toString(16).padStart(2,'0')).join(''); }
function cookieToken(request){ const m=(request.headers.get('cookie')||'').match(new RegExp(`${COOKIE}=([^;]+)`)); return m?.[1] || null; }
function cookieHeader(token,maxAge){ return `${COOKIE}=${token}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`; }

async function adminFromRequest(env, request) {
  const token=cookieToken(request); if(!token) return null;
  const hash=await sha256Hex(token);
  const row=await env.DB.prepare(`SELECT a.* FROM sessions s JOIN admins a ON a.id=s.admin_id WHERE s.token_hash=? AND s.expires_at>?`).bind(hash,nowIso()).first();
  return row || null;
}
async function requireAdmin(env, request){ const a=await adminFromRequest(env,request); return a; }
async function audit(env, adminId, action, type=null, id=null, meta=null){ await env.DB.prepare(`INSERT INTO audit_logs(admin_id,action,target_type,target_id,metadata_json) VALUES(?,?,?,?,?)`).bind(adminId,action,type,id,meta?JSON.stringify(meta):null).run(); }

async function ensureAdmin(env){
  const count=await env.DB.prepare(`SELECT COUNT(*) c FROM admins`).first();
  if(Number(count?.c||0)>0) return;
  if(!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD) return;
  const salt=randomToken().slice(0,32);
  const ph=await hashPassword(env.ADMIN_PASSWORD,salt);
  await env.DB.prepare(`INSERT OR IGNORE INTO admins(email,password_hash) VALUES(?,?)`).bind(env.ADMIN_EMAIL.toLowerCase().trim(),ph).run();
}

async function publicList(env, url){
  const type=url.searchParams.get('type');
  const q=(url.searchParams.get('q')||'').trim();
  const page=Math.max(1,Number(url.searchParams.get('page')||1));
  const limit=Math.min(30,Math.max(1,Number(url.searchParams.get('limit')||15)));
  const offset=(page-1)*limit;
  const where=[`status='published'`,`(published_at IS NULL OR published_at>=datetime('now','-365 day'))`];
  const args=[];
  if(type && PUBLIC_TYPES.includes(type)){where.push('type=?');args.push(type);}
  if(q){where.push(`(title LIKE ? OR organization LIKE ? OR qualification LIKE ? OR category LIKE ?)`);const x=`%${q}%`;args.push(x,x,x,x);}
  const sql=`SELECT id,slug,type,title,organization,category,location,qualification,vacancies,age_limit,fee,application_start,last_date,exam_date,official_url,apply_url,notification_url,published_at FROM items WHERE ${where.join(' AND ')} ORDER BY COALESCE(published_at,created_at) DESC,id DESC LIMIT ? OFFSET ?`;
  const rows=(await env.DB.prepare(sql).bind(...args,limit,offset).all()).results||[];
  return json({ok:true,page,limit,items:rows});
}

async function publicItem(env, slug){
  const item=await env.DB.prepare(`SELECT * FROM items WHERE slug=? AND status='published' AND (published_at IS NULL OR published_at>=datetime('now','-365 day'))`).bind(slug).first();
  if(!item) return json({ok:false,error:'Not found'},404);
  return json({ok:true,item});
}

async function adminDashboard(env){
  const queries = await Promise.all([
    env.DB.prepare(`SELECT COUNT(*) c FROM items WHERE status='published'`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM items WHERE status='verification_required'`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM sources WHERE enabled=1 AND last_error IS NOT NULL`).first(),
    env.DB.prepare(`SELECT COUNT(*) c FROM notifications WHERE read_at IS NULL`).first()
  ]);
  return json({ok:true,stats:{published:Number(queries[0]?.c||0),verification_required:Number(queries[1]?.c||0),source_errors:Number(queries[2]?.c||0),unread_notifications:Number(queries[3]?.c||0)}});
}

async function adminApi(env, request, url, admin){
  const path=url.pathname;
  if(path==='/api/admin/me') return json({ok:true,admin:{id:admin.id,email:admin.email}});
  if(path==='/api/admin/dashboard') return adminDashboard(env);
  if(path==='/api/admin/sources') return json({ok:true,sources:(await env.DB.prepare(`SELECT * FROM sources ORDER BY role,priority,id`).all()).results||[]});
  if(path==='/api/admin/items') return json({ok:true,items:(await env.DB.prepare(`SELECT * FROM items WHERE status IN ('verification_required','published') ORDER BY updated_at DESC LIMIT 100`).all()).results||[]});
  if(path==='/api/admin/notifications') return json({ok:true,notifications:(await env.DB.prepare(`SELECT * FROM notifications ORDER BY created_at DESC LIMIT 100`).all()).results||[]});
  if(path==='/api/admin/runs') return json({ok:true,runs:(await env.DB.prepare(`SELECT * FROM monitor_runs ORDER BY id DESC LIMIT 100`).all()).results||[]});
  if(path==='/api/admin/audit') return json({ok:true,logs:(await env.DB.prepare(`SELECT * FROM audit_logs ORDER BY id DESC LIMIT 100`).all()).results||[]});
  if(path==='/api/admin/verification-logs') return json({ok:true,logs:(await env.DB.prepare(`SELECT * FROM verification_events ORDER BY id DESC LIMIT 100`).all()).results||[]});
  if(path==='/api/admin/discover') {
    const name=url.searchParams.get('source'); if(!name) return json({ok:false,error:'Missing source'},400);
    const result=await runMonitor(env,name); await audit(env,admin.id,'manual_discover','source',name); return json({ok:true,...result});
  }
  if(path==='/api/admin/item/verify' && request.method==='POST') {
    const body=await safeJson(request); const id=Number(body.id); if(!id) return json({ok:false,error:'Invalid id'},400);
    await env.DB.prepare(`UPDATE items SET status='published',verification_status='admin_verified',last_verified_at=?,published_at=COALESCE(published_at,?),updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(nowIso(),nowIso(),id).run();
    await audit(env,admin.id,'verify_publish','item',id); return json({ok:true});
  }
  if(path==='/api/admin/item/reject' && request.method==='POST') {
    const body=await safeJson(request); const id=Number(body.id); if(!id) return json({ok:false,error:'Invalid id'},400);
    await env.DB.prepare(`UPDATE items SET status='rejected',verification_status='rejected',updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(id).run();
    await audit(env,admin.id,'reject','item',id); return json({ok:true});
  }
  if(path==='/api/admin/source/save' && request.method==='POST') {
    const b=await safeJson(request); const id=Number(b.id); if(!id) return json({ok:false,error:'Invalid id'},400);
    await env.DB.prepare(`UPDATE sources SET name=?,base_url=?,allowed_domains=?,adapter=?,fallback_key=?,priority=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(String(b.name||''),String(b.base_url||''),String(b.allowed_domains||''),String(b.adapter||'generic'),String(b.fallback_key||'*'),Number(b.priority||50),b.enabled?1:0,id).run();
    await audit(env,admin.id,'update_source','source',id,b); return json({ok:true});
  }
  if(path==='/api/admin/password' && request.method==='POST') {
    const b=await safeJson(request); if(!b.current || !b.next || String(b.next).length<10) return json({ok:false,error:'Password must be at least 10 characters'},400);
    if(!(await verifyPassword(b.current,admin.password_hash))) return json({ok:false,error:'Current password is incorrect'},403);
    const salt=randomToken().slice(0,32); const ph=await hashPassword(String(b.next),salt);
    await env.DB.prepare(`UPDATE admins SET password_hash=? WHERE id=?`).bind(ph,admin.id).run(); await audit(env,admin.id,'change_password','admin',admin.id); return json({ok:true});
  }
  if(path==='/api/admin/email' && request.method==='POST') {
    const b=await safeJson(request); const email=String(b.email||'').trim().toLowerCase(); if(!/^\S+@\S+\.\S+$/.test(email)) return json({ok:false,error:'Invalid email'},400);
    await env.DB.prepare(`UPDATE admins SET email=? WHERE id=?`).bind(email,admin.id).run(); await audit(env,admin.id,'change_email','admin',admin.id); return json({ok:true});
  }
  if(path==='/api/admin/notification/read' && request.method==='POST') { const b=await safeJson(request); await env.DB.prepare(`UPDATE notifications SET read_at=? WHERE id=?`).bind(nowIso(),Number(b.id)).run(); return json({ok:true}); }
  return json({ok:false,error:'Not found'},404);
}

function loginPage(){return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login — North Bharat Jobs</title><style>body{font-family:system-ui;background:#eef3f9;display:grid;place-items:center;min-height:100vh;margin:0}.box{background:white;padding:28px;border-radius:16px;box-shadow:0 10px 35px #0001;width:min(380px,90%)}input,button{width:100%;padding:12px;margin:7px 0;border-radius:9px;border:1px solid #ccd5e2;box-sizing:border-box}button{background:#155eef;color:white;border:0;font-weight:700}</style></head><body><form class="box" method="post" action="/api/admin/login"><h1>North Bharat Jobs</h1><p>Admin Portal</p><input name="email" type="email" placeholder="Admin email" required><input name="password" type="password" placeholder="Password" required><button>Login</button></form></body></html>`,{headers:htmlHeaders});}

async function handleLogin(env,request){
  const ct=request.headers.get('content-type')||''; let email='',password='';
  if(ct.includes('application/json')){const b=await safeJson(request);email=String(b.email||'');password=String(b.password||'');}
  else {const f=await request.formData();email=String(f.get('email')||'');password=String(f.get('password')||'');}
  await ensureAdmin(env); const admin=await env.DB.prepare(`SELECT * FROM admins WHERE email=?`).bind(email.toLowerCase().trim()).first();
  if(!admin || !(await verifyPassword(password,admin.password_hash))) return new Response('Invalid credentials',{status:401,headers:{'content-type':'text/plain'}});
  const token=randomToken(); const hash=await sha256Hex(token); const expires=new Date(Date.now()+SESSION_DAYS*86400000).toISOString();
  await env.DB.prepare(`INSERT INTO sessions(token_hash,admin_id,expires_at) VALUES(?,?,?)`).bind(hash,admin.id,expires).run(); await env.DB.prepare(`UPDATE admins SET last_login_at=? WHERE id=?`).bind(nowIso(),admin.id).run();
  if(ct.includes('application/json')) return new Response(JSON.stringify({ok:true}),{headers:{...jsonHeaders,'set-cookie':cookieHeader(token,SESSION_DAYS*86400)}});
  return Response.redirect(new URL('/admin/',request.url),303);
}

async function logout(env,request){const token=cookieToken(request);if(token) await env.DB.prepare(`DELETE FROM sessions WHERE token_hash=?`).bind(await sha256Hex(token)).run();return new Response('',{status:204,headers:{'set-cookie':cookieHeader('',0)}})}

export default {
  async fetch(request, env, ctx) {
    const url=new URL(request.url); await ensureAdmin(env);
    if(url.pathname==='/api/admin/login' && request.method==='POST') return handleLogin(env,request);
    if(url.pathname==='/api/admin/logout' && request.method==='POST') return logout(env,request);
    if(url.pathname==='/admin/' || url.pathname==='/admin') { const a=await adminFromRequest(env,request); return a ? env.ASSETS.fetch(new Request(new URL('/admin.html',request.url), request)) : loginPage(); }
    if(url.pathname==='/admin.html') { const a=await adminFromRequest(env,request); if(!a) return new Response('Unauthorized',{status:401}); return env.ASSETS.fetch(request); }
    if(url.pathname.startsWith('/api/admin/')) { const a=await requireAdmin(env,request); if(!a) return json({ok:false,error:'Unauthorized'},401); return adminApi(env,request,url,a); }
    if(url.pathname==='/api/jobs') return publicList(env,url);
    if(url.pathname.startsWith('/api/jobs/')) return publicItem(env,decodeURIComponent(url.pathname.slice('/api/jobs/'.length)));
    if(url.pathname==='/api/health') return json({ok:true,service:'north-bharat-jobs',time:nowIso()});
    if(url.pathname==='/sitemap.xml') {
      const rows=(await env.DB.prepare(`SELECT slug,updated_at FROM items WHERE status='published' AND (published_at IS NULL OR published_at>=datetime('now','-365 day')) ORDER BY updated_at DESC LIMIT 5000`).all()).results||[];
      const origin=siteOrigin(request); const urls=[`${origin}/`,`${origin}/about.html`,`${origin}/contact.html`,`${origin}/privacy.html`];
      const body='<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+urls.map(x=>`<url><loc>${x.replace(/&/g,'&amp;')}</loc></url>`).join('')+rows.map(r=>`<url><loc>${origin}/item/${encodeURIComponent(r.slug)}</loc><lastmod>${new Date(r.updated_at).toISOString()}</lastmod></url>`).join('')+'</urlset>';
      return new Response(body,{headers:{'content-type':'application/xml; charset=UTF-8','cache-control':'public,max-age=900'}});
    }
    if(url.pathname==='/robots.txt') return new Response(`User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/admin\nSitemap: ${siteOrigin(request)}/sitemap.xml\n`,{headers:{'content-type':'text/plain; charset=UTF-8'}});
    if(url.pathname.startsWith('/item/')) {
      const slug=decodeURIComponent(url.pathname.slice('/item/'.length)); const item=await env.DB.prepare(`SELECT * FROM items WHERE slug=? AND status='published'`).bind(slug).first();
      if(!item) return env.ASSETS.fetch(new Request(new URL('/index.html',request.url),request));
      return new Response(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(item.title)} | North Bharat Jobs</title><meta name="description" content="${esc((item.description||'').slice(0,155))}"><link rel="stylesheet" href="/style.css"></head><body><header class="top"><a href="/" class="brand">North Bharat Jobs</a><a href="/">Home</a></header><main class="detail"><div class="badge">${esc(item.type)}</div><h1>${esc(item.title)}</h1><p class="muted">${esc(item.organization||'')} ${item.location?'• '+esc(item.location):''}</p><section class="facts">${[['Post',item.title],['Organization',item.organization],['Category',item.category],['Location',item.location],['Vacancies',item.vacancies],['Qualification',item.qualification],['Eligibility',item.eligibility],['Age Limit',item.age_limit],['Age Relaxation',item.age_relaxation],['Fee',item.fee],['Salary',item.salary],['Selection Process',item.selection_process],['Application Start',item.application_start],['Last Date',item.last_date],['Exam Date',item.exam_date],['How to Apply',item.how_to_apply],['Important Dates',item.important_dates]].filter(x=>x[1]).map(x=>`<div><b>${x[0]}</b><span>${esc(x[1])}</span></div>`).join('')}</section><article><h2>Description</h2><p>${esc(item.description||'Verified details are shown from the available source evidence.')}</p></article><div class="actions">${item.official_url?`<a href="${esc(item.official_url)}" target="_blank" rel="noopener">Official Website</a>`:''}${item.notification_url?`<a href="${esc(item.notification_url)}" target="_blank" rel="noopener">Notification PDF</a>`:''}${item.apply_url?`<a href="${esc(item.apply_url)}" target="_blank" rel="noopener">Apply Online</a>`:''}</div></main></body></html>`,{headers:htmlHeaders});
    }
    if(request.method==='GET') return env.ASSETS.fetch(request);
    if(request.method==='POST' && url.pathname==='/api/cron') return json(await runMonitor(env));
    return json({ok:false,error:'Not found'},404);
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(runMonitor(env)); }
};
