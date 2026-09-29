import { runMonitor } from './monitor.js';
import { sha256Hex } from './verification.js';

const COOKIE = 'nbj_admin_session';
const SESSION_DAYS = 7;

const PUBLIC_TYPES = [
  'job',
  'recruitment',
  'admit_card',
  'result',
  'answer_key',
  'syllabus',
  'admission',
  'scholarship',
  'update'
];

const htmlHeaders = {
  'content-type': 'text/html; charset=UTF-8',
  'cache-control': 'public, max-age=300'
};

const jsonHeaders = {
  'content-type': 'application/json; charset=UTF-8',
  'cache-control': 'no-store'
};


function hasPublicUrlTracking(value) {
  const raw=String(value||'').trim();
  if(!raw) return false;
  try{
    const u=new URL(raw);
    const keys=[...u.searchParams.keys()].map(k=>k.toLowerCase());
    const blocked=new Set(['utm_source','utm_medium','utm_campaign','utm_term','utm_content','gclid','dclid','fbclid','msclkid','mc_cid','mc_eid','yclid','ref','referrer','affiliate','aff','affiliate_id','clickid','click_id','campaign','tracking','track','source']);
    if(keys.some(k=>blocked.has(k)||/^(utm_|tracking_|affiliate_|click_)/i.test(k))) return true;
    const host=u.hostname.toLowerCase().replace(/^www\\./,'');
    if(/^(?:bit\\.ly|tinyurl\\.com|t\\.co|goo\\.gl|is\\.gd|ow\\.ly|buff\\.ly|cutt\\.ly|rb\\.gy|rebrand\\.ly|lnkd\\.in)$/.test(host)) return true;
    return /(?:^|[\\/_.-])(redirect|redir|track|tracking|click|affiliate|referral|out)(?:[\\/_.?&=-]|$)/i.test(u.pathname+u.search)
      || /(?:^|[?&])(url|target|dest|destination|redirect|redirect_url|return|return_url|continue)=/i.test(u.search);
  }catch{return true;}
}

function publicSafeUrl(value) {
  const raw=String(value||'').trim();
  if(!raw||hasPublicUrlTracking(raw)) return null;
  try{
    const u=new URL(raw);
    if(u.protocol!=='http:'&&u.protocol!=='https:') return null;
    const host=u.hostname.toLowerCase().replace(/^www\\./,'');
    if(host==='localhost'||host.endsWith('.localhost')||host==='metadata.google.internal') return null;
    if(/^(?:0|127\\.|10\\.|169\\.254\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[0-1])\\.)/.test(host)) return null;
    if(/^(?:::1|fc|fd|fe80)/i.test(host)) return null;
    u.hash='';
    return u.toString();
  }catch{return null;}
}

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: jsonHeaders
    }
  );
}

function nowIso() {
  return new Date().toISOString();
}

function siteOrigin(request) {
  return new URL(request.url).origin;
}

function safeJson(request) {
  return request.json().catch(() => ({}));
}

function esc(value = '') {
  return String(value).replace(
    /[&<>'"]/g,
    char => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[char])
  );
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: enc.encode(salt),
      // Cloudflare Workers rejects PBKDF2 iteration counts above 100000.
      // Keep this at the runtime-supported ceiling.
      iterations: 100000,
      hash: 'SHA-256'
    },
    key,
    256
  );

  return `${salt}$${[
    ...new Uint8Array(bits)
  ]
    .map(
      b =>
        b.toString(16).padStart(2, '0')
    )
    .join('')}`;
}

async function verifyPassword(
  password,
  stored
) {
  if (!stored?.includes('$')) {
    return false;
  }

  const separator = stored.indexOf('$');

  const salt =
    stored.slice(0, separator);

  const expected =
    stored.slice(separator + 1);

  const actual =
    await hashPassword(
      password,
      salt
    );

  return actual.slice(
    actual.indexOf('$') + 1
  ) === expected;
}

function randomToken() {
  const bytes =
    new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return [
    ...bytes
  ]
    .map(
      b =>
        b.toString(16).padStart(2, '0')
    )
    .join('');
}

function cookieToken(request) {
  const cookie =
    request.headers.get('cookie') || '';

  for (const part of cookie.split(';')) {
    const [rawName, ...rawValue] = part.trim().split('=');
    if (rawName === COOKIE) {
      return rawValue.join('=') || null;
    }
  }

  return null;
}

function cookieHeader(
  token,
  maxAge
) {
  return [
    `${COOKIE}=${token}`,
    `Max-Age=${maxAge}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax'
  ].join('; ');
}

/*
  Admin authentication
*/
async function adminFromRequest(
  env,
  request
) {
  const token =
    cookieToken(request);

  if (!token) {
    return null;
  }

  const hash =
    await sha256Hex(token);

  const row =
    await env.DB
      .prepare(`
        SELECT
          a.*
        FROM sessions s
        JOIN admins a
          ON a.id=s.admin_id
        WHERE
          s.token_hash=?
          AND s.expires_at>?
      `)
      .bind(
        hash,
        nowIso()
      )
      .first();

  return row || null;
}

async function requireAdmin(
  env,
  request
) {
  return adminFromRequest(
    env,
    request
  );
}

async function audit(
  env,
  adminId,
  action,
  type = null,
  id = null,
  meta = null
) {
  await env.DB
    .prepare(`
      INSERT INTO audit_logs(
        admin_id,
        action,
        target_type,
        target_id,
        metadata_json
      )
      VALUES(?,?,?,?,?)
    `)
    .bind(
      adminId,
      action,
      type,
      id,
      meta
        ? JSON.stringify(meta)
        : null
    )
    .run();
}

/*
  Creates the first admin only when
  the database has no admin account.
*/
async function ensureAdmin(env) {
  const count =
    await env.DB
      .prepare(
        `SELECT COUNT(*) c FROM admins`
      )
      .first();

  if (
    Number(count?.c || 0) > 0
  ) {
    return;
  }

  if (
    !env.ADMIN_EMAIL ||
    !env.ADMIN_PASSWORD
  ) {
    return;
  }

  const email =
    String(
      env.ADMIN_EMAIL
    )
      .trim()
      .toLowerCase();

  const password =
    String(env.ADMIN_PASSWORD);

  if (
    !/^\S+@\S+\.\S+$/.test(email) ||
    password.length < 10
  ) {
    return;
  }

  const salt =
    randomToken().slice(0, 32);

  const passwordHash =
    await hashPassword(
      password,
      salt
    );

  await env.DB
    .prepare(`
      INSERT OR IGNORE INTO admins(
        email,
        password_hash
      )
      VALUES(?,?)
    `)
    .bind(
      email,
      passwordHash
    )
    .run();
}

/*
  Public jobs list
*/
async function publicList(env,url) {
  const type=url.searchParams.get('type');
  const q=(url.searchParams.get('q')||'').trim();
  const requestedPage=Number(url.searchParams.get('page')||1);
  const requestedLimit=Number(url.searchParams.get('limit')||15);
  const page=Number.isFinite(requestedPage)?Math.max(1,Math.floor(requestedPage)):1;
  const limit=Number.isFinite(requestedLimit)?Math.min(30,Math.max(1,Math.floor(requestedLimit))):15;
  const offset=(page-1)*limit;
  const where=[`status='published'`,`published_at IS NOT NULL`,`published_at >= datetime('now','-365 day')`];
  const args=[];
  if(type&&PUBLIC_TYPES.includes(type)){where.push('type=?');args.push(type);}
  if(q){
    const search='%'+q+'%';
    where.push('(title LIKE ? OR organization LIKE ? OR qualification LIKE ? OR category LIKE ?)');
    args.push(search,search,search,search);
  }
  const rows=(await env.DB.prepare(`
    SELECT id,slug,type,title,organization,category,location,qualification,vacancies,
           age_limit,age_relaxation,fee,selection_process,salary,application_start,last_date,
           exam_date,how_to_apply,important_dates,official_url,apply_url,notification_url,
           published_at,updated_at
    FROM items WHERE ${where.join(' AND ')}
    ORDER BY published_at DESC,id DESC LIMIT ? OFFSET ?
  `).bind(...args,limit,offset).all()).results||[];
  const items=rows.map(row=>({
    ...row,
    official_url:publicSafeUrl(row.official_url),
    notification_url:publicSafeUrl(row.notification_url),
    apply_url:publicSafeUrl(row.apply_url)
  }));
  return json({ok:true,page,limit,items});
}

/*
  Public item
*/
async function publicItem(env,slug) {
  const item=await env.DB.prepare(`
    SELECT id,slug,type,title,organization,category,location,description,eligibility,qualification,
           vacancies,age_limit,age_relaxation,fee,selection_process,salary,application_start,last_date,
           exam_date,how_to_apply,important_dates,official_url,apply_url,notification_url,published_at,updated_at
    FROM items
    WHERE slug=? AND status='published' AND published_at IS NOT NULL
      AND published_at >= datetime('now','-365 day')
  `).bind(slug).first();
  if(!item) return json({ok:false,error:'Not found'},404);
  item.official_url=publicSafeUrl(item.official_url);
  item.notification_url=publicSafeUrl(item.notification_url);
  item.apply_url=publicSafeUrl(item.apply_url);
  delete item.source_name; delete item.source_id; delete item.source_url; delete item.source_hash;
  delete item.evidence_json; delete item.verification_status; delete item.confidence_score;
  return json({ok:true,item});
}


/*
  Admin notification analyzer.
  Results are always returned for Admin review; this endpoint never publishes.
*/
const ANALYZER_FIELDS = [
  'type','title','organization','category','location','description',
  'eligibility','qualification','vacancies','age_limit','age_relaxation',
  'fee','selection_process','salary','application_start','last_date',
  'exam_date','how_to_apply','important_dates','official_url',
  'notification_url','apply_url','canonical_url'
];

function analyzerText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim();
}

function stripHtmlForAnalyzer(html) {
  return String(html || '')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#39;/gi, "'")
    .replace(/&quot;/gi, '"')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 180000);
}

function extractLinksForAnalyzer(html, baseUrl) {
  const links = [];
  const re = /<a\b[^>]*?href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(String(html || ''))) ) {
    try {
      const href = new URL(m[1], baseUrl).toString();
      if (!/^https?:$/i.test(new URL(href).protocol)) continue;
      links.push({url: href, label: stripHtmlForAnalyzer(m[2]).slice(0, 300)});
    } catch {}
    if (links.length >= 250) break;
  }
  return links;
}

function extractJsonFromModel(value) {
  const raw = String(value || '').trim();
  try { return JSON.parse(raw); } catch {}
  const fenced = raw.match(/\`\`\`(?:json)?\s*([\s\S]*?)\s*\`\`\`/i);
  if (fenced) { try { return JSON.parse(fenced[1]); } catch {} }
  const first = raw.indexOf('{');
  const last = raw.lastIndexOf('}');
  if (first >= 0 && last > first) {
    try { return JSON.parse(raw.slice(first, last + 1)); } catch {}
  }
  return null;
}

function normalizeAnalyzerResult(value) {
  const out = {};
  for (const field of ANALYZER_FIELDS) {
    const v = value?.[field];
    out[field] = v === null || v === undefined ? '' : String(v).trim();
  }
  if (!out.type) out.type = 'job';
  if (!out.category) out.category = 'Latest Jobs';
  return out;
}

function analyzerPrompt(context) {
  return [
    'You are the official-document extraction engine for North Bharat Jobs.',
    'Extract structured recruitment/admission/update data ONLY from the supplied official source.',
    '',
    'CRITICAL RULES:',
    '- Never invent, guess, infer, or complete a missing fact.',
    '- If a field is not explicitly supported by the source, return an empty string.',
    '- Preserve exact dates, vacancy counts, fees, qualifications, age limits and salary as stated.',
    '- How to Apply must summarize the source actual application instructions.',
    '- URLs must be copied exactly from the source when available. Never construct a URL from a guess.',
    '- Notification PDF URL must be an actual PDF URL.',
    '- Apply URL must be a real application page, not the PDF.',
    '- If the supplied source is itself a PDF, use it as notification_url unless the document clearly identifies a different official notification PDF.',
    '- This result is for ADMIN REVIEW. Do not claim independent verification.',
    '- Return JSON only. No markdown and no commentary.',
    '',
    'Return exactly these keys:',
    ANALYZER_FIELDS.join(','),
    '',
    'SOURCE CONTEXT:',
    context
  ].join('\n');
}

async function callOpenAIAnalyzer(env, content) {
  if (!env.OPENAI_API_KEY) {
    return {ok:false, error:'OpenAI fallback is not configured.'};
  }

  const model = String(env.OPENAI_MODEL || 'gpt-5-mini').trim();
  const response = await fetch('https://api.openai.com/v1/responses', {
    method:'POST',
    headers:{
      authorization:'Bearer '+env.OPENAI_API_KEY,
      'content-type':'application/json'
    },
    body:JSON.stringify({
      model,
      input:[{role:'user',content}],
      max_output_tokens:6000
    })
  });

  const raw = await response.text();
  let data = null;
  try { data = JSON.parse(raw); } catch {}

  if (!response.ok) {
    return {ok:false,error:data?.error?.message || ('OpenAI request failed ('+response.status+')')};
  }

  const outputText =
    data?.output_text ||
    (data?.output || [])
      .flatMap(item => item?.content || [])
      .map(item => item?.text || '')
      .join(' ');

  const parsed = extractJsonFromModel(outputText);
  if (!parsed || typeof parsed !== 'object') {
    return {ok:false,error:'OpenAI returned no valid structured JSON.'};
  }

  return {ok:true,item:normalizeAnalyzerResult(parsed),model};
}

async function callCloudflareAnalyzer(env, content) {
  if (!env.AI || typeof env.AI.run !== 'function') {
    return {ok:false,error:'Cloudflare Workers AI binding is not configured.'};
  }

  const model = String(env.CF_AI_MODEL || '@cf/google/gemma-4-26b-a4b-it').trim();
  try {
    const response = await env.AI.run(model, {
      messages: [
        {
          role:'system',
          content:'You are a strict official-document extraction engine. Return JSON only. Never invent, guess, infer, or fill missing facts.'
        },
        {
          role:'user',
          content
        }
      ],
      chat_template_kwargs:{enable_thinking:false}
    }, {rejectIfBusy:true});

    const outputText =
      response?.response ||
      response?.result?.response ||
      response?.choices?.[0]?.message?.content ||
      response?.result?.choices?.[0]?.message?.content ||
      '';

    const parsed = extractJsonFromModel(outputText);
    if (!parsed || typeof parsed !== 'object') {
      return {ok:false,error:'Cloudflare AI returned no valid structured JSON.'};
    }

    return {ok:true,item:normalizeAnalyzerResult(parsed),model};
  } catch (error) {
    return {ok:false,error:'Cloudflare AI failed: '+String(error?.message || error)};
  }
}

const DEFAULT_AI_DAILY_ANALYSIS_LIMIT = 50;
const DEFAULT_AI_MONTHLY_ANALYSIS_LIMIT = 1000;
const AI_USAGE_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS ai_usage (
  period_type TEXT NOT NULL,
  period_key TEXT NOT NULL,
  analysis_count INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(period_type, period_key)
)`;

function aiLimit(env, name, fallback) {
  const n = Number(env[name]);
  return Number.isFinite(n) && n >= 0 ? Math.floor(n) : fallback;
}

function utcDayKey(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

function utcMonthKey(date = new Date()) {
  return date.toISOString().slice(0, 7);
}

async function ensureAiUsageTable(env) {
  await env.DB.prepare(AI_USAGE_TABLE_SQL).run();
}

async function getAiUsage(env) {
  await ensureAiUsageTable(env);
  const day = utcDayKey();
  const month = utcMonthKey();
  const rows = (await env.DB.prepare(`
    SELECT period_type, period_key, analysis_count, updated_at
    FROM ai_usage
    WHERE (period_type='day' AND period_key=?)
       OR (period_type='month' AND period_key=?)
  `).bind(day, month).all()).results || [];

  const out = {day:0, month:0};
  for (const row of rows) {
    if (row.period_type === 'day') out.day = Number(row.analysis_count || 0);
    if (row.period_type === 'month') out.month = Number(row.analysis_count || 0);
  }

  const dailyLimit = aiLimit(env, 'AI_DAILY_ANALYSIS_LIMIT', DEFAULT_AI_DAILY_ANALYSIS_LIMIT);
  const monthlyLimit = aiLimit(env, 'AI_MONTHLY_ANALYSIS_LIMIT', DEFAULT_AI_MONTHLY_ANALYSIS_LIMIT);

  return {
    day,
    month,
    daily: {used:out.day, limit:dailyLimit, remaining:Math.max(0,dailyLimit-out.day)},
    monthly: {used:out.month, limit:monthlyLimit, remaining:Math.max(0,monthlyLimit-out.month)},
    openaiFallback: String(env.AI_ALLOW_OPENAI_FALLBACK || '').toLowerCase() === 'true'
  };
}

async function reserveAiAnalysis(env) {
  await ensureAiUsageTable(env);

  const day = utcDayKey();
  const month = utcMonthKey();
  const dailyLimit = aiLimit(env, 'AI_DAILY_ANALYSIS_LIMIT', DEFAULT_AI_DAILY_ANALYSIS_LIMIT);
  const monthlyLimit = aiLimit(env, 'AI_MONTHLY_ANALYSIS_LIMIT', DEFAULT_AI_MONTHLY_ANALYSIS_LIMIT);

  const rows = (await env.DB.prepare(`
    SELECT period_type, period_key, analysis_count
    FROM ai_usage
    WHERE (period_type='day' AND period_key=?)
       OR (period_type='month' AND period_key=?)
  `).bind(day, month).all()).results || [];

  let dayUsed = 0;
  let monthUsed = 0;
  for (const row of rows) {
    if (row.period_type === 'day') dayUsed = Number(row.analysis_count || 0);
    if (row.period_type === 'month') monthUsed = Number(row.analysis_count || 0);
  }

  if (dayUsed >= dailyLimit) {
    return {ok:false, code:'daily_limit', message:'Daily AI analysis limit reached. Try again after 00:00 UTC.', usage:{
      daily:{used:dayUsed,limit:dailyLimit,remaining:0},
      monthly:{used:monthUsed,limit:monthlyLimit,remaining:Math.max(0,monthlyLimit-monthUsed)}
    }};
  }

  if (monthUsed >= monthlyLimit) {
    return {ok:false, code:'monthly_limit', message:'Monthly AI analysis limit reached. Try again next month.', usage:{
      daily:{used:dayUsed,limit:dailyLimit,remaining:Math.max(0,dailyLimit-dayUsed)},
      monthly:{used:monthUsed,limit:monthlyLimit,remaining:0}
    }};
  }

  await env.DB.batch([
    env.DB.prepare(`
      INSERT INTO ai_usage(period_type,period_key,analysis_count,updated_at)
      VALUES('day',?,?,CURRENT_TIMESTAMP)
      ON CONFLICT(period_type,period_key)
      DO UPDATE SET analysis_count=analysis_count+1, updated_at=CURRENT_TIMESTAMP
    `).bind(day, 1),
    env.DB.prepare(`
      INSERT INTO ai_usage(period_type,period_key,analysis_count,updated_at)
      VALUES('month',?,?,CURRENT_TIMESTAMP)
      ON CONFLICT(period_type,period_key)
      DO UPDATE SET analysis_count=analysis_count+1, updated_at=CURRENT_TIMESTAMP
    `).bind(month, 1)
  ]);

  return {
    ok:true,
    usage:{
      daily:{used:dayUsed+1,limit:dailyLimit,remaining:Math.max(0,dailyLimit-dayUsed-1)},
      monthly:{used:monthUsed+1,limit:monthlyLimit,remaining:Math.max(0,monthlyLimit-monthUsed-1)}
    }
  };
}

async function callAnalyzer(env, content) {
  const cloudflare = await callCloudflareAnalyzer(env, content);
  if (cloudflare.ok) return {...cloudflare,provider:'cloudflare_workers_ai'};

  const allowOpenAI = String(env.AI_ALLOW_OPENAI_FALLBACK || '').toLowerCase() === 'true';
  if (allowOpenAI) {
    const openai = await callOpenAIAnalyzer(env, content);
    if (openai.ok) return {...openai,provider:'openai_fallback'};
    return {
      ok:false,
      error:'Cloudflare Workers AI failed. OpenAI fallback also failed: '+openai.error
    };
  }

  return {
    ok:false,
    error:'Cloudflare Workers AI failed: '+cloudflare.error+' OpenAI fallback is disabled by default to avoid unexpected API charges.'
  };
}

async function convertOfficialPdfToMarkdown(env, url) {
  if (!env.AI || typeof env.AI.toMarkdown !== 'function') {
    return {ok:false,error:'Cloudflare document conversion is not configured.'};
  }

  const response = await fetch(url,{
    redirect:'follow',
    headers:{'user-agent':'North-Bharat-Jobs-Admin-Analyzer/1.0'},
    cache:'no-store'
  });
  if (!response.ok) {
    return {ok:false,error:'Official PDF could not be fetched (HTTP '+response.status+').'};
  }

  const buffer = await response.arrayBuffer();
  const name = new URL(url).pathname.split('/').pop() || 'notification.pdf';

  try {
    const converted = await env.AI.toMarkdown({
      name,
      blob:new Blob([buffer],{type:'application/pdf'})
    });
    const result = Array.isArray(converted) ? converted[0] : converted;
    if (result?.format === 'error') {
      return {ok:false,error:'PDF conversion failed: '+String(result.error || 'unknown conversion error')};
    }
    const text = String(result?.data || '').trim();
    if (!text) return {ok:false,error:'PDF conversion returned no readable text.'};
    return {ok:true,text:text.slice(0,220000)};
  } catch (error) {
    return {ok:false,error:'PDF conversion failed: '+String(error?.message || error)};
  }
}

async function validateAnalyzerUrls(item, inputUrl) {
  const result = {...item};
  for (const field of ['official_url','notification_url','apply_url','canonical_url']) {
    const raw = analyzerText(result[field]);
    if (!raw) continue;
    const safe = publicSafeUrl(raw);
    if (!safe) { result[field]=''; continue; }

    try {
      const u = new URL(safe);
      const input = new URL(inputUrl);
      const sameOfficialHost =
        u.hostname.toLowerCase().replace(/^www\./,'') ===
        input.hostname.toLowerCase().replace(/^www\./,'');
      if (!sameOfficialHost) { result[field]=''; continue; }

      if (field==='notification_url' && !/\.pdf(?:$|[?#])/i.test(u.pathname+u.search)) {
        result[field]='';
      }
      if (field==='apply_url' && /\.pdf(?:$|[?#])/i.test(u.pathname+u.search)) {
        result[field]='';
      }
    } catch {
      result[field]='';
    }
  }
  return result;
}

async function analyzeOfficialNotification(env, sourceUrl) {
  const budget = await reserveAiAnalysis(env);
  if (!budget.ok) {
    return {ok:false,error:budget.message,code:budget.code,usage:budget.usage};
  }

  const inputUrl = publicSafeUrl(sourceUrl);
  if (!inputUrl) return {ok:false,error:'Enter a valid public HTTP/HTTPS official URL.'};

  const input = new URL(inputUrl);
  const looksPdf = /\.pdf(?:$|[?#])/i.test(input.pathname+input.search);
  let links = [];
  const contentParts = [];

  if (looksPdf) {
    const converted=await convertOfficialPdfToMarkdown(env,inputUrl);
    if (!converted.ok) return converted;
    contentParts.push({
      type:'input_text',
      text:analyzerPrompt('The supplied input is this official PDF URL: '+inputUrl+'\nConverted PDF text/Markdown:\n'+converted.text)
    });
  } else {
    const response = await fetch(inputUrl,{
      redirect:'follow',
      headers:{'user-agent':'North-Bharat-Jobs-Admin-Analyzer/1.0'},
      cache:'no-store'
    });

    if (!response.ok) {
      return {ok:false,error:'Official URL could not be fetched (HTTP '+response.status+').'};
    }

    const contentType=(response.headers.get('content-type')||'').toLowerCase();

    if (contentType.includes('application/pdf')) {
      const converted=await convertOfficialPdfToMarkdown(env,inputUrl);
      if (!converted.ok) return converted;
      contentParts.push({
        type:'input_text',
        text:analyzerPrompt('The supplied input is this official PDF URL: '+inputUrl+'\nConverted PDF text/Markdown:\n'+converted.text)
      });
    } else {
      const html=await response.text();
      const pageText=stripHtmlForAnalyzer(html);
      links=extractLinksForAnalyzer(html,inputUrl);
      const linkText=links.map((x,i)=>(i+1)+'. '+x.label+' -> '+x.url).join('\n');

      contentParts.push({
        type:'input_text',
        text:analyzerPrompt(
          'Official source URL: '+inputUrl+
          '\n\nPAGE TEXT:\n'+pageText+
          '\n\nLINKS FOUND ON THE OFFICIAL PAGE:\n'+linkText
        )
      });
    }
  }

  const first=await callAnalyzer(
    env,
    contentParts.map(part => part?.text || '').filter(Boolean).join('\n\n')
  );
  if (!first.ok) return first;

  let item=await validateAnalyzerUrls(first.item,inputUrl);

  if (!looksPdf && !item.notification_url) {
    const pdfCandidates=links.filter(x=>/\.pdf(?:$|[?#])/i.test(x.url)).slice(0,8);
    if (pdfCandidates.length) {
      const pdfHint=pdfCandidates.map((x,i)=>(i+1)+'. '+x.label+' -> '+x.url).join('\n');
      const secondParts=[{
        type:'input_text',
        text:analyzerPrompt(
          'Official recruitment webpage: '+inputUrl+
          '\nThe PDF links below are official candidates. Identify the correct recruitment notification PDF and extract the full structured data from the supplied PDF.\nPDF CANDIDATES:\n'+pdfHint
        )
      }];

      for (const candidate of pdfCandidates.slice(0,3)) {
        const converted=await convertOfficialPdfToMarkdown(env,candidate.url);
        if (converted.ok) {
          secondParts.push({
            type:'input_text',
            text:'PDF '+candidate.url+'\n'+converted.text
          });
        }
      }

      const second=await callAnalyzer(
        env,
        secondParts.map(part => part?.text || '').filter(Boolean).join('\n\n')
      );
      if (second.ok) {
        const secondItem=await validateAnalyzerUrls(second.item,inputUrl);
        for (const field of ANALYZER_FIELDS) {
          if (analyzerText(secondItem[field])) item[field]=secondItem[field];
        }
      }
    }
  }

  if (!item.official_url) item.official_url=inputUrl;
  if (!item.canonical_url) item.canonical_url=item.official_url;
  if (looksPdf && !item.notification_url) item.notification_url=inputUrl;

  return {
    ok:true,
    item,
    analysis:{
      status:'admin_review_required',
      source_url:inputUrl,
      model:first.model,
      provider:first.provider || 'unknown',
      note:'Extracted from the supplied official source. Admin must review every field before publishing.'
    }
  };
}

/*
  Admin dashboard
*/
async function adminDashboard(env) {
  /*
    Keep the dashboard deliberately resilient. The Admin Portal must
    still render even when an optional/older D1 table is unavailable.
  */
  const count = async (sql) => {
    try {
      const row = await env.DB.prepare(sql).first();
      return Number(row?.c || 0);
    } catch {
      return 0;
    }
  };

  const published = await count(
    "SELECT COUNT(*) c FROM items WHERE status='published'"
  );

  const verificationRequired = await count(
    "SELECT COUNT(*) c FROM items WHERE status='verification_required'"
  );

  const sourceErrors = await count(
    "SELECT COUNT(*) c FROM sources WHERE enabled=1 AND last_error IS NOT NULL"
  );

  /*
    Notifications are optional in some existing D1 installations.
    Do not let a missing notifications table break the whole dashboard.
  */
  const unreadNotifications = await count(
    "SELECT COUNT(*) c FROM notifications WHERE read_at IS NULL"
  );

  return json({
    ok: true,
    stats: {
      published,
      verification_required: verificationRequired,
      source_errors: sourceErrors,
      unread_notifications: unreadNotifications
    }
  });
}

/*
  Admin API
*/
async function adminApi(
  env,
  request,
  url,
  admin
) {
  const path =
    url.pathname;

  if (
    path ===
    '/api/admin/me'
  ) {
    return json({
      ok: true,
      admin: {
        id: admin.id,
        email: admin.email
      }
    });
  }

  if (
    path ===
    '/api/admin/dashboard'
  ) {
    return adminDashboard(env);
  }

  if (
    path ===
    '/api/admin/ai-usage'
  ) {
    try {
      const usage = await getAiUsage(env);
      return json({ok:true,usage});
    } catch (error) {
      return json({ok:false,error:'AI usage status unavailable: '+String(error?.message || error)},500);
    }
  }

  if (
    path ===
    '/api/admin/sources'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM sources
            ORDER BY
              role,
              priority,
              id
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      sources: rows
    });
  }

  if (
    path ===
    '/api/admin/items'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM items
            WHERE status IN (
              'verification_required',
              'published'
            )
            ORDER BY
              updated_at DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      items: rows
    });
  }

  if (
    path ===
    '/api/admin/notifications'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM notifications
            ORDER BY
              created_at DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      notifications: rows
    });
  }

  if (
    path ===
    '/api/admin/runs'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM monitor_runs
            ORDER BY
              id DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      runs: rows
    });
  }

  if (
    path ===
    '/api/admin/audit'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM audit_logs
            ORDER BY
              id DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      logs: rows
    });
  }

  if (
    path ===
    '/api/admin/verification-logs'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM verification_events
            ORDER BY
              id DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      logs: rows
    });
  }

  /*
    Manual source discovery
  */
  if (
    path ===
      '/api/admin/discover' &&
    request.method === 'POST'
  ) {
    const name =
      url.searchParams.get(
        'source'
      );

    if (!name) {
      return json(
        {
          ok: false,
          error:
            'Missing source'
        },
        400
      );
    }

    const result =
      await runMonitor(
        env,
        name
      );

    await audit(
      env,
      admin.id,
      'manual_discover',
      'source',
      name
    );

    return json({
      ok: true,
      ...result
    });
  }

  /*
    Analyze an official notification before creating a job.
  */
  if (
    path === '/api/admin/item/analyze' &&
    request.method === 'POST'
  ) {
    const body=await safeJson(request);
    const sourceUrl=String(body?.url || '').trim();

    try {
      const result=await analyzeOfficialNotification(env,sourceUrl);
      await audit(env,admin.id,'analyze_notification','item',null,{
        source_url:publicSafeUrl(sourceUrl),
        ok:result.ok===true
      });
      return json(result,result.ok?200:400);
    } catch(error) {
      await audit(env,admin.id,'analyze_notification_error','item',null,{
        source_url:publicSafeUrl(sourceUrl),
        error:String(error?.message || error)
      });
      return json({
        ok:false,
        error:'Notification analysis failed: '+String(error?.message || error)
      },500);
    }
  }

  /*
    Create a new job manually from Admin Portal.
    Manual records are clearly marked as admin-created and still pass
    the same public URL safety checks before they can be published.
  */
  if (
    path === '/api/admin/item/create' &&
    request.method === 'POST'
  ) {
    const body = await safeJson(request);

    const fields = [
      'type','title','organization','category','location',
      'description','eligibility','qualification','vacancies',
      'age_limit','age_relaxation','fee','selection_process',
      'salary','application_start','last_date','exam_date',
      'how_to_apply','important_dates','official_url',
      'apply_url','notification_url','canonical_url'
    ];

    const data = {};
    for (const field of fields) {
      data[field] =
        body[field] === null || body[field] === undefined
          ? ''
          : String(body[field]).trim();
    }

    if (!data.title) {
      return json({ ok:false, error:'Title cannot be empty' }, 400);
    }

    if (!data.type) data.type = 'job';
    if (!data.category) data.category = 'Latest Jobs';

    if (!data.official_url) {
      return json({ ok:false, error:'Official Website URL is required' }, 400);
    }
    if (!data.notification_url) {
      return json({ ok:false, error:'Notification PDF URL is required' }, 400);
    }
    if (!data.apply_url) {
      return json({ ok:false, error:'Apply Online URL is required' }, 400);
    }

    for (const field of ['official_url','notification_url','apply_url']) {
      if (hasPublicUrlTracking(data[field])) {
        return json({
          ok:false,
          error:'Tracking/redirect URL is not allowed in '+field
        }, 400);
      }
    }

    if (!data.canonical_url) data.canonical_url = data.official_url;

    /*
      Do not treat a generic official/careers page or a repeated title as
      a duplicate by itself. One organization can legitimately have many
      recruitments pointing to the same careers page, and separate editions
      can reuse similar titles. The stable notification PDF URL is the
      strongest manual-create identity.
    */
    const duplicate = await env.DB.prepare(`
      SELECT id,title,status,notification_url,canonical_url
      FROM items
      WHERE notification_url IS NOT NULL
        AND trim(notification_url) <> ''
        AND notification_url=?
      ORDER BY id DESC
      LIMIT 1
    `).bind(data.notification_url).first();

    if (duplicate) {
      return json({
        ok:false,
        error:'This exact Notification PDF is already registered as job #'+duplicate.id+': '+duplicate.title,
        duplicate_id:duplicate.id,
        duplicate_reason:'notification_url',
        existing_notification_url:duplicate.notification_url
      }, 409);
    }

    const baseSlug = data.title
      .toLowerCase()
      .replace(/[^a-z0-9]+/g,'-')
      .replace(/^-+|-+$/g,'')
      .slice(0,120) || 'job';

    let slug = baseSlug;
    for (let n=2; n<=1000; n++) {
      const exists = await env.DB
        .prepare('SELECT id FROM items WHERE slug=? LIMIT 1')
        .bind(slug)
        .first();
      if (!exists) break;
      slug = baseSlug+'-'+n;
    }

    const status = body.publish === true ? 'published' : 'verification_required';
    const verificationStatus = body.publish === true
      ? 'admin_verified'
      : 'admin_created';

    const publishedAt = body.publish === true ? nowIso() : null;

    const result = await env.DB.prepare(`
      INSERT INTO items(
        slug,notification_key,type,title,organization,category,location,
        description,eligibility,qualification,vacancies,age_limit,age_relaxation,
        fee,selection_process,salary,application_start,last_date,exam_date,
        how_to_apply,important_dates,official_url,apply_url,notification_url,
        source_url,source_name,source_id,source_hash,canonical_url,status,
        verification_status,confidence_score,evidence_json,last_verified_at,
        last_seen_at,published_at,created_at,updated_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
    `).bind(
      slug,
      'admin:'+slug,
      data.type,
      data.title,
      data.organization,
      data.category,
      data.location,
      data.description,
      data.eligibility,
      data.qualification,
      data.vacancies,
      data.age_limit,
      data.age_relaxation,
      data.fee,
      data.selection_process,
      data.salary,
      data.application_start,
      data.last_date,
      data.exam_date,
      data.how_to_apply,
      data.important_dates,
      data.official_url,
      data.apply_url,
      data.notification_url,
      data.official_url,
      'Admin Manual',
      null,
      null,
      data.canonical_url,
      status,
      verificationStatus,
      body.publish === true ? 100 : 0,
      JSON.stringify({
        origin:'admin_manual',
        created_by_admin_id:admin.id,
        public_firewall:'url_safety_checked'
      }),
      body.publish === true ? nowIso() : null,
      nowIso(),
      publishedAt
    ).run();

    const id = Number(result.meta?.last_row_id || 0);
    if (!id) {
      return json({ ok:false, error:'Job could not be created' }, 500);
    }

    await audit(env, admin.id, 'create_item', 'item', id, {
      status,
      title:data.title
    });

    return json({ ok:true, id, status, slug });
  }

  /*
    Manual item verification
  */
  if (
    path ===
      '/api/admin/item/verify' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error: 'Invalid id'
        },
        400
      );
    }

    const existing =
      await env.DB
        .prepare('SELECT * FROM items WHERE id=?')
        .bind(id)
        .first();

    if (!existing) {
      return json({ ok:false, error:'Item not found' }, 404);
    }

    const publishUrlProblems = ['official_url','notification_url','apply_url']
      .filter(field => existing[field] && hasPublicUrlTracking(existing[field]));
    if (publishUrlProblems.length) {
      return json({ ok:false, error:'Cannot publish tracking/redirect URL. Correct these fields first: '+publishUrlProblems.join(', ') }, 400);
    }

    const result =
      await env.DB
        .prepare(`
          UPDATE items
          SET
            status='published',
            verification_status='admin_verified',
            last_verified_at=?,
            archived_at=NULL,
            archive_reason=NULL,
            published_at=COALESCE(published_at, ?),
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(
          nowIso(),
          nowIso(),
          id
        )
        .run();

    if (
      Number(
        result.meta?.changes || 0
      ) === 0
    ) {
      return json(
        {
          ok: false,
          error:
            'Item not found'
        },
        404
      );
    }

    await audit(
      env,
      admin.id,
      'verify_publish',
      'item',
      id
    );

    return json({
      ok: true
    });
  }

  /*
    Edit item fields from Admin Portal.
    Every edit creates a revision snapshot before changing the record.
  */
  if (
    path === '/api/admin/item/update' &&
    request.method === 'POST'
  ) {
    const body = await safeJson(request);
    const id = Number(body.id);

    if (!Number.isInteger(id) || id <= 0) {
      return json({ ok:false, error:'Invalid id' }, 400);
    }

    const existing = await env.DB
      .prepare('SELECT * FROM items WHERE id=?')
      .bind(id)
      .first();

    if (!existing) {
      return json({ ok:false, error:'Item not found' }, 404);
    }

    const allowed = [
      'type','title','organization','category','location',
      'description','eligibility','qualification','vacancies',
      'age_limit','age_relaxation','fee','selection_process',
      'salary','application_start','last_date','exam_date',
      'how_to_apply','important_dates','official_url',
      'apply_url','notification_url','source_url',
      'source_name','canonical_url'
    ];

    const next = {};
    for (const field of allowed) {
      if (Object.prototype.hasOwnProperty.call(body, field)) {
        next[field] = body[field] === null ? null : String(body[field]).trim();
      }
    }

    if (next.title !== undefined && !next.title) {
      return json({ ok:false, error:'Title cannot be empty' }, 400);
    }

    const changed = allowed.filter(field =>
      Object.prototype.hasOwnProperty.call(next, field) &&
      String(existing[field] ?? '') !== String(next[field] ?? '')
    );

    if (!changed.length) {
      return json({ ok:true, changed:[] });
    }

    await env.DB
      .prepare('INSERT INTO item_revisions(item_id,revision_no,changed_fields_json,snapshot_json) VALUES(?,?,?,?)')
      .bind(
        id,
        (Number((await env.DB.prepare('SELECT COALESCE(MAX(revision_no),0) n FROM item_revisions WHERE item_id=?').bind(id).first())?.n || 0) + 1),
        JSON.stringify(changed),
        JSON.stringify(existing)
      )
      .run();

    const assignments = changed.map(field => field + '=?').join(',');
    await env.DB
      .prepare('UPDATE items SET ' + assignments + ', verification_status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
      .bind(...changed.map(field => next[field]), 'admin_verified', id)
      .run();

    await audit(env, admin.id, 'edit_item', 'item', id, {
      changed_fields: changed
    });

    return json({ ok:true, changed });
  }

  /*
    Preview current item data without publishing it.
  */
  if (
    path === '/api/admin/item/preview' &&
    request.method === 'GET'
  ) {
    const id = Number(url.searchParams.get('id'));
    if (!Number.isInteger(id) || id <= 0) {
      return json({ ok:false, error:'Invalid id' }, 400);
    }

    const item = await env.DB
      .prepare('SELECT * FROM items WHERE id=?')
      .bind(id)
      .first();

    if (!item) {
      return json({ ok:false, error:'Item not found' }, 404);
    }

    return json({ ok:true, item });
  }

  /*
    Re-run source monitoring for the item's source.
  */
  if (
    path === '/api/admin/item/reverify' &&
    request.method === 'POST'
  ) {
    const body = await safeJson(request);
    const id = Number(body.id);

    if (!Number.isInteger(id) || id <= 0) {
      return json({ ok:false, error:'Invalid id' }, 400);
    }

    const item = await env.DB
      .prepare('SELECT * FROM items WHERE id=?')
      .bind(id)
      .first();

    if (!item) {
      return json({ ok:false, error:'Item not found' }, 404);
    }

    let monitorSource = item.source_name;
    if (String(item.source_name || '') === 'Secondary Cross-check' || !String(item.source_name || '').trim()) {
      const sourceRow = await env.DB.prepare('SELECT name FROM sources WHERE id=? LIMIT 1').bind(item.source_id).first();
      monitorSource = sourceRow?.name || null;
    }
    const result = monitorSource
      ? await runMonitor(env, monitorSource, { maintenance:false })
      : await runMonitor(env, null, { maintenance:false })

    await audit(env, admin.id, 'reverify_item', 'item', id, {
      source_name: item.source_name
    });

    return json({ ok:true, monitor:result });
  }

  /*
    Archive without deleting. This preserves history and deduplication identity.
  */
  if (
    path === '/api/admin/item/archive' &&
    request.method === 'POST'
  ) {
    const body = await safeJson(request);
    const id = Number(body.id);
    const reason = String(body.reason || 'admin_archive').trim().slice(0,500);

    if (!Number.isInteger(id) || id <= 0) {
      return json({ ok:false, error:'Invalid id' }, 400);
    }

    const result = await env.DB
      .prepare('UPDATE items SET status=?, archived_at=?, archive_reason=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
      .bind('archived', nowIso(), reason || 'admin_archive', id)
      .run();

    if (!Number(result.meta?.changes || 0)) {
      return json({ ok:false, error:'Item not found' }, 404);
    }

    await audit(env, admin.id, 'archive', 'item', id, { reason });
    return json({ ok:true });
  }

  /*
    Unpublish: remove from public listings but keep it for admin/history.
  */
  if (
    path === '/api/admin/item/unpublish' &&
    request.method === 'POST'
  ) {
    const body = await safeJson(request);
    const id = Number(body.id);

    if (!Number.isInteger(id) || id <= 0) {
      return json({ ok:false, error:'Invalid id' }, 400);
    }

    const result = await env.DB
      .prepare('UPDATE items SET status=?, verification_status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?')
      .bind('verification_required', 'admin_unpublished', id)
      .run();

    if (!Number(result.meta?.changes || 0)) {
      return json({ ok:false, error:'Item not found' }, 404);
    }

    await audit(env, admin.id, 'unpublish', 'item', id);
    return json({ ok:true });
  }

  /*
    Complete revision/change history for one item.
  */
  if (
    path === '/api/admin/item/history' &&
    request.method === 'GET'
  ) {
    const id = Number(url.searchParams.get('id'));

    if (!Number.isInteger(id) || id <= 0) {
      return json({ ok:false, error:'Invalid id' }, 400);
    }

    const rows = (
      await env.DB
        .prepare('SELECT * FROM item_revisions WHERE item_id=? ORDER BY revision_no DESC LIMIT 100')
        .bind(id)
        .all()
    ).results || [];

    return json({ ok:true, history:rows });
  }

  /*
    Reject item
  */
  if (
    path ===
      '/api/admin/item/reject' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error: 'Invalid id'
        },
        400
      );
    }

    const result =
      await env.DB
        .prepare(`
          UPDATE items
          SET
            status='rejected',
            verification_status='rejected',
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(id)
        .run();

    if (
      Number(
        result.meta?.changes || 0
      ) === 0
    ) {
      return json(
        {
          ok: false,
          error:
            'Item not found'
        },
        404
      );
    }

    await audit(
      env,
      admin.id,
      'reject',
      'item',
      id
    );

    return json({
      ok: true
    });
  }

  /*
    Save source
  */
  if (
    path ===
      '/api/admin/source/save' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error: 'Invalid id'
        },
        400
      );
    }

    const existing =
      await env.DB
        .prepare(`
          SELECT *
          FROM sources
          WHERE id=?
        `)
        .bind(id)
        .first();

    if (!existing) {
      return json(
        {
          ok: false,
          error:
            'Source not found'
        },
        404
      );
    }

    const name =
      String(
        body.name || ''
      ).trim();

    const baseUrl =
      String(
        body.base_url || ''
      ).trim();

    const domains =
      String(
        body.allowed_domains || ''
      ).trim();

    const adapter =
      String(
        body.adapter ||
        'generic'
      ).trim();

    const fallbackKey =
      String(
        body.fallback_key ||
        '*'
      ).trim();

    const priority =
      Number(
        body.priority ?? 50
      );

    const enabled =
      body.enabled
        ? 1
        : 0;

    if (
      !name ||
      !baseUrl ||
      !domains
    ) {
      return json(
        {
          ok: false,
          error:
            'Name, base URL and allowed domains are required'
        },
        400
      );
    }

    if (
      !Number.isFinite(priority)
    ) {
      return json(
        {
          ok: false,
          error:
            'Invalid priority'
        },
        400
      );
    }

    /*
      Admin cannot change an official
      source into a portal or vice versa
      from this endpoint.
    */
    const result =
      await env.DB
        .prepare(`
          UPDATE sources
          SET
            name=?,
            base_url=?,
            allowed_domains=?,
            adapter=?,
            fallback_key=?,
            priority=?,
            enabled=?,
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(
          name,
          baseUrl,
          domains,
          adapter,
          fallbackKey,
          priority,
          enabled,
          id
        )
        .run();

    await audit(
      env,
      admin.id,
      'update_source',
      'source',
      id,
      {
        name,
        base_url: baseUrl,
        allowed_domains: domains,
        adapter,
        fallback_key: fallbackKey,
        priority,
        enabled
      }
    );

    return json({
      ok: true,
      changes:
        Number(
          result.meta?.changes || 0
        )
    });
  }

  /*
    Change password
  */
  if (
    path ===
      '/api/admin/password' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    if (
      !body.current ||
      !body.next ||
      String(body.next).length < 10
    ) {
      return json(
        {
          ok: false,
          error:
            'Password must be at least 10 characters'
        },
        400
      );
    }

    if (
      !(await verifyPassword(
        String(body.current),
        admin.password_hash
      ))
    ) {
      return json(
        {
          ok: false,
          error:
            'Current password is incorrect'
        },
        403
      );
    }

    const salt =
      randomToken().slice(0, 32);

    const passwordHash =
      await hashPassword(
        String(body.next),
        salt
      );

    await env.DB
      .prepare(`
        UPDATE admins
        SET password_hash=?
        WHERE id=?
      `)
      .bind(
        passwordHash,
        admin.id
      )
      .run();

    /*
      Invalidate all existing sessions
      after a password change.
    */
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE admin_id=?
      `)
      .bind(admin.id)
      .run();

    await audit(
      env,
      admin.id,
      'change_password',
      'admin',
      admin.id
    );

    return json({
      ok: true
    });
  }

  /*
    Change email
  */
  if (
    path ===
      '/api/admin/email' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const email =
      String(
        body.email || ''
      )
        .trim()
        .toLowerCase();

    if (
      !/^\S+@\S+\.\S+$/.test(email)
    ) {
      return json(
        {
          ok: false,
          error:
            'Invalid email'
        },
        400
      );
    }

    try {
      await env.DB
        .prepare(`
          UPDATE admins
          SET email=?
          WHERE id=?
        `)
        .bind(
          email,
          admin.id
        )
        .run();
    } catch {
      return json(
        {
          ok: false,
          error:
            'Email is already in use'
        },
        409
      );
    }

    await audit(
      env,
      admin.id,
      'change_email',
      'admin',
      admin.id
    );

    return json({
      ok: true
    });
  }

  /*
    Mark notification read
  */
  if (
    path ===
      '/api/admin/notification/read' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error:
            'Invalid id'
        },
        400
      );
    }

    await env.DB
      .prepare(`
        UPDATE notifications
        SET read_at=?
        WHERE id=?
      `)
      .bind(
        nowIso(),
        id
      )
      .run();

    return json({
      ok: true
    });
  }

  return json(
    {
      ok: false,
      error: 'Not found'
    },
    404
  );
}

/*
  Login page
*/
function loginPage() {
  return new Response(
    `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — North Bharat Jobs</title>
<style>
body{
  font-family:system-ui;
  background:#eef3f9;
  display:grid;
  place-items:center;
  min-height:100vh;
  margin:0
}
.box{
  background:white;
  padding:28px;
  border-radius:16px;
  box-shadow:0 10px 35px #0001;
  width:min(380px,90%)
}
input,button{
  width:100%;
  padding:12px;
  margin:7px 0;
  border-radius:9px;
  border:1px solid #ccd5e2;
  box-sizing:border-box
}
button{
  background:#155eef;
  color:white;
  border:0;
  font-weight:700
}
</style>
</head>
<body>
<form class="box"
      method="post"
      action="/api/admin/login">
<h1>North Bharat Jobs</h1>
<p>Admin Portal</p>
<input
  name="email"
  type="email"
  placeholder="Admin email"
  required>
<input
  name="password"
  type="password"
  placeholder="Password"
  required>
<button type="submit">
Login
</button>
</form>
</body>
</html>`,
    {
      headers: {
        'content-type': 'text/html; charset=UTF-8',
        'cache-control': 'no-store, no-cache, must-revalidate',
        'pragma': 'no-cache',
        'expires': '0'
      }
    }
  );
}

/*
  Admin login
*/
async function handleLogin(
  env,
  request
) {
  const contentType =
    request.headers.get(
      'content-type'
    ) || '';

  let email = '';
  let password = '';

  if (
    contentType.includes(
      'application/json'
    )
  ) {
    const body =
      await safeJson(request);

    email =
      String(
        body.email || ''
      );

    password =
      String(
        body.password || ''
      );
  } else {
    const form =
      await request.formData();

    email =
      String(
        form.get('email') || ''
      );

    password =
      String(
        form.get('password') || ''
      );
  }

  email =
    email
      .trim()
      .toLowerCase();

  /*
    First admin can be seeded from
    ADMIN_EMAIL / ADMIN_PASSWORD secrets.
  */
  await ensureAdmin(env);

  let admin =
    await env.DB
      .prepare(`
        SELECT *
        FROM admins
        WHERE email=?
      `)
      .bind(email)
      .first();

  /*
    Admin recovery/bootstrap:
    If the submitted credentials exactly match the
    Cloudflare ADMIN_EMAIL / ADMIN_PASSWORD secrets,
    allow them to repair an existing admin account too.
    This fixes the common case where the D1 admin was
    created with an older email/password.
  */
  const configuredEmail =
    String(env.ADMIN_EMAIL || '')
      .trim()
      .toLowerCase();
  const configuredPassword =
    String(env.ADMIN_PASSWORD || '');

  const matchesConfiguredCredentials =
    configuredEmail &&
    configuredPassword &&
    email === configuredEmail &&
    password === configuredPassword;

  if (
    matchesConfiguredCredentials
  ) {
    if (!admin) {
      admin =
        await env.DB
          .prepare(`
            SELECT *
            FROM admins
            ORDER BY id ASC
            LIMIT 1
          `)
          .first();
    }

    if (admin) {
      const salt =
        randomToken().slice(0, 32);
      const passwordHash =
        await hashPassword(
          configuredPassword,
          salt
        );

      await env.DB
        .prepare(`
          UPDATE admins
          SET email=?, password_hash=?
          WHERE id=?
        `)
        .bind(
          configuredEmail,
          passwordHash,
          admin.id
        )
        .run();

      admin =
        await env.DB
          .prepare(`
            SELECT *
            FROM admins
            WHERE id=?
          `)
          .bind(admin.id)
          .first();
    } else {
      await ensureAdmin(env);
      admin =
        await env.DB
          .prepare(`
            SELECT *
            FROM admins
            WHERE email=?
          `)
          .bind(configuredEmail)
          .first();
    }
  }

  if (
    !admin ||
    !(await verifyPassword(
      password,
      admin.password_hash
    ))
  ) {
    return new Response(
      'Invalid credentials',
      {
        status: 401,
        headers: {
          'content-type':
            'text/plain; charset=UTF-8'
        }
      }
    );
  }

  const token =
    randomToken();

  const tokenHash =
    await sha256Hex(token);

  const expires =
    new Date(
      Date.now() +
      SESSION_DAYS *
      86_400_000
    ).toISOString();

  await env.DB
    .prepare(`
      INSERT INTO sessions(
        token_hash,
        admin_id,
        expires_at
      )
      VALUES(?,?,?)
    `)
    .bind(
      tokenHash,
      admin.id,
      expires
    )
    .run();

  await env.DB
    .prepare(`
      UPDATE admins
      SET last_login_at=?
      WHERE id=?
    `)
    .bind(
      nowIso(),
      admin.id
    )
    .run();

  const sessionCookie = cookieHeader(
    token,
    SESSION_DAYS *
      86_400
  );

  if (
    contentType.includes(
      'application/json'
    )
  ) {
    return new Response(
      JSON.stringify({
        ok: true
      }),
      {
        headers: {
          ...jsonHeaders,
          'set-cookie': sessionCookie
        }
      }
    );
  }

  return new Response(null, {
    status: 303,
    headers: {
      location: new URL(
        '/admin/',
        request.url
      ).toString(),
      'set-cookie': sessionCookie,
      'cache-control': 'no-store'
    }
  });
}

/*
  Logout
*/
async function logout(
  env,
  request
) {
  const token =
    cookieToken(request);

  if (token) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token_hash=?
      `)
      .bind(
        await sha256Hex(token)
      )
      .run();
  }

  return new Response(
    '',
    {
      status: 204,
      headers: {
        'set-cookie':
          cookieHeader('', 0)
      }
    }
  );
}

/*
  Public item HTML
*/
async function publicItemPage(
  env,
  request,
  slug
) {
  const item =
    await env.DB
      .prepare(`
        SELECT *
        FROM items
        WHERE
          slug=?
          AND status='published'
          AND (
            published_at IS NOT NULL
            AND published_at >= datetime('now','-365 day')
          )
      `)
      .bind(slug)
      .first();

  if (!item) {
    return env.ASSETS.fetch(
      new Request(
        new URL(
          '/index.html',
          request.url
        ),
        request
      )
    );
  }

  const facts = [
    ['Post', item.title],
    ['Organization', item.organization],
    ['Category', item.category],
    ['Location', item.location],
    ['Vacancies', item.vacancies],
    ['Qualification', item.qualification],
    ['Eligibility', item.eligibility],
    ['Age Limit', item.age_limit],
    ['Age Relaxation', item.age_relaxation],
    ['Fee', item.fee],
    ['Salary', item.salary],
    ['Selection Process', item.selection_process],
    ['Application Start', item.application_start],
    ['Last Date', item.last_date],
    ['Exam Date', item.exam_date],
    ['How to Apply', item.how_to_apply],
    ['Important Dates', item.important_dates]
  ];

  const factsHtml =
    facts
      .filter(
        fact =>
          fact[1] !== null &&
          fact[1] !== undefined &&
          String(fact[1]).trim() !== ''
      )
      .map(
        fact =>
          `<div><b>${esc(fact[0])}</b><span>${esc(fact[1])}</span></div>`
      )
      .join('');

  const actions = [];

  const publicOfficialUrl = publicSafeUrl(item.official_url);
  const publicNotificationUrl = publicSafeUrl(item.notification_url);
  const publicApplyUrl = publicSafeUrl(item.apply_url);

  if (publicOfficialUrl) {
    actions.push(
      `<a href="${esc(publicOfficialUrl)}" target="_blank" rel="noopener noreferrer">Official Website</a>`
    );
  }

  if (publicNotificationUrl) {
    actions.push(
      `<a href="${esc(publicNotificationUrl)}" target="_blank" rel="noopener noreferrer">Notification PDF</a>`
    );
  }

  if (publicApplyUrl) {
    actions.push(
      `<a href="${esc(publicApplyUrl)}" target="_blank" rel="noopener noreferrer">Apply Online</a>`
    );
  }

  return new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>${esc(item.title)} | North Bharat Jobs</title>
<meta
  name="description"
  content="${esc(
    (item.description || '').slice(0, 155)
  )}">
<link rel="stylesheet"
      href="/style.css">
</head>

<body>

<header class="top">
<a href="/" class="brand">
North Bharat Jobs
</a>
<a href="/">
Home
</a>
</header>

<main class="detail">

<div class="badge">
${esc(item.type)}
</div>

<h1>
${esc(item.title)}
</h1>

<p class="muted">
${esc(item.organization || '')}
${item.location
  ? ` • ${esc(item.location)}`
  : ''}
</p>

<section class="facts">
${factsHtml}
</section>

<article>
<h2>Description</h2>
<p>
${esc(
  item.description ||
  'Verified details are shown from the available source evidence.'
)}
</p>
</article>

${
  actions.length
    ? `<div class="actions">${actions.join('')}</div>`
    : ''
}

</main>
</body>
</html>`,
    {
      headers: htmlHeaders
    }
  );
}

/*
  Main Worker
*/
export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    const url =
      new URL(request.url);

    /*
      Login/logout do not require
      an existing session.
    */
    if (
      url.pathname ===
        '/api/admin/login' &&
      request.method === 'POST'
    ) {
      return handleLogin(
        env,
        request
      );
    }

    if (
      url.pathname ===
        '/api/admin/logout' &&
      request.method === 'POST'
    ) {
      return logout(
        env,
        request
      );
    }

    /*
      Seed first admin if configured.
    */
    await ensureAdmin(env);

    /*
      Admin pages
    */
    if (
      url.pathname === '/admin/' ||
      url.pathname === '/admin'
    ) {
      const admin =
        await adminFromRequest(
          env,
          request
        );

      if (!admin) {
        return loginPage();
      }

      const adminResponse =
        await env.ASSETS.fetch(
          new Request(
            new URL(
              '/admin.html',
              request.url
            ),
            request
          )
        );

      const adminHeaders =
        new Headers(
          adminResponse.headers
        );

      adminHeaders.set(
        'cache-control',
        'no-store, no-cache, must-revalidate'
      );
      adminHeaders.set(
        'pragma',
        'no-cache'
      );
      adminHeaders.set(
        'expires',
        '0'
      );

      return new Response(
        adminResponse.body,
        {
          status:
            adminResponse.status,
          statusText:
            adminResponse.statusText,
          headers:
            adminHeaders
        }
      );
    }

    if (
      url.pathname ===
      '/admin.html'
    ) {
      const admin =
        await adminFromRequest(
          env,
          request
        );

      if (!admin) {
        return new Response(
          'Unauthorized',
          {
            status: 401
          }
        );
      }

      return env.ASSETS.fetch(
        request
      );
    }

    /*
      All admin APIs require a valid
      session.
    */
    if (
      url.pathname.startsWith(
        '/api/admin/'
      )
    ) {
      const admin =
        await requireAdmin(
          env,
          request
        );

      if (!admin) {
        return json(
          {
            ok: false,
            error:
              'Unauthorized'
          },
          401
        );
      }

      return adminApi(
        env,
        request,
        url,
        admin
      );
    }

    /*
      Public API
    */
    if (
      url.pathname ===
      '/api/jobs'
    ) {
      return publicList(
        env,
        url
      );
    }

    if (
      url.pathname.startsWith(
        '/api/jobs/'
      )
    ) {
      return publicItem(
        env,
        decodeURIComponent(
          url.pathname.slice(
            '/api/jobs/'.length
          )
        )
      );
    }

    /*
      Health endpoint
    */
    if (
      url.pathname ===
      '/api/health'
    ) {
      return json({
        ok: true,
        service:
          'north-bharat-jobs',
        time: nowIso()
      });
    }

    /*
      Sitemap
    */
    if (
      url.pathname ===
      '/sitemap.xml'
    ) {
      const rows =
        (
          await env.DB
            .prepare(`
              SELECT
                slug,
                updated_at
              FROM items
              WHERE
                status='published'
                AND (
                  published_at IS NULL
                  OR published_at >= datetime('now','-365 day')
                )
              ORDER BY
                updated_at DESC
              LIMIT 5000
            `)
            .all()
        ).results || [];

      const origin =
        siteOrigin(request);

      const staticUrls = [
        `${origin}/`,
        `${origin}/about.html`,
        `${origin}/contact.html`,
        `${origin}/privacy.html`
      ];

      const staticXml =
        staticUrls
          .map(
            value =>
              `<url><loc>${esc(value)}</loc></url>`
          )
          .join('');

      const itemXml =
        rows
          .map(
            row =>
              `<url><loc>${esc(
                `${origin}/item/${encodeURIComponent(row.slug)}`
              )}</loc><lastmod>${new Date(
                row.updated_at
              ).toISOString()}</lastmod></url>`
          )
          .join('');

      const body =
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
        staticXml +
        itemXml +
        `</urlset>`;

      return new Response(
        body,
        {
          headers: {
            'content-type':
              'application/xml; charset=UTF-8',
            'cache-control':
              'public,max-age=900'
          }
        }
      );
    }

    /*
      Robots
    */
    if (
      url.pathname ===
      '/robots.txt'
    ) {
      return new Response(
        `User-agent: *
Allow: /
Disallow: /admin
Disallow: /api/admin
Sitemap: ${siteOrigin(request)}/sitemap.xml
`,
        {
          headers: {
            'content-type':
              'text/plain; charset=UTF-8'
          }
        }
      );
    }

    /*
      Public SEO item page
    */
    if (
      url.pathname.startsWith(
        '/item/'
      )
    ) {
      return publicItemPage(
        env,
        request,
        decodeURIComponent(
          url.pathname.slice(
            '/item/'.length
          )
        )
      );
    }

    /*
      IMPORTANT:
      /api/cron is intentionally NOT
      exposed anymore.

      Monitoring is performed only
      through the Cloudflare scheduled()
      handler or authenticated admin
      discovery endpoint.
    */

    if (
      request.method === 'GET'
    ) {
      return env.ASSETS.fetch(
        request
      );
    }

    return json(
      {
        ok: false,
        error: 'Not found'
      },
      404
    );
  },

  /*
    Cloudflare Cron Trigger
  */
  async scheduled(
    event,
    env,
    ctx
  ) {
    /*
      The frequent 5-minute Cron only monitors one source.
      The daily 02:17 UTC Cron additionally performs the
      bounded 365-day retention cleanup.
    */
    const maintenance =
      event?.cron === '17 2 * * *';

    await runMonitor(
      env,
      null,
      { maintenance }
    );
  }
};
