import { isPdfUrl, normalizeUrl, sameHostOrAllowed } from './verification.js';

const WORDS = {
  job: /(recruit|vacan|career|appointment|notification|advertisement|post|application|constable|officer|assistant|teacher|engineer|clerk|group\s*[abc])/i,
  admit: /(admit\s*card|hall\s*ticket|call\s*letter)/i,
  result: /\b(result|merit|score|selection\s*list|shortlist)\b/i,
  answer: /(answer\s*key|response\s*sheet)/i,
  syllabus: /\bsyllabus\b/i,
  admission: /(admission|entrance|counselling|counseling)/i,
  scholarship: /\bscholarship\b/i,
  update: /(notice|latest|important|extension|corrigendum|exam\s*date|schedule)/i
};
const APPLY = /(apply\s*(online|now)|online\s*application|registration|login|application\s*form|careers?)/i;
const NOTIFY = /(notification|advertisement|detailed\s*advertisement|prospectus|recruitment.*pdf|notice.*pdf)/i;
const MAX_LINKS = 180;
const MAX_PAGES = 18;
const FETCH_TIMEOUT_MS = 12000;

function decodeEntities(s) { return s.replace(/&nbsp;/g,' ').replace(/&amp;/g,'&').replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/<[^>]+>/g,' '); }
function textOf(html) { return decodeEntities(html.replace(/<script[\s\S]*?<\/script>/gi,' ').replace(/<style[\s\S]*?<\/style>/gi,' ').replace(/<[^>]+>/g,' ')).replace(/\s+/g,' ').trim(); }
function linksOf(html, base) {
  const out = [];
  const re = /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) && out.length < MAX_LINKS) {
    try {
      const url = new URL(m[1], base).toString();
      out.push({ url, text: textOf(m[2]).slice(0, 500) });
    } catch {}
  }
  return out;
}

async function fetchWithTimeout(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const response = await fetch(url, { redirect:'follow', cache:'no-store', signal:controller.signal, headers:{'User-Agent':'NorthBharatJobs/1.0 (+official-source-monitor)','Accept':'text/html,application/xhtml+xml,application/pdf;q=0.9'} });
    const contentType = response.headers.get('content-type') || '';
    const body = await response.text();
    return { ok: response.ok, status: response.status, body, contentType, finalUrl: response.url || url, retryAfter: response.headers.get('retry-after') };
  } catch (e) { return { ok:false, status:0, body:'', contentType:'', finalUrl:url, error:String(e?.message || e) }; }
  finally { clearTimeout(timer); }
}

function classify(title, body) {
  const t = `${title} ${body.slice(0,5000)}`;
  if (WORDS.admit.test(t)) return 'admit_card';
  if (WORDS.result.test(t)) return 'result';
  if (WORDS.answer.test(t)) return 'answer_key';
  if (WORDS.syllabus.test(t)) return 'syllabus';
  if (WORDS.admission.test(t)) return 'admission';
  if (WORDS.scholarship.test(t)) return 'scholarship';
  if (WORDS.job.test(t)) return 'job';
  return 'update';
}

function extractDate(text, labels) {
  const month = '(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)';
  const patterns = [
    new RegExp(`(?:${labels})[^\\d]{0,30}(\\d{1,2}[\\/-]\\d{1,2}[\\/-]\\d{2,4})`, 'i'),
    new RegExp(`(?:${labels})[^\\d]{0,30}(\\d{1,2}\\s+${month}\\s+\\d{4})`, 'i'),
    new RegExp(`(?:${labels})[^\\d]{0,30}(${month}\\s+\\d{1,2},?\\s+\\d{4})`, 'i')
  ];
  for (const p of patterns) { const m = text.match(p); if (m) return m[1]; }
  return null;
}

function makeCandidate(page, source) {
  const titleMatch = page.body.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  const title = textOf(titleMatch?.[1] || page.body).slice(0, 220);
  const body = textOf(page.body).slice(0, 14000);
  const links = linksOf(page.body, page.finalUrl || page.url);
  const pdf = links.find(x => isPdfUrl(x.url) && NOTIFY.test(x.text + ' ' + x.url));
  const apply = links.find(x => !isPdfUrl(x.url) && APPLY.test(x.text + ' ' + x.url));
  const type = classify(title, body);
  const sourceUrl = normalizeUrl(page.finalUrl || page.url);
  return {
    type, title, organization: source.name, category: type,
    description: body.slice(0, 4000), eligibility: null, qualification: null,
    vacancies: null, age_limit: null, age_relaxation: null, fee: null,
    selection_process: null, salary: null,
    application_start: extractDate(body,'(?:application|registration|online application).*?(?:start|from|begins?)'),
    last_date: extractDate(body,'(?:last date|closing date|apply by|deadline|application.*?ends?)'),
    exam_date: extractDate(body,'(?:exam date|examination date|written exam|test date)'),
    how_to_apply: null, important_dates: null,
    official_url: source.role === 'official' ? sourceUrl : null,
    apply_url: apply?.url || null,
    notification_url: pdf?.url || null,
    source_url: sourceUrl, source_name: source.name, source_id: source.id,
    canonical_url: sourceUrl,
    notification_key: pdf?.url || sourceUrl,
    _source_role: source.role,
    _links: links.slice(0,20)
  };
}

export async function discoverFromSource(source) {
  const home = await fetchWithTimeout(source.base_url);
  if (!home.ok) throw Object.assign(new Error(`HTTP ${home.status || 'fetch-error'}`), { status: home.status, retryAfter: home.retryAfter });
  if (!/<html[\s>]/i.test(home.body.slice(0,5000)) && !/text\/html/i.test(home.contentType)) throw Object.assign(new Error('Security or unsupported content response'), { status: home.status });

  const all = linksOf(home.body, home.finalUrl || source.base_url).filter(x => sameHostOrAllowed(x.url, source.allowed_domains));
  const selected = all.filter(x => WORDS.job.test(x.text) || WORDS.admit.test(x.text) || WORDS.result.test(x.text) || WORDS.answer.test(x.text) || WORDS.syllabus.test(x.text) || WORDS.admission.test(x.text) || WORDS.scholarship.test(x.text) || WORDS.update.test(x.text)).slice(0, MAX_PAGES);
  const pages = [{ url: home.finalUrl || source.base_url, body: home.body }];
  for (const link of selected) {
    if (pages.length >= MAX_PAGES) break;
    const r = await fetchWithTimeout(link.url);
    if (r.ok && /html/i.test(r.contentType || '') || /<html[\s>]/i.test(r.body.slice(0,2000))) pages.push({ url: link.url, body: r.body, finalUrl:r.finalUrl });
  }
  const seen = new Set(); const candidates = [];
  for (const p of pages) {
    const c = makeCandidate(p, source);
    if (!c.title || seen.has(c.source_url)) continue;
    seen.add(c.source_url);
    if (c.type === 'job' && !c.notification_url && !c.apply_url) continue;
    candidates.push(c);
  }
  return candidates;
}

export async function discoverPortal(source) { return discoverFromSource(source); }
