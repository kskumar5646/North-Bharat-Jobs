import { discoverFromSource, discoverPortal } from './sources.js';
import { canonicalNotificationKey, slugify, verifyCandidate, sha256Hex } from './verification.js';

const RETRY_LIMIT = 20;
const RETRY_MINUTES = 5;
const RETENTION_DAYS = 365;
const SOURCE_BATCH = 4;

function iso(d = new Date()) { return d.toISOString(); }
function dayKey(d = new Date()) { return d.toISOString().slice(0,10); }
function plusMinutes(d, m) { return new Date(d.getTime() + m * 60000).toISOString(); }
function plusDays(d, n) { return new Date(d.getTime() + n * 86400000).toISOString(); }
function errorKind(error) {
  const s = `${error?.message || ''}`.toLowerCase();
  const code = Number(error?.status || 0);
  if (/captcha|challenge|access denied|security check|cloudflare ray id/.test(s)) return 'security_challenge';
  if (code === 404) return 'not_found';
  if (code === 401 || code === 403) return 'access_denied';
  if (code === 429) return 'rate_limited';
  if (code >= 500 || /fetch-error|timeout|aborted|522|525|network/.test(s)) return 'transient';
  return 'error';
}

async function resetRetryIfNewDay(db, source, now) {
  const today = dayKey(now);
  if (source.retry_day !== today) {
    await db.prepare(`UPDATE sources SET retry_day=?, retry_count=0, next_retry_at=?, circuit_until=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(today, iso(now), source.id).run();
    return { ...source, retry_day: today, retry_count: 0, next_retry_at: iso(now), circuit_until: null };
  }
  return source;
}

function candidateKey(c) { return canonicalNotificationKey(c); }
function comparable(c) {
  const norm = v => String(v ?? '').trim().toLowerCase().replace(/\s+/g,' ');
  return [norm(c.title), norm(c.organization), norm(c.vacancies), norm(c.qualification), norm(c.eligibility), norm(c.last_date), norm(c.application_start), norm(c.fee), norm(c.selection_process), norm(c.salary)].join('|');
}

async function archiveExpired(db) {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86400000).toISOString();
  const r = await db.prepare(`UPDATE items SET status='archived', archived_at=CURRENT_TIMESTAMP, archive_reason='retention-365-days', updated_at=CURRENT_TIMESTAMP WHERE status <> 'archived' AND COALESCE(published_at, created_at) < ?`).bind(cutoff).run();
  return r.meta?.changes || 0;
}

async function recordEvent(db, {itemId=null, sourceId=null, eventType, severity='info', message, evidence=null}) {
  await db.prepare(`INSERT INTO verification_events(item_id,source_id,event_type,severity,message,evidence_json) VALUES(?,?,?,?,?,?)`).bind(itemId,sourceId,eventType,severity,message,evidence ? JSON.stringify(evidence) : null).run();
}

async function notify(db, kind, title, message, itemId=null) {
  await db.prepare(`INSERT INTO notifications(kind,title,message,item_id) VALUES(?,?,?,?)`).bind(kind,title,message,itemId).run();
}

async function sourceSuccess(db, source, now) {
  await db.prepare(`UPDATE sources SET retry_day=?,retry_count=0,next_retry_at=?,circuit_until=NULL,last_checked_at=?,last_success_at=?,last_error=NULL,last_error_code=NULL,last_error_type=NULL,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(dayKey(now), iso(now), iso(now), iso(now), source.id).run();
}

async function sourceFailure(db, source, error, now) {
  const current = await resetRetryIfNewDay(db, source, now);
  const kind = errorKind(error);
  const code = Number(error?.status || 0) || null;
  let count = current.retry_count + 1;
  let next = plusMinutes(now, RETRY_MINUTES);
  let circuit = null;
  if (kind === 'security_challenge') { next = plusDays(now, 1); circuit = next; }
  else if (kind === 'not_found') { next = plusDays(now, 1); circuit = next; }
  else if (kind === 'access_denied' && count < 3) { next = plusMinutes(now, 60); }
  else if (kind === 'access_denied') { next = plusDays(now, 1); circuit = next; }
  else if (kind === 'rate_limited') {
    const retryAfter = Number(error?.retryAfter || 0);
    next = retryAfter > 0 ? new Date(now.getTime() + retryAfter * 1000).toISOString() : plusMinutes(now, 10);
  }
  if (count >= RETRY_LIMIT) circuit = plusDays(now, 1);
  await db.prepare(`UPDATE sources SET retry_day=?,retry_count=?,next_retry_at=?,circuit_until=?,last_checked_at=?,last_error=?,last_error_code=?,last_error_type=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(dayKey(now), count, next, circuit, iso(now), String(error?.message || error), code, kind, source.id).run();
  return { count, kind, next, circuit };
}

async function upsertOfficial(db, candidate, verification, source, now) {
  const key = candidateKey(candidate);
  const hash = await sha256Hex(JSON.stringify(candidate));
  const existing = await db.prepare(`SELECT * FROM items WHERE notification_key=? OR canonical_url=? OR source_url=? ORDER BY id LIMIT 1`).bind(key, candidate.canonical_url || candidate.source_url, candidate.source_url).first();
  const validationOk = verification.ok && verification.confidence >= 85;
  const status = validationOk ? 'published' : 'verification_required';
  const fields = {
    notification_key:key, type:candidate.type || 'update', title:candidate.title, organization:candidate.organization,
    category:candidate.category, location:candidate.location || null, description:candidate.description,
    eligibility:candidate.eligibility, qualification:candidate.qualification, vacancies:candidate.vacancies,
    age_limit:candidate.age_limit, age_relaxation:candidate.age_relaxation, fee:candidate.fee,
    selection_process:candidate.selection_process, salary:candidate.salary, application_start:candidate.application_start,
    last_date:candidate.last_date, exam_date:candidate.exam_date, how_to_apply:candidate.how_to_apply,
    important_dates:candidate.important_dates, official_url:candidate.official_url, apply_url:candidate.apply_url,
    notification_url:candidate.notification_url, source_url:candidate.source_url, source_name:source.name, source_id:source.id,
    source_hash:hash, canonical_url:candidate.canonical_url || candidate.source_url, status,
    verification_status:validationOk ? 'verified' : 'verification_required', confidence_score:verification.confidence,
    evidence_json:JSON.stringify({errors:verification.errors,warnings:verification.warnings,authority:'official'}),
    last_verified_at:validationOk ? iso(now) : null, last_seen_at:iso(now), published_at:existing?.published_at || (validationOk ? iso(now) : null)
  };
  if (existing) {
    const changed = Object.keys(fields).filter(k => String(existing[k] ?? '') !== String(fields[k] ?? ''));
    const revision = Number((await db.prepare(`SELECT COALESCE(MAX(revision_no),0)+1 n FROM item_revisions WHERE item_id=?`).bind(existing.id).first())?.n || 1);
    await db.prepare(`INSERT INTO item_revisions(item_id,revision_no,changed_fields_json,snapshot_json) VALUES(?,?,?,?)`).bind(existing.id,revision,JSON.stringify(changed),JSON.stringify(fields)).run();
    const set = Object.keys(fields).map(k => `${k}=?`).join(',');
    await db.prepare(`UPDATE items SET ${set},updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(...Object.values(fields), existing.id).run();
    return { id:existing.id, updated:true, published:status==='published', verificationRequired:status==='verification_required' };
  }
  const slug = `${slugify(candidate.title)}-${(await sha256Hex(key)).slice(0,8)}`;
  const cols = Object.keys(fields).join(',');
  const qs = Object.keys(fields).map(()=>'?').join(',');
  const r = await db.prepare(`INSERT INTO items(slug,${cols},created_at,updated_at) VALUES(?,${qs},CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`).bind(slug,...Object.values(fields)).run();
  return { id:r.meta?.last_row_id, updated:false, published:status==='published', verificationRequired:status==='verification_required' };
}

async function runOfficial(db, source, now, stats) {
  const sourceFresh = await resetRetryIfNewDay(db, source, now);
  if (sourceFresh.circuit_until && new Date(sourceFresh.circuit_until) > now) return;
  if (sourceFresh.next_retry_at && new Date(sourceFresh.next_retry_at) > now) return;
  if (sourceFresh.retry_count >= RETRY_LIMIT) return;
  try {
    const candidates = await discoverFromSource(sourceFresh);
    for (const candidate of candidates.slice(0,8)) {
      const v = await verifyCandidate(candidate, sourceFresh);
      stats.discovered++;
      const result = await upsertOfficial(db,candidate,v,sourceFresh,now);
      if (result.published) stats.published++; else stats.verificationRequired++;
      if (result.updated) stats.updated++;
      if (result.verificationRequired) {
        await recordEvent(db,{itemId:result.id,sourceId:sourceFresh.id,eventType:'verification_required',severity:'warning',message:'Automatic official-source verification incomplete',evidence:{errors:v.errors,warnings:v.warnings}});
        await notify(db,'verification_required','Verification required',`Review: ${candidate.title}`,result.id);
      }
    }
    await sourceSuccess(db,sourceFresh,now);
  } catch (error) {
    stats.errors++;
    const f = await sourceFailure(db,sourceFresh,error,now);
    await recordEvent(db,{sourceId:sourceFresh.id,eventType:'source_error',severity:'error',message:`${f.kind}: ${error?.message || error}`,evidence:{retry_count:f.count,next_retry_at:f.next}});
    if (f.count >= RETRY_LIMIT) await runPortalsForFallback(db,sourceFresh,now,stats);
  }
}

async function runPortalsForFallback(db, official, now, stats) {
  const portals = await db.prepare(`SELECT * FROM sources WHERE enabled=1 AND role='portal' AND (fallback_key=? OR fallback_key='*') ORDER BY priority,id LIMIT 2`).bind(official.fallback_key).all();
  if ((portals.results || []).length < 2) {
    await notify(db,'configuration','Portal fallback not configured',`Official source ${official.name} reached its daily retry limit. Configure two enabled portal sources for fallback_key=${official.fallback_key}.`);
    return;
  }
  const found = [];
  for (const portal of portals.results) {
    try {
      const cs = await discoverPortal(portal);
      found.push({portal, candidates:cs});
    } catch (error) {
      stats.errors++;
      await recordEvent(db,{sourceId:portal.id,eventType:'portal_error',severity:'warning',message:`${portal.name}: ${error?.message || error}`});
    }
  }
  const byKey = new Map();
  for (const group of found) for (const c of group.candidates.slice(0,8)) {
    const k = candidateKey(c); const a = byKey.get(k) || []; a.push({...c,_portal:group.portal.name}); byKey.set(k,a);
  }
  for (const [key, candidates] of byKey) {
    const hasP1 = candidates.some(c => c._portal === portals.results[0].name);
    const hasP2 = candidates.some(c => c._portal === portals.results[1].name);
    if (!hasP1 || !hasP2) continue;
    const same = comparable(candidates[0]) === comparable(candidates.find(c => c._portal !== candidates[0]._portal));
    const merged = {...candidates[0], official_url:null, source_name:`${portals.results[0].name} + ${portals.results[1].name}`, source_id:null, source_url:candidates[0].source_url};
    const existing = await db.prepare(`SELECT * FROM items WHERE notification_key=? OR canonical_url=? LIMIT 1`).bind(key, merged.canonical_url).first();
    const title = merged.title;
    if (existing) {
      await db.prepare(`UPDATE items SET status='verification_required',verification_status='secondary_crosscheck',confidence_score=?,evidence_json=?,last_seen_at=?,updated_at=CURRENT_TIMESTAMP WHERE id=?`).bind(same?65:35,JSON.stringify({authority:'secondary_only',portals:[portals.results[0].name,portals.results[1].name],consistent:same}),iso(now),existing.id).run();
    } else {
      const slug = `${slugify(title)}-${(await sha256Hex(key)).slice(0,8)}`;
      await db.prepare(`INSERT OR IGNORE INTO items(slug,notification_key,type,title,organization,category,location,description,qualification,vacancies,age_limit,fee,selection_process,salary,application_start,last_date,exam_date,official_url,apply_url,notification_url,source_url,source_name,status,verification_status,confidence_score,evidence_json,last_seen_at,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`).bind(slug,key,merged.type||'job',merged.title,merged.organization,merged.category,merged.location,merged.description,merged.qualification,merged.vacancies,merged.age_limit,merged.fee,merged.selection_process,merged.salary,merged.application_start,merged.last_date,merged.exam_date,null,merged.apply_url,merged.notification_url,merged.source_url,merged.source_name,'verification_required','secondary_crosscheck',same?65:35,JSON.stringify({authority:'secondary_only',portals:[portals.results[0].name,portals.results[1].name],consistent:same} ),iso(now)).run();
    }
    stats.verificationRequired++;
    await notify(db,'verification_required',same?'Two-portal match needs admin verification':'Portal mismatch needs admin verification',`${title}. Official source was unavailable after the daily retry budget.`,existing?.id || null);
  }
}

export async function runMonitor(env, requestedSource = null) {
  const db = env.DB; const started = new Date();
  const stats = {sources:0,discovered:0,published:0,updated:0,verificationRequired:0,blocked:0,errors:0,archived:0,details:[]};
  stats.archived = await archiveExpired(db);
  let sources;
  if (requestedSource) {
    sources = (await db.prepare(`SELECT * FROM sources WHERE enabled=1 AND (name=? OR adapter=?) LIMIT 1`).bind(requestedSource,requestedSource).all()).results || [];
  } else {
    sources = (await db.prepare(`SELECT * FROM sources WHERE enabled=1 AND role='official' AND (next_retry_at IS NULL OR next_retry_at<=?) ORDER BY priority ASC,COALESCE(last_checked_at,'1970-01-01') ASC LIMIT ?`).bind(iso(started),SOURCE_BATCH).all()).results || [];
  }
  for (const source of sources) {
    stats.sources++;
    const before = stats.errors;
    await runOfficial(db,source,new Date(),stats);
    stats.details.push({source:source.name,error:stats.errors>before});
  }
  const finished = new Date();
  await db.prepare(`INSERT INTO monitor_runs(started_at,finished_at,source_count,discovered,published,updated,verification_required,blocked,errors,archived,details) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(iso(started),iso(finished),stats.sources,stats.discovered,stats.published,stats.updated,stats.verificationRequired,stats.blocked,stats.errors,stats.archived,JSON.stringify(stats.details)).run();
  return {started:iso(started),finished:iso(finished),...stats};
}
