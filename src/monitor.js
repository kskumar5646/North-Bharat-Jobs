/*
  North Bharat Jobs
  Official-source monitoring engine

  FLOW
  ----
  1. Scan official sources.
  2. Verify official candidates.
  3. Publish only when official evidence is complete.
  4. Official-source branch and Portal branch are completely independent.
  5. Branch B:
       Portal 1 + Portal 2 -> factual comparison -> Google cross-check
       -> data/URL gates -> publish OR Admin.
  6. Branch B NEVER calls official-source verification.
  7. Google is supporting cross-check evidence, not an authority.
  8. Any mismatch/error/unavailable/uncertainty -> Admin verification.
  8. Existing recruitment is updated in-place.
  9. No duplicate for a revised notification.
  10. Real revisions only are stored.
  11. Temporary official-source failure must NOT destroy
      an already published record.
  12. Records older than 365 days are archived in bounded batches;
      history and deduplication identity are preserved.
*/

import {
  discoverFromSource,
  discoverPortal,
  discoverPortalNewOnly
} from './sources.js';

import {
  canonicalNotificationKey,
  slugify,
  verifyCandidate,
  sha256Hex
} from './verification.js';


/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const RETRY_LIMIT = 20;
const RETRY_MINUTES = 5;

const RETENTION_DAYS = 365;

// Free Workers allows only 10 ms CPU per Cron invocation.
// Process one official source per run instead of four at once.
const SOURCE_BATCH = 1;
const CANDIDATE_LIMIT = 8;

const PORTAL_LIMIT = 2;

const RETENTION_DELETE_BATCH = 100;
const PORTAL_SCAN_DAYS = 1;
const PORTAL_SEEN_URL_LIMIT = 2000;
const PORTAL_NEW_CANDIDATE_LIMIT = 8;
const PORTAL_EVIDENCE_TTL_DAYS = 2;



/* -------------------------------------------------------------------------- */
/* Time helpers                                                               */
/* -------------------------------------------------------------------------- */

function iso(date = new Date()) {
  return date.toISOString();
}

function dayKey(date = new Date()) {
  return date.toISOString().slice(0, 10);
}

function plusMinutes(date, minutes) {
  return new Date(
    date.getTime() + minutes * 60_000
  ).toISOString();
}

function plusDays(date, days) {
  return new Date(
    date.getTime() + days * 86_400_000
  ).toISOString();
}


/* -------------------------------------------------------------------------- */
/* Generic helpers                                                            */
/* -------------------------------------------------------------------------- */

function safeJson(value) {
  try {
    return JSON.stringify(value ?? null);
  } catch {
    return JSON.stringify(null);
  }
}

function normalizeComparable(value) {
  return String(value ?? '')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
}

function comparable(candidate) {
  return [
    normalizeComparable(candidate.title),
    normalizeComparable(candidate.organization),
    normalizeComparable(candidate.vacancies),
    normalizeComparable(candidate.qualification),
    normalizeComparable(candidate.eligibility),
    normalizeComparable(candidate.last_date),
    normalizeComparable(candidate.application_start),
    normalizeComparable(candidate.exam_date),
    normalizeComparable(candidate.fee),
    normalizeComparable(candidate.selection_process),
    normalizeComparable(candidate.salary)
  ].join('|');
}

function candidateKey(candidate) {
  return canonicalNotificationKey(candidate);
}

function hasUsableUrl(value) {
  return Boolean(
    String(value || '').trim()
  );
}

function hasCompleteRecruitmentUrls(candidate) {
  return Boolean(
    hasUsableUrl(candidate?.official_url) &&
    hasUsableUrl(candidate?.notification_url) &&
    hasUsableUrl(candidate?.apply_url)
  );
}

function missingRecruitmentUrls(candidate) {
  const missing = [];

  if (!hasUsableUrl(candidate?.official_url)) {
    missing.push('official_url');
  }

  if (!hasUsableUrl(candidate?.notification_url)) {
    missing.push('notification_url');
  }

  if (!hasUsableUrl(candidate?.apply_url)) {
    missing.push('apply_url');
  }

  return missing;
}


/* -------------------------------------------------------------------------- */
/* Error classification                                                       */
/* -------------------------------------------------------------------------- */

function errorKind(error) {
  const message =
    `${error?.message || ''}`.toLowerCase();

  const status =
    Number(error?.status || 0);

  if (
    /captcha|challenge|security check|cloudflare ray id|just a moment/.test(
      message
    )
  ) {
    return 'security_challenge';
  }

  if (status === 404) {
    return 'not_found';
  }

  if (
    status === 401 ||
    status === 403
  ) {
    return 'access_denied';
  }

  if (status === 429) {
    return 'rate_limited';
  }

  if (
    status >= 500 ||
    /fetch-error|timeout|aborted|522|525|network|connection/.test(
      message
    )
  ) {
    return 'transient';
  }

  return 'error';
}


/* -------------------------------------------------------------------------- */
/* Retry handling                                                             */
/* -------------------------------------------------------------------------- */

async function resetRetryIfNewDay(
  db,
  source,
  now
) {
  const today =
    dayKey(now);

  if (
    source.retry_day === today
  ) {
    return source;
  }

  const nextRetry =
    iso(now);

  await db
    .prepare(`
      UPDATE sources
      SET
        retry_day=?,
        retry_count=0,
        next_retry_at=?,
        circuit_until=NULL,
        updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `)
    .bind(
      today,
      nextRetry,
      source.id
    )
    .run();

  return {
    ...source,
    retry_day: today,
    retry_count: 0,
    next_retry_at: nextRetry,
    circuit_until: null
  };
}

async function sourceSuccess(
  db,
  source,
  now
) {
  await db
    .prepare(`
      UPDATE sources
      SET
        retry_day=?,
        retry_count=0,
        next_retry_at=?,
        circuit_until=NULL,
        last_checked_at=?,
        last_success_at=?,
        last_error=NULL,
        last_error_code=NULL,
        last_error_type=NULL,
        updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `)
    .bind(
      dayKey(now),
      iso(now),
      iso(now),
      iso(now),
      source.id
    )
    .run();
}

async function sourceFailure(
  db,
  source,
  error,
  now
) {
  const current =
    await resetRetryIfNewDay(
      db,
      source,
      now
    );

  const kind =
    errorKind(error);

  const status =
    Number(error?.status || 0) || null;

  const retryCount =
    Number(current.retry_count || 0) + 1;

  let nextRetry =
    plusMinutes(
      now,
      RETRY_MINUTES
    );

  let circuitUntil =
    null;

  if (
    kind === 'security_challenge'
  ) {
    nextRetry =
      plusDays(now, 1);

    circuitUntil =
      nextRetry;
  }

  else if (
    kind === 'not_found'
  ) {
    nextRetry =
      plusDays(now, 1);

    circuitUntil =
      nextRetry;
  }

  else if (
    kind === 'access_denied' &&
    retryCount < 3
  ) {
    nextRetry =
      plusMinutes(now, 60);
  }

  else if (
    kind === 'access_denied'
  ) {
    nextRetry =
      plusDays(now, 1);

    circuitUntil =
      nextRetry;
  }

  else if (
    kind === 'rate_limited'
  ) {
    const retryAfter =
      Number(
        error?.retryAfter || 0
      );

    nextRetry =
      retryAfter > 0
        ? new Date(
            now.getTime() +
            retryAfter * 1000
          ).toISOString()
        : plusMinutes(now, 10);
  }

  if (
    retryCount >= RETRY_LIMIT
  ) {
    nextRetry =
      plusDays(now, 1);

    circuitUntil =
      nextRetry;
  }

  await db
    .prepare(`
      UPDATE sources
      SET
        retry_day=?,
        retry_count=?,
        next_retry_at=?,
        circuit_until=?,
        last_checked_at=?,
        last_error=?,
        last_error_code=?,
        last_error_type=?,
        updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `)
    .bind(
      dayKey(now),
      retryCount,
      nextRetry,
      circuitUntil,
      iso(now),
      String(
        error?.message || error
      ),
      status,
      kind,
      source.id
    )
    .run();

  return {
    count: retryCount,
    kind,
    next: nextRetry,
    circuit: circuitUntil
  };
}


/* -------------------------------------------------------------------------- */
/* Database events / admin notifications                                      */
/* -------------------------------------------------------------------------- */

async function recordEvent(
  db,
  {
    itemId = null,
    sourceId = null,
    eventType,
    severity = 'info',
    message,
    evidence = null
  }
) {
  await db
    .prepare(`
      INSERT INTO verification_events(
        item_id,
        source_id,
        event_type,
        severity,
        message,
        evidence_json
      )
      VALUES(?,?,?,?,?,?)
    `)
    .bind(
      itemId,
      sourceId,
      eventType,
      severity,
      message,
      evidence
        ? safeJson(evidence)
        : null
    )
    .run();
}

async function notify(
  db,
  kind,
  title,
  message,
  itemId = null
) {
  await db
    .prepare(`
      INSERT INTO notifications(
        kind,
        title,
        message,
        item_id
      )
      VALUES(?,?,?,?)
    `)
    .bind(
      kind,
      title,
      message,
      itemId
    )
    .run();
}


/* -------------------------------------------------------------------------- */
/* Retention                                                                 */
/* -------------------------------------------------------------------------- */

async function purgeExpiredItems(
  db,
  now
) {
  const cutoff = new Date(
    now.getTime() - RETENTION_DAYS * 86_400_000
  ).toISOString();

  /*
    Daily bounded cleanup: archive instead of DELETE.
    Public queries can exclude status='archived', while notification
    identity, revisions and history remain available for deduplication
    and audit.
  */
  const result = await db
    .prepare(`
      UPDATE items
      SET
        status='archived',
        archived_at=CURRENT_TIMESTAMP,
        archive_reason='retention_365_days',
        updated_at=CURRENT_TIMESTAMP
      WHERE id IN (
        SELECT id
        FROM items
        WHERE COALESCE(published_at, created_at) < ?
          AND COALESCE(status, '') != 'archived'
        LIMIT ?
      )
    `)
    .bind(cutoff, RETENTION_DELETE_BATCH)
    .run();

  return Number(result.meta?.changes || 0);
}


/* -------------------------------------------------------------------------- */
/* Existing item lookup                                                       */
/* -------------------------------------------------------------------------- */

async function findExistingItem(
  db,
  candidate,
  key
) {
  if (key) {
    const row =
      await db
        .prepare(`
          SELECT *
          FROM items
          WHERE notification_key=?
          ORDER BY id
          LIMIT 1
        `)
        .bind(key)
        .first();

    if (row) {
      return row;
    }
  }

  const canonical =
    candidate?.canonical_url ||
    null;

  if (canonical) {
    const row =
      await db
        .prepare(`
          SELECT *
          FROM items
          WHERE canonical_url=?
          ORDER BY id
          LIMIT 1
        `)
        .bind(canonical)
        .first();

    if (row) {
      return row;
    }
  }

  const sourceUrl =
    candidate?.source_url ||
    null;

  if (sourceUrl) {
    const row =
      await db
        .prepare(`
          SELECT *
          FROM items
          WHERE source_url=?
          ORDER BY id
          LIMIT 1
        `)
        .bind(sourceUrl)
        .first();

    if (row) {
      return row;
    }
  }

  return null;
}


/* -------------------------------------------------------------------------- */
/* Recruitment matching                                                      */
/* -------------------------------------------------------------------------- */

/*
  Portal candidate does not necessarily have the same
  notification_key because its source_id is different.

  Therefore we also compare the actual recruitment identity.
*/

function titleSimilarity(a, b) {
  const x =
    normalizeComparable(a);

  const y =
    normalizeComparable(b);

  if (!x || !y) {
    return false;
  }

  if (x === y) {
    return true;
  }

  if (
    x.includes(y) ||
    y.includes(x)
  ) {
    return true;
  }

  const ax =
    new Set(
      x.split(/\W+/)
        .filter(Boolean)
    );

  const by =
    new Set(
      y.split(/\W+/)
        .filter(Boolean)
    );

  if (
    ax.size < 3 ||
    by.size < 3
  ) {
    return false;
  }

  let common = 0;

  for (const word of ax) {
    if (by.has(word)) {
      common++;
    }
  }

  const ratio =
    common /
    Math.max(
      ax.size,
      by.size
    );

  return ratio >= 0.70;
}

function sameRecruitment(
  officialCandidate,
  portalCandidate
) {
  if (
    titleSimilarity(
      officialCandidate?.title,
      portalCandidate?.title
    )
  ) {
    return true;
  }

  const officialKey =
    normalizeComparable(
      officialCandidate?.notification_key
    );

  const portalKey =
    normalizeComparable(
      portalCandidate?.notification_key
    );

  if (
    officialKey &&
    portalKey &&
    officialKey === portalKey
  ) {
    return true;
  }

  return false;
}


/* -------------------------------------------------------------------------- */
/* Official candidate fields                                                  */
/* -------------------------------------------------------------------------- */

function buildOfficialFields(
  candidate,
  verification,
  source,
  now,
  existing,
  hash
) {
  const verified =
    verification?.ok === true &&
    Number(
      verification?.confidence || 0
    ) >= 85 &&
    hasCompleteRecruitmentUrls(
      candidate
    );

  /*
    IMPORTANT:
    If an existing item was already published
    and a temporary scan loses one URL, do not
    erase the good published data.

    The item remains published until an actual
    confirmed change is available.
  */
  const existingPublished =
    existing?.status === 'published';

  const recruitmentType =
    candidate?.type === 'job' ||
    candidate?.type === 'recruitment';

  const candidateHasAllRecruitmentUrls =
    !recruitmentType ||
    hasCompleteRecruitmentUrls(candidate);

  const requiresAdminReview =
    candidate?._requires_admin_review === true ||
    !candidateHasAllRecruitmentUrls ||
    (
      recruitmentType &&
      existing?.apply_url &&
      isRejectedApplyUrl(existing.apply_url, candidate) &&
      !candidate?.apply_url
    );

  /*
    A published item may survive a temporary scan that merely loses a
    valid URL, because the existing valid URL is preserved below.
    But if the scanner explicitly rejects an existing URL or sanitizes
    contradictory data, the item must move to admin verification instead
    of silently remaining published/verified.
  */
  const status =
    verified && !requiresAdminReview
      ? 'published'
      : requiresAdminReview
        ? 'verification_required'
        : existingPublished
          ? 'published'
          : 'verification_required';

  const verificationStatus =
    verified && !requiresAdminReview
      ? 'verified'
      : requiresAdminReview
        ? 'verification_required'
        : existingPublished
          ? 'verified'
          : 'verification_required';

  return {
    notification_key:
      candidateKey(candidate),

    type:
      candidate.type || 'update',

    title:
      candidate.title,

    organization:
      candidate.organization || null,

    category:
      candidate.category || null,

    location:
      candidate.location || null,

    description:
      candidate.description || null,

    eligibility:
      candidate.eligibility || null,

    qualification:
      candidate.qualification || null,

    vacancies:
      candidate.vacancies || null,

    age_limit:
      candidate.age_limit || null,

    age_relaxation:
      candidate.age_relaxation || null,

    fee:
      candidate.fee || null,

    selection_process:
      candidate.selection_process || null,

    salary:
      candidate.salary || null,

    application_start:
      candidate.application_start || null,

    last_date:
      candidate.last_date || null,

    exam_date:
      candidate.exam_date || null,

    how_to_apply:
      candidate.how_to_apply || null,

    important_dates:
      candidate.important_dates || null,

    /*
      Never replace a valid existing URL with NULL
      during an incomplete scan.
    */
    official_url:
      candidate.official_url ||
      existing?.official_url ||
      null,

    apply_url:
      candidate.apply_url ||
      (
        existing?.apply_url &&
        !isRejectedApplyUrl(existing.apply_url, candidate)
          ? existing.apply_url
          : null
      ),

    notification_url:
      candidate.notification_url ||
      existing?.notification_url ||
      null,

    source_url:
      candidate.source_url ||
      existing?.source_url,

    source_name:
      source.name,

    source_id:
      source.id,

    source_hash:
      hash,

    canonical_url:
      candidate.canonical_url ||
      candidate.source_url ||
      existing?.canonical_url ||
      null,

    status,

    verification_status:
      verificationStatus,

    confidence_score:
      verified
        ? Number(
            verification.confidence || 0
          )
        : existingPublished
          ? Number(
              existing.confidence_score || 0
            )
          : Number(
              verification?.confidence || 0
            ),

    evidence_json:
      safeJson({
        authority:
          'official',

        errors:
          verification?.errors || [],

        warnings:
          verification?.warnings || [],

        source_evidence:
          candidate?._evidence || [],

        source_evidence_score:
          candidate?._evidence_score || 0,

        sanitized_fields:
          candidate?._sanitized_fields || [],

        missing_urls:
          missingRecruitmentUrls(
            candidate
          ),

        admin_review_required:
          requiresAdminReview
      }),

    last_verified_at:
      verified
        ? iso(now)
        : existing?.last_verified_at ||
          null,

    last_seen_at:
      iso(now),

    published_at:
      existing?.published_at ||
      (
        verified
          ? iso(now)
          : null
      )
  };
}


/* -------------------------------------------------------------------------- */
/* Changed field detection                                                    */
/* -------------------------------------------------------------------------- */

function getChangedFields(
  existing,
  fields
) {
  return Object.keys(fields)
    .filter(field =>
      String(
        existing[field] ?? ''
      ) !==
      String(
        fields[field] ?? ''
      )
    );
}


/* -------------------------------------------------------------------------- */
/* Official upsert                                                            */
/* -------------------------------------------------------------------------- */

async function upsertOfficial(
  db,
  candidate,
  verification,
  source,
  now
) {
  const key =
    candidateKey(candidate);

  if (!key) {
    return {
      id: null,
      created: false,
      updated: false,
      changed: false,
      published: false,
      verificationRequired: true,
      blocked: true
    };
  }

  const hash =
    await sha256Hex(
      JSON.stringify(candidate)
    );

  const existing =
    await findExistingItem(
      db,
      candidate,
      key
    );

  const fields =
    buildOfficialFields(
      candidate,
      verification,
      source,
      now,
      existing,
      hash
    );

  /*
    Existing item.
  */
  if (existing) {
    const changedFields =
      getChangedFields(
        existing,
        fields
      );

    if (
      changedFields.length === 0
    ) {
      await db
        .prepare(`
          UPDATE items
          SET
            last_seen_at=?,
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(
          iso(now),
          existing.id
        )
        .run();

      return {
        id: existing.id,
        created: false,
        updated: false,
        changed: false,
        published:
          existing.status ===
          'published',
        verificationRequired:
          existing.status ===
          'verification_required',
        blocked: false
      };
    }

    const revisionRow =
      await db
        .prepare(`
          SELECT
            COALESCE(
              MAX(revision_no),
              0
            ) + 1 AS next_revision
          FROM item_revisions
          WHERE item_id=?
        `)
        .bind(existing.id)
        .first();

    const revisionNo =
      Number(
        revisionRow?.next_revision || 1
      );

    await db
      .prepare(`
        INSERT INTO item_revisions(
          item_id,
          revision_no,
          changed_fields_json,
          snapshot_json
        )
        VALUES(?,?,?,?)
      `)
      .bind(
        existing.id,
        revisionNo,
        safeJson(changedFields),
        safeJson(fields)
      )
      .run();

    const assignments =
      Object.keys(fields)
        .map(
          field =>
            `${field}=?`
        )
        .join(',');

    await db
      .prepare(`
        UPDATE items
        SET
          ${assignments},
          updated_at=CURRENT_TIMESTAMP
        WHERE id=?
      `)
      .bind(
        ...Object.values(fields),
        existing.id
      )
      .run();

    return {
      id: existing.id,
      created: false,
      updated: true,
      changed: true,
      published:
        fields.status ===
        'published',
      verificationRequired:
        fields.status ===
        'verification_required',
      blocked: false
    };
  }

  /*
    New item.
  */
  const slug =
    `${slugify(candidate.title)}-${(
      await sha256Hex(key)
    ).slice(0, 8)}`;

  const columns =
    Object.keys(fields);

  const placeholders =
    columns
      .map(() => '?')
      .join(',');

  const result =
    await db
      .prepare(`
        INSERT INTO items(
          slug,
          ${columns.join(',')},
          created_at,
          updated_at
        )
        VALUES(
          ?,
          ${placeholders},
          CURRENT_TIMESTAMP,
          CURRENT_TIMESTAMP
        )
      `)
      .bind(
        slug,
        ...Object.values(fields)
      )
      .run();

  const id =
    result.meta?.last_row_id ||
    null;

  return {
    id,
    created: true,
    updated: false,
    changed: true,
    published:
      fields.status ===
      'published',
    verificationRequired:
      fields.status ===
      'verification_required',
    blocked: false
  };
}



/* -------------------------------------------------------------------------- */
/* Portal new-only scan state                                                 */
/* -------------------------------------------------------------------------- */

function portalStateKey(source) {
  return `portal_scan:${Number(source.id)}`;
}

async function readPortalScanState(db, source) {
  const key = portalStateKey(source);

  const row = await db.prepare(`
    SELECT value
    FROM settings
    WHERE key=?
    LIMIT 1
  `).bind(key).first();

  if (!row?.value) {
    return {
      lastScanAt: null,
      seenUrls: []
    };
  }

  try {
    const parsed = JSON.parse(row.value);
    return {
      lastScanAt: parsed?.lastScanAt || null,
      seenUrls: Array.isArray(parsed?.seenUrls)
        ? parsed.seenUrls.slice(-PORTAL_SEEN_URL_LIMIT)
        : []
    };
  } catch {
    return {
      lastScanAt: null,
      seenUrls: []
    };
  }
}

async function writePortalScanState(db, source, state) {
  const key = portalStateKey(source);
  const value = safeJson({
    lastScanAt: state.lastScanAt || null,
    seenUrls: Array.from(
      new Set(
        (state.seenUrls || [])
          .map(value => String(value || '').trim())
          .filter(Boolean)
      )
    ).slice(-PORTAL_SEEN_URL_LIMIT)
  });

  await db.prepare(`
    INSERT INTO settings(key, value)
    VALUES(?,?)
    ON CONFLICT(key) DO UPDATE SET
      value=excluded.value,
      updated_at=CURRENT_TIMESTAMP
  `).bind(key, value).run();
}

function portalScanDue(state, now) {
  if (!state?.lastScanAt) return true;

  const last = new Date(state.lastScanAt);
  if (Number.isNaN(last.getTime())) return true;

  return (
    now.getTime() - last.getTime()
    >= PORTAL_SCAN_DAYS * 86_400_000
  );
}

async function runIndependentPortalScan(
  db,
  portal,
  env,
  now,
  stats
) {
  const state =
    await readPortalScanState(
      db,
      portal
    );

  if (!portalScanDue(state, now)) {
    return {
      skipped: true,
      discovered: 0
    };
  }

  try {
    const candidates =
      await discoverPortalNewOnly(
        portal,
        state.seenUrls
      );

    const newCandidates =
      (candidates || [])
        .filter(candidate =>
          candidate?._portal_new_discovery === true
        )
        .slice(
          0,
          PORTAL_NEW_CANDIDATE_LIMIT
        );

    /*
      Mark URLs seen only after discovery has returned.
      This prevents a failed fetch from permanently consuming
      a URL before it was actually inspected.
    */
    const discoveredUrls =
      [];

    for (const candidate of newCandidates) {
      for (const field of [
        'source_url',
        'canonical_url',
        'notification_url'
      ]) {
        const value =
          normalizePortalStateUrl(
            candidate?.[field]
          );

        if (value) {
          discoveredUrls.push(value);
        }
      }
    }

    const nextState = {
      lastScanAt: iso(now),
      seenUrls: [
        ...(state.seenUrls || []),
        ...discoveredUrls
      ]
    };

    await writePortalScanState(
      db,
      portal,
      nextState
    );

    /*
      Portal discovery is secondary only.
      It is staged first; publication requires Portal 1 + Portal 2
      agreement and a successful Google cross-check.
      Each candidate is passed to the dedicated
      Portal 1 + Portal 2 + Google verification queue.
    */
    for (const candidate of newCandidates) {
      stats.discovered++;

      await queuePortalCandidateForVerification(
        db,
        env,
        candidate,
        portal,
        now,
        stats
      );
    }

    await sourceSuccess(
      db,
      portal,
      now
    );

    return {
      skipped: false,
      discovered: newCandidates.length
    };
  } catch (error) {
    stats.errors++;

    await sourceFailure(
      db,
      portal,
      error,
      now
    );

    await recordEvent(
      db,
      {
        sourceId: portal.id,
        eventType: 'portal_scan_error',
        severity: 'warning',
        message:
          `${portal.name}: ${error?.message || error}`
      }
    );

    return {
      skipped: false,
      discovered: 0,
      error: true
    };
  }
}

function normalizePortalStateUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;

  try {
    const url = new URL(raw);
    url.hash = '';
    return url.toString();
  } catch {
    return raw;
  }
}

function portalHost(source) {
  try { return new URL(source.base_url).hostname.toLowerCase().replace(/^www\\./, ''); } catch { return ''; }
}

function urlHasTrackingSignal(value) {
  const raw = String(value || '').trim();
  if (!raw) return false;
  try {
    const url = new URL(raw);
    const params = ['utm_source','utm_medium','utm_campaign','utm_term','utm_content','fbclid','gclid','msclkid','mc_cid','mc_eid'];
    if (params.some(name => url.searchParams.has(name))) return true;
    return /(?:redirect|redir|track|tracking|click|out\\b|go\\b|url=|target=|dest=|destination=)/i.test(url.pathname + url.search);
  } catch { return /(?:redirect|redir|track|tracking|click|url=|target=|dest=)/i.test(raw); }
}

function isPortalOwnedUrl(value, source) {
  try {
    const host = new URL(String(value)).hostname.toLowerCase().replace(/^www\\./, '');
    const base = portalHost(source);
    return Boolean(base && (host === base || host.endsWith('.' + base)));
  } catch { return false; }
}

function portalUrlReview(candidate, source) {
  const problems = [];
  for (const field of ['official_url','notification_url','apply_url']) {
    const value = candidate?.[field];
    if (!value) continue;
    if (isPortalOwnedUrl(value, source)) problems.push({field, reason:'secondary_domain_url'});
    if (urlHasTrackingSignal(value)) problems.push({field, reason:'tracking_or_redirect_signal'});
  }
  return {clean: problems.length === 0, problems};
}

async function googleCrossCheck(env, candidate) {
  const apiKey = String(env?.GOOGLE_CSE_API_KEY || '').trim();
  const cx = String(env?.GOOGLE_CSE_CX || '').trim();
  if (!apiKey || !cx) return {status:'unavailable', verified:false, reason:'google_search_not_configured'};
  const queries = [
    [candidate?.organization,candidate?.title,candidate?.notification_url].filter(Boolean).join(' '),
    [candidate?.organization,candidate?.title,candidate?.last_date].filter(Boolean).join(' ')
  ].filter(Boolean);
  const results=[];
  for (const q of queries.slice(0,2)) {
    try {
      const r=await fetch('https://www.googleapis.com/customsearch/v1?key='+encodeURIComponent(apiKey)+'&cx='+encodeURIComponent(cx)+'&q='+encodeURIComponent(q),{headers:{Accept:'application/json'}});
      if(!r.ok) continue;
      const j=await r.json();
      for(const item of (j?.items||[])) results.push({title:item.title||'',link:item.link||'',snippet:item.snippet||''});
    } catch {}
  }
  if(!results.length) return {status:'not_confirmed',verified:false,reason:'google_returned_no_results'};
  const org=normalizeComparable(candidate?.organization);
  const title=normalizeComparable(candidate?.title);
  const words=title.split(/\\W+/).filter(w=>w.length>=4);
  const relevant=results.filter(item=>{
    const hay=normalizeComparable((item.title||'')+' '+(item.link||'')+' '+(item.snippet||''));
    const orgMatch=!org || hay.includes(org);
    const matches=words.filter(w=>hay.includes(w)).length;
    return orgMatch && matches>=Math.max(2,Math.ceil(words.length*0.35));
  });
  return {status:relevant.length?'confirmed':'not_confirmed',verified:relevant.length>0,results:relevant.slice(0,5)};
}
function googleUrlCoverage(candidate, google) {
  const results = google?.results || [];
  const hosts = results.map(r => {
    try { return new URL(r.link).hostname.toLowerCase().replace(/^www\\./, ''); }
    catch { return ''; }
  }).filter(Boolean);

  const problems = [];
  for (const field of ['official_url','notification_url','apply_url']) {
    const value = String(candidate?.[field] || '').trim();
    if (!value) {
      problems.push({ field, reason: 'missing' });
      continue;
    }
    try {
      const u = new URL(value);
      const host = u.hostname.toLowerCase().replace(/^www\\./, '');
      const matched = hosts.some(h => h === host || h.endsWith('.' + host) || host.endsWith('.' + h));
      if (!matched) problems.push({ field, reason: 'url_domain_not_confirmed_by_google', host });
    } catch {
      problems.push({ field, reason: 'invalid_url' });
    }
  }
  return { clean: problems.length === 0, problems };
}

/*
  Portal candidates enter a verification_required record.
  No portal candidate can become published merely because
  a portal found it.
*/
function portalSecondaryIdentity(candidate) {
  const ad = candidate?.advertisement_number || candidate?.notification_number || candidate?.advt_no || candidate?.notification_key || '';
  const title = normalizeComparable(candidate?.title);
  const org = normalizeComparable(candidate?.organization);
  return ad ? org + '|' + normalizeComparable(ad) : org + '|' + title;
}

async function readPortalEvidence(db, identity) {
  const key = 'portal_evidence:' + identity;
  const row = await db.prepare('SELECT value FROM settings WHERE key=? LIMIT 1').bind(key).first();
  if (!row?.value) return {};
  try { const value = JSON.parse(row.value); return value && typeof value === 'object' ? value : {}; } catch { return {}; }
}

async function writePortalEvidence(db, identity, value) {
  const key = 'portal_evidence:' + identity;
  await db.prepare(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`).bind(key, safeJson(value)).run();
}

function portalImportantFields() {
  return ['title','organization','vacancies','qualification','eligibility','age_limit','fee','application_start','last_date','exam_date','selection_process','salary'];
}

function comparePortalCandidates(a, b) {
  const matches = []; const mismatches = [];
  for (const field of portalImportantFields()) {
    const av = normalizeComparable(a?.[field]); const bv = normalizeComparable(b?.[field]);
    if (!av || !bv) continue;
    if (av === bv) matches.push(field);
    else mismatches.push({field, portal1:a?.[field] ?? null, portal2:b?.[field] ?? null});
  }
  const identityMatch = titleSimilarity(a?.title,b?.title) && (!a?.organization || !b?.organization || titleSimilarity(a?.organization,b?.organization));
  return {identityMatch,matches,mismatches,agreement:identityMatch && mismatches.length===0 && matches.length>=1};
}

function portalCandidateForPublicData(candidate) {
  const c = {...(candidate || {})};
  c.description = null; c.how_to_apply = null; c.important_dates = null;
  return c;
}

function portalGoogleFieldCoverage(candidate, google) {
  const results = google?.results || [];
  const haystack = results.map(r => normalizeComparable((r.title||'')+' '+(r.snippet||'')+' '+(r.link||''))).join(' ');
  const fields=['vacancies','qualification','age_limit','fee','application_start','last_date','exam_date','salary'];
  const checked=[]; let confirmed=0;
  for (const field of fields) {
    const value=normalizeComparable(candidate?.[field]); if(!value) continue; checked.push(field);
    const tokens=value.split(/[^a-z0-9]+/i).filter(Boolean).filter(t=>t.length>=3);
    if(!tokens.length) continue;
    const hits=tokens.filter(t=>haystack.includes(t)).length;
    if(hits>=Math.max(1,Math.ceil(tokens.length*0.5))) confirmed++;
  }
  return {checked,confirmed,sufficient:checked.length===0 || confirmed>=Math.max(1,Math.ceil(checked.length*0.5))};
}

async function publishPortalVerifiedCandidate(db,candidate,portalEvidence,google,now,stats) {
  const key=candidateKey(candidate); if(!key) return {published:false,reason:'missing_identity'};
  const existing=await findExistingItem(db,candidate,key);
  if(existing) {
    await recordEvent(db,{itemId:existing.id,sourceId:portalEvidence?.source_id||null,eventType:'portal_google_verified_existing_item',severity:'info',message:'Portal/Google cross-check matched existing item: '+candidate.title,evidence:{verification_stage:'portal_google',google,portals:portalEvidence?.portals||[]}});
    return {published:existing.status==='published',existing:true,id:existing.id};
  }
  const clean=portalCandidateForPublicData(candidate);
  const hash=await sha256Hex(JSON.stringify({key,title:clean.title,organization:clean.organization,vacancies:clean.vacancies,qualification:clean.qualification,last_date:clean.last_date,application_start:clean.application_start,exam_date:clean.exam_date,fee:clean.fee,official_url:clean.official_url,notification_url:clean.notification_url,apply_url:clean.apply_url}));
  const fields={notification_key:key,type:clean.type||'job',title:clean.title||null,organization:clean.organization||null,category:clean.category||'job',location:clean.location||null,description:null,eligibility:clean.eligibility||null,qualification:clean.qualification||null,vacancies:clean.vacancies||null,age_limit:clean.age_limit||null,age_relaxation:clean.age_relaxation||null,fee:clean.fee||null,selection_process:clean.selection_process||null,salary:clean.salary||null,application_start:clean.application_start||null,last_date:clean.last_date||null,exam_date:clean.exam_date||null,how_to_apply:null,important_dates:null,official_url:clean.official_url||null,apply_url:clean.apply_url||null,notification_url:clean.notification_url||null,source_url:clean.source_url||null,source_name:'Secondary Cross-check',source_id:null,source_hash:hash,canonical_url:clean.canonical_url||clean.source_url||null,status:'published',verification_status:'google_verified',confidence_score:90,evidence_json:safeJson({authority:'secondary_crosscheck',verification_stage:'portal1_portal2_google',publishable_from_portal:true,portals:portalEvidence?.portals||[],portal_comparison:portalEvidence?.comparison||null,google_verification:google}),last_verified_at:iso(now),last_seen_at:iso(now),published_at:iso(now)};
  const slug=slugify(clean.title||'job')+'-'+hash.slice(0,8);
  const columns=Object.keys(fields); const placeholders=columns.map(()=>'?').join(',');
  const result=await db.prepare(`INSERT INTO items(slug,${columns.join(',')},created_at,updated_at) VALUES(?,${placeholders},CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`).bind(slug,...Object.values(fields)).run();
  const id=result.meta?.last_row_id||null; stats.published++;
  await recordEvent(db,{itemId:id,sourceId:portalEvidence?.source_id||null,eventType:'portal_google_published',severity:'info',message:'Published after Portal 1 + Portal 2 + Google cross-check: '+clean.title,evidence:{portal_comparison:portalEvidence?.comparison||null,google}});
  return {published:true,id};
}

async function queuePortalCandidateForVerification(db,env,candidate,portal,now,stats) {
  const key=candidateKey(candidate); if(!key){stats.verificationRequired++;return;}
  const urlReview=portalUrlReview(candidate,portal);
  const identity=await sha256Hex(portalSecondaryIdentity(candidate));
  const state=await readPortalEvidence(db,identity);
  if (state.updated_at) {
    const age = Date.now() - new Date(state.updated_at).getTime();
    if (!Number.isFinite(age) || age > PORTAL_EVIDENCE_TTL_DAYS * 86_400_000) {
      for (const k of Object.keys(state)) {
        if (/^\\d+$/.test(k)) delete state[k];
      }
    }
  }
  state.version=2; state.first_seen_at=state.first_seen_at||iso(now); state.updated_at=iso(now);
  state[portal.id]={portal_id:portal.id,portal_name:portal.name,candidate:portalCandidateForPublicData(candidate),seen_at:iso(now)};
  await writePortalEvidence(db,identity,state);
  const entries=Object.keys(state).filter(k=>/^\d+$/.test(k)).map(id=>state[id]).filter(Boolean);
  const portal1=entries.find(e=>/Sarkari Result/i.test(e.portal_name));
  const portal2=entries.find(e=>/FreeJobAlert/i.test(e.portal_name));
  if(!portal1 || !portal2){await recordEvent(db,{sourceId:portal.id,eventType:'portal_evidence_pending',severity:'info',message:'Waiting for both Portal 1 and Portal 2: '+candidate.title,evidence:{identity,portal_id:portal.id}});return;}
  const comparison=comparePortalCandidates(portal1.candidate,portal2.candidate);
  if(!comparison.agreement){stats.verificationRequired++;await notify(db,'portal_verification','Admin verification required: Portal 1/2 mismatch',candidate.title+': Portal 1 and Portal 2 contain conflicting or insufficient factual data.',null);await recordEvent(db,{sourceId:portal.id,eventType:'portal_comparison_mismatch',severity:'warning',message:'Portal 1/2 mismatch: '+candidate.title,evidence:{comparison}});return;}
  const merged={...portal1.candidate};
  for(const field of portalImportantFields()){merged[field]=portal1.candidate?.[field]||portal2.candidate?.[field]||null;}
  merged.official_url=portal1.candidate?.official_url||portal2.candidate?.official_url||null;
  merged.notification_url=portal1.candidate?.notification_url||portal2.candidate?.notification_url||null;
  merged.apply_url=portal1.candidate?.apply_url||portal2.candidate?.apply_url||null;
  const finalUrlProblems=[];
  for(const field of ['official_url','notification_url','apply_url']){const value=merged[field];if(!value)finalUrlProblems.push({field,reason:'missing'});else if(isPortalOwnedUrl(value,portal))finalUrlProblems.push({field,reason:'secondary_domain_url'});else if(urlHasTrackingSignal(value))finalUrlProblems.push({field,reason:'tracking_or_redirect_signal'});}
  if(finalUrlProblems.length){stats.verificationRequired++;await notify(db,'portal_url_review','Admin verification required: URL problem',candidate.title+': final URL validation failed.',null);await recordEvent(db,{sourceId:portal.id,eventType:'portal_url_validation_failed',severity:'warning',message:'Portal URL validation failed: '+candidate.title,evidence:{problems:finalUrlProblems}});return;}
  const google=await googleCrossCheck(env,merged);
  const coverage=portalGoogleFieldCoverage(merged,google);
  const googleUrls=googleUrlCoverage(merged,google);
  if(google.status!=='confirmed'||google.verified!==true||!coverage.sufficient||!googleUrls.clean){
    stats.verificationRequired++;
    await notify(db,'portal_verification','Admin verification required: Google cross-check failed',candidate.title+': Google cross-check/data/URL confirmation did not pass; automatic publishing is blocked.',null);
    await recordEvent(db,{sourceId:portal.id,eventType:'google_crosscheck_failed',severity:'warning',message:'Google cross-check failed: '+candidate.title,evidence:{google,coverage,google_urls:googleUrls,comparison}});
    return;
  }
  await publishPortalVerifiedCandidate(db,merged,{source_id:portal.id,portals:[portal1.portal_name,portal2.portal_name],comparison},{...google,field_coverage:coverage,url_coverage:googleUrls},now,stats);
}
/* -------------------------------------------------------------------------- */
/* Portal source selection                                                    */
/* -------------------------------------------------------------------------- */

async function getPortalSources(
  db,
  official
) {
  /*
    FIXED SECONDARY PORTALS
    -----------------------
    Portal 1 = Sarkari Result
    Portal 2 = FreeJobAlert

    These are secondary discovery/evidence sources only.
    Branch B does not call the official-source verification branch.
    Google is the third cross-check. Any unresolved issue goes to Admin.
  */
  const result =
    await db
      .prepare(`
        SELECT *
        FROM sources
        WHERE
          enabled=1
          AND role='portal'
          AND name IN (
            'Sarkari Result (Portal 1)',
            'FreeJobAlert (Portal 2)'
          )
        ORDER BY
          CASE name
            WHEN 'Sarkari Result (Portal 1)' THEN 1
            WHEN 'FreeJobAlert (Portal 2)' THEN 2
            ELSE 99
          END ASC
        LIMIT ?
      `)
      .bind(PORTAL_LIMIT)
      .all();

  return (
    result.results || []
  );
}

/* -------------------------------------------------------------------------- */
/* Fixed portal configuration                                                 */
/* -------------------------------------------------------------------------- */

async function ensureFixedPortalSources(db) {
  /*
    Make the two secondary sources deterministic on every monitor run.
    This also repairs the old placeholder Portal 1/Portal 2 rows without
    requiring a manual D1 edit.
  */
  await db.prepare(`
    INSERT INTO sources(
      name,
      role,
      fallback_key,
      base_url,
      allowed_domains,
      adapter,
      enabled,
      priority
    )
    VALUES(
      'Sarkari Result (Portal 1)',
      'portal',
      '*',
      'https://www.sarkariresult.com/',
      'sarkariresult.com',
      'generic',
      1,
      90
    )
    ON CONFLICT(name) DO UPDATE SET
      role='portal',
      fallback_key='*',
      base_url=excluded.base_url,
      allowed_domains=excluded.allowed_domains,
      adapter='generic',
      enabled=1,
      priority=90,
      updated_at=CURRENT_TIMESTAMP
  `).run();

  await db.prepare(`
    INSERT INTO sources(
      name,
      role,
      fallback_key,
      base_url,
      allowed_domains,
      adapter,
      enabled,
      priority
    )
    VALUES(
      'FreeJobAlert (Portal 2)',
      'portal',
      '*',
      'https://www.freejobalert.com/',
      'freejobalert.com',
      'generic',
      0,
      91
    )
    ON CONFLICT(name) DO UPDATE SET
      role='portal',
      fallback_key='*',
      base_url=excluded.base_url,
      allowed_domains=excluded.allowed_domains,
      adapter='generic',
      enabled=0,
      priority=91,
      updated_at=CURRENT_TIMESTAMP
  `).run();

  /*
    No third portal may silently enter the RT fallback chain.
  */
  await db.prepare(`
    UPDATE sources
    SET
      enabled=0,
      updated_at=CURRENT_TIMESTAMP
    WHERE
      role='portal'
      AND name NOT IN (
        'Sarkari Result (Portal 1)',
        'FreeJobAlert (Portal 2)'
      )
  `).run();
}


/* -------------------------------------------------------------------------- */
/* Candidate safety normalization                                             */
/* -------------------------------------------------------------------------- */

function monitorDateKey(value) {
  const s = String(value || '').trim();
  if (!s) return null;
  let m = s.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](\d{4})$/);
  if (m) {
    const d=Number(m[1]), mo=Number(m[2]), y=Number(m[3]);
    if (mo>=1 && mo<=12 && d>=1 && d<=31) return `${y}-${String(mo).padStart(2,'0')}-${String(d).padStart(2,'0')}`;
  }
  m = s.match(/^(\d{4})[\/-](\d{1,2})[\/-](\d{1,2})$/);
  if (m) return `${m[1]}-${String(m[2]).padStart(2,'0')}-${String(m[3]).padStart(2,'0')}`;
  m = s.match(/^(\d{1,2})\s+([A-Za-z]{3,9})\s+(\d{4})$/);
  if (m) {
    const months={jan:1,feb:2,mar:3,apr:4,may:5,jun:6,jul:7,aug:8,sep:9,oct:10,nov:11,dec:12};
    const mo=months[m[2].slice(0,3).toLowerCase()];
    if (mo) return `${m[3]}-${String(mo).padStart(2,'0')}-${String(Number(m[1])).padStart(2,'0')}`;
  }
  return null;
}
function sameMonitorUrl(a,b) {
  if(!a||!b) return false;
  try{return normalizeUrl(a)===normalizeUrl(b);}catch{return String(a).trim().replace(/\/$/,'')===String(b).trim().replace(/\/$/,'');}
}
function isRejectedApplyUrl(url, candidate = {}) {
  const value = String(url || '');
  if (!value) return false;
  return (
    isPdfUrl(value) ||
    sameMonitorUrl(value, candidate.official_url) ||
    sameMonitorUrl(value, candidate.canonical_url) ||
    sameMonitorUrl(value, candidate.source_url) ||
    /(?:exam_files\.php\?click=yes|notifications?\.aspx|recruitment\.php|advertisement\.php|index\.php(?:\?|$))/i.test(value)
  );
}

function sanitizeMonitorCandidate(candidate) {
  const c={...(candidate||{})};
  if(c.type!=='job'&&c.type!=='recruitment') return c;

  const sanitizedFields = [];

  const start=monitorDateKey(c.application_start);
  const last=monitorDateKey(c.last_date);
  const exam=monitorDateKey(c.exam_date);

  if(start&&last&&exam&&start===last&&last===exam){
    c.application_start=null;
    c.last_date=null;
    c.exam_date=null;
    sanitizedFields.push('application_start','last_date','exam_date');
  } else {
    if(start&&last&&last<start){
      c.last_date=null;
      sanitizedFields.push('last_date');
    }
    if(start&&exam&&exam<start){
      c.exam_date=null;
      sanitizedFields.push('exam_date');
    }
  }

  const apply=String(c.apply_url||'');
  if(apply&&isRejectedApplyUrl(apply,c)){
    c.apply_url=null;
    sanitizedFields.push('apply_url');
  }

  if(c.notification_url&&sameMonitorUrl(c.notification_url,c.apply_url)){
    c.notification_url=null;
    sanitizedFields.push('notification_url');
  }

  if(sanitizedFields.length){
    c._sanitized_fields = [...new Set(sanitizedFields)];
    c._requires_admin_review = true;
  }

  return c;
}

/* -------------------------------------------------------------------------- */
/* Official source processing                                                 */
/* -------------------------------------------------------------------------- */

async function runOfficial(
  db,
  source,
  now,
  stats
) {
  const current =
    await resetRetryIfNewDay(
      db,
      source,
      now
    );

  if (
    current.circuit_until &&
    new Date(
      current.circuit_until
    ) > now
  ) {
    return;
  }

  if (
    current.next_retry_at &&
    new Date(
      current.next_retry_at
    ) > now
  ) {
    return;
  }

  if (
    Number(
      current.retry_count || 0
    ) >= RETRY_LIMIT
  ) {
    return;
  }

  try {
    const candidates =
      await discoverFromSource(
        current
      );

    const limited =
      (candidates || [])
        .slice(
          0,
          CANDIDATE_LIMIT
        );

    /*
      Successful fetch means the source itself
      is reachable. Reset its retry counter.
    */
    await sourceSuccess(
      db,
      current,
      now
    );

    for (
      let candidate of limited
    ) {
      candidate = sanitizeMonitorCandidate(candidate);
      stats.discovered++;

      let verification;

      try {
        verification =
          await verifyCandidate(
            candidate,
            current
          );
      } catch (error) {
        stats.errors++;

        await recordEvent(
          db,
          {
            sourceId:
              current.id,

            eventType:
              'candidate_verification_error',

            severity:
              'error',

            message:
              `Candidate verification failed: ${
                error?.message || error
              }`,

            evidence: {
              title:
                candidate?.title ||
                null
            }
          }
        );

        continue;
      }

      /*
        Existing record before update.
      */
      const existing =
        await findExistingItem(
          db,
          candidate,
          candidateKey(
            candidate
          )
        );

      /*
        JOB/RECRUITMENT URL GATE
        ------------------------
        If an official recruitment candidate
        is missing notification/apply URL,
        do NOT publish it yet.

        Immediately ask Portal 1 + Portal 2
        to recover the missing information.
      */
      const isRecruitment =
        candidate.type === 'job' ||
        candidate.type === 'recruitment';

      if (
        isRecruitment &&
        !hasCompleteRecruitmentUrls(
          candidate
        )
      ) {
        stats.verificationRequired++;

        /*
          IMPORTANT: keep the official discovery as a real
          verification_required item before fallback. Previously an
          incomplete official recruitment was only sent to the portal
          fallback, so with no configured portals it disappeared
          completely and produced no admin-review record.
        */
        const incompleteResult =
          await upsertOfficial(
            db,
            candidate,
            verification,
            current,
            now
          );

        if (
          incompleteResult.created ||
          incompleteResult.changed
        ) {
          await notify(
            db,
            'verification_required',
            'Admin verification required',
            candidate.title + ': official recruitment discovered but one or more required URLs are missing (' +
              missingRecruitmentUrls(candidate).join(', ') + ').',
            incompleteResult.id
          );
        }

        /*
          Branches are independent.
          Official-source candidates do NOT enter Portal 1/2.
          Incomplete official candidates remain Admin verification.
        */
        continue;
      }

      /*
        Complete recruitment but verification
        failed -> verification_required.
      */
      if (
        !verification ||
        verification.ok !== true ||
        Number(
          verification.confidence || 0
        ) < 85
      ) {
        stats.verificationRequired++;

        const result =
          await upsertOfficial(
            db,
            candidate,
            verification,
            current,
            now
          );

        if (
          result.created ||
          result.changed
        ) {
          await notify(
            db,
            'verification_required',
            'Admin verification required',
            `${candidate.title}: official verification did not reach the automatic publish threshold.`,
            result.id
          );
        }

        await recordEvent(
          db,
          {
            itemId:
              result.id,

            sourceId:
              current.id,

            eventType:
              'verification_required',

            severity:
              'warning',

            message:
              `Automatic verification incomplete: ${candidate.title}`,

            evidence: {
              errors:
                verification?.errors ||
                [],

              warnings:
                verification?.warnings ||
                [],

              confidence:
                verification?.confidence ||
                0
            }
          }
        );

        continue;
      }

      /*
        Fully verified official candidate.
      */
      const result =
        await upsertOfficial(
          db,
          candidate,
          verification,
          current,
          now
        );

      if (
        result.published
      ) {
        stats.published++;
      }

      if (
        result.updated
      ) {
        stats.updated++;
      }
    }

  } catch (error) {
    stats.errors++;

    const failure =
      await sourceFailure(
        db,
        current,
        error,
        now
      );

    await recordEvent(
      db,
      {
        sourceId:
          current.id,

        eventType:
          'source_error',

        severity:
          'error',

        message:
          `${failure.kind}: ${
            error?.message || error
          }`,

        evidence: {
          retry_count:
            failure.count,

          next_retry_at:
            failure.next,

          circuit_until:
            failure.circuit
        }
      }
    );

    /*
      Official-source failure stays inside Branch A.
      Branch B has its own independent daily scan and
      must never be invoked as an official-source fallback.
    */
  }
}


/* -------------------------------------------------------------------------- */
/* Main monitor                                                               */
/* -------------------------------------------------------------------------- */

export async function runMonitor(
  env,
  requestedSource = null,
  options = {}
) {
  const db =
    env.DB;

  /*
    Lock the secondary-source configuration before any fallback
    decision is made. This keeps Portal 1/2 deterministic across
    deployments and existing D1 databases.
  */
  await ensureFixedPortalSources(db);

  const started =
    new Date();

  const stats = {
    sources: 0,
    discovered: 0,
    published: 0,
    updated: 0,
    verificationRequired: 0,
    blocked: 0,
    errors: 0,
    archived: 0,
    details: []
  };

  /* Retention cleanup runs only during the daily maintenance Cron. */
  if (options?.maintenance === true) {
    stats.archived =
      await purgeExpiredItems(
        db,
        started
      );
  }


  /*
    Independent daily Portal 1/Portal 2 discovery.
    This branch is deliberately separate from the official-source
    rotation. It never publishes directly.
  */
  if (
    !requestedSource &&
    options?.skipPortals !== true
  ) {
    const portals =
      await getPortalSources(db, null);

    for (const portal of portals) {
      stats.sources++;
      await runIndependentPortalScan(
        db,
        portal,
        env,
        new Date(),
        stats
      );
    }
  }

  let sources;

  /*
    Manual source request.
  */
  if (
    requestedSource
  ) {
    const result =
      await db
        .prepare(`
          SELECT *
          FROM sources
          WHERE
            enabled=1
            AND (
              name=?
              OR adapter=?
            )
          LIMIT 1
        `)
        .bind(
          requestedSource,
          requestedSource
        )
        .all();

    sources =
      result.results || [];

  } else {
    /*
      Fair source rotation.
    */
    const result =
      await db
        .prepare(`
          SELECT *
          FROM sources
          WHERE
            enabled=1
            AND role='official'
            AND (
              next_retry_at IS NULL
              OR next_retry_at<=?
            )
          /*
            Fair rotation: oldest checked source first.
            Priority is only the tie-breaker; otherwise a
            high-priority source can monopolize every Cron run.
          */
          ORDER BY
            COALESCE(
              last_checked_at,
              '1970-01-01'
            ) ASC,
            priority ASC,
            id ASC
          LIMIT ?
        `)
        .bind(
          iso(started),
          SOURCE_BATCH
        )
        .all();

    sources =
      result.results || [];
  }

  for (
    const source of sources
  ) {
    stats.sources++;

    const beforeErrors =
      stats.errors;

    try {
      await runOfficial(
        db,
        source,
        new Date(),
        stats
      );

    } catch (error) {
      stats.errors++;

      await recordEvent(
        db,
        {
          sourceId:
            source.id,

          eventType:
            'monitor_source_unhandled_error',

          severity:
            'error',

          message:
            String(
              error?.message ||
              error
            )
        }
      );
    }

    stats.details.push({
      source:
        source.name,

      error:
        stats.errors >
        beforeErrors
    });
  }

  const finished =
    new Date();

  /*
    Save run summary.
  */
  await db
    .prepare(`
      INSERT INTO monitor_runs(
        started_at,
        finished_at,
        source_count,
        discovered,
        published,
        updated,
        verification_required,
        blocked,
        errors,
        archived,
        details
      )
      VALUES(?,?,?,?,?,?,?,?,?,?,?)
    `)
    .bind(
      iso(started),
      iso(finished),
      stats.sources,
      stats.discovered,
      stats.published,
      stats.updated,
      stats.verificationRequired,
      stats.blocked,
      stats.errors,
      stats.archived,
      safeJson(
        stats.details
      )
    )
    .run();

  return {
    started:
      iso(started),

    finished:
      iso(finished),

    ...stats
  };
      }