/*
  North Bharat Jobs
  Official-source monitoring engine

  FLOW
  ----
  1. Scan official sources.
  2. Verify official candidates.
  3. Publish only when official evidence is complete.
  4. If notification/apply URL is missing:
       Official -> Portal 1 -> Portal 2
  5. Portal information is secondary evidence only.
  6. Portal data NEVER becomes automatically verified/published.
  7. If official confirmation is still missing:
       verification_required + admin notification.
  8. Existing recruitment is updated in-place.
  9. No duplicate for a revised notification.
  10. Real revisions only are stored.
  11. Temporary official-source failure must NOT destroy
      an already published record.
  12. Records older than 365 days are deleted in bounded batches.
*/

import {
  discoverFromSource,
  discoverPortal
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

  /* Daily bounded cleanup: one batch only, avoiding an unbounded CPU loop. */
  const result = await db
    .prepare(`DELETE FROM items
      WHERE id IN (
        SELECT id FROM items
        WHERE COALESCE(published_at, created_at) < ?
        LIMIT ?
      )\`)
    .bind(cutoff, RETENTION_DELETE_BATCH)
    .run();

  return Number(result.meta?.changes || 0);
}


/* -------------------------------------------------------------------------- */
/* Existing item lookup                                                       */
/* -------------------------------------------------------------------------- */

(
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

  const status =
    verified
      ? 'published'
      : existingPublished
        ? 'published'
        : 'verification_required';

  const verificationStatus =
    verified
      ? 'verified'
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
      existing?.apply_url ||
      null,

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

        missing_urls:
          missingRecruitmentUrls(
            candidate
          )
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
/* Portal source selection                                                    */
/* -------------------------------------------------------------------------- */

async function getPortalSources(
  db,
  official
) {
  const result =
    await db
      .prepare(`
        SELECT *
        FROM sources
        WHERE
          enabled=1
          AND role='portal'
          AND (
            fallback_key=?
            OR fallback_key='*'
          )
        ORDER BY
          priority ASC,
          id ASC
        LIMIT ?
      `)
      .bind(
        official?.fallback_key || '*',
        PORTAL_LIMIT
      )
      .all();

  return (
    result.results || []
  );
}


/* -------------------------------------------------------------------------- */
/* Portal fallback for one missing-URL candidate                              */
/* -------------------------------------------------------------------------- */

async function portalFallbackForCandidate(
  db,
  officialSource,
  officialCandidate,
  officialVerification,
  existing,
  now,
  stats
) {
  const missing =
    missingRecruitmentUrls(
      officialCandidate
    );

  if (!missing.length) {
    return false;
  }

  const portals =
    await getPortalSources(
      db,
      officialSource
    );

  /*
    No two configured portals:
    Admin must be told.
  */
  if (
    portals.length < 2
  ) {
    await notify(
      db,
      'missing_url',
      'Admin action required: fallback portals not configured',
      `${officialCandidate.title}: missing ${missing.join(', ')}. Enable and configure Portal 1 and Portal 2.`,
      existing?.id || null
    );

    await recordEvent(
      db,
      {
        itemId:
          existing?.id || null,

        sourceId:
          officialSource.id,

        eventType:
          'fallback_not_configured',

        severity:
          'warning',

        message:
          `Missing ${missing.join(', ')} and two portal sources are not enabled.`,

        evidence: {
          missing,
          portals_found:
            portals.length
        }
      }
    );

    return false;
  }

  const portalResults = [];

  /*
    Ask BOTH portals.
  */
  for (
    const portal of portals
  ) {
    try {
      const candidates =
        await discoverPortal(
          portal
        );

      const matches =
        (candidates || [])
          .filter(candidate =>
            sameRecruitment(
              officialCandidate,
              candidate
            )
          )
          .slice(
            0,
            CANDIDATE_LIMIT
          );

      portalResults.push({
        portal,
        matches
      });

    } catch (error) {
      stats.errors++;

      await recordEvent(
        db,
        {
          sourceId:
            portal.id,

          eventType:
            'portal_error',

          severity:
            'warning',

          message:
            `${portal.name}: ${
              error?.message || error
            }`
        }
      );
    }
  }

  const first =
    portalResults[0];

  const second =
    portalResults[1];

  const firstCandidate =
    first?.matches?.[0] ||
    null;

  const secondCandidate =
    second?.matches?.[0] ||
    null;

  /*
    Both portals must independently find
    the same recruitment before portal
    information is considered a strong
    secondary cross-check.
  */
  if (
    !firstCandidate ||
    !secondCandidate
  ) {
    await notify(
      db,
      'missing_url',
      'Admin action required: recruitment URL missing',
      `${officialCandidate.title}: missing ${missing.join(', ')}. Portal 1/2 could not both confirm the missing information.`,
      existing?.id || null
    );

    await recordEvent(
      db,
      {
        itemId:
          existing?.id || null,

        sourceId:
          officialSource.id,

        eventType:
          'portal_fallback_incomplete',

        severity:
          'warning',

        message:
          `Portal fallback could not completely recover: ${missing.join(', ')}`,

        evidence: {
          missing,
          portal1_found:
            Boolean(firstCandidate),
          portal2_found:
            Boolean(secondCandidate)
        }
      }
    );

    return false;
  }

  /*
    Compare the two portals.
  */
  const portalAgreement =
    comparable(
      firstCandidate
    ) ===
    comparable(
      secondCandidate
    );

  /*
    Extract only missing values.
    Existing official values are never replaced
    by null.
  */
  const recovered = {};

  for (
    const field of [
      'notification_url',
      'apply_url',
      'last_date',
      'application_start',
      'exam_date',
      'vacancies',
      'qualification',
      'eligibility',
      'fee',
      'selection_process',
      'salary'
    ]
  ) {
    const officialValue =
      officialCandidate[field];

    if (
      hasUsableUrl(
        officialValue
      ) ||
      (
        existing &&
        hasUsableUrl(
          existing[field]
        )
      )
    ) {
      continue;
    }

    const firstValue =
      firstCandidate[field];

    const secondValue =
      secondCandidate[field];

    if (
      hasUsableUrl(
        firstValue
      ) &&
      hasUsableUrl(
        secondValue
      ) &&
      normalizeComparable(
        firstValue
      ) ===
      normalizeComparable(
        secondValue
      )
    ) {
      recovered[field] =
        firstValue;
    }
  }

  /*
    Portal data can help prepare a candidate,
    but official verification remains required.
  */
  const recoveredCandidate = {
    ...officialCandidate,
    ...recovered
  };

  const recoveredMissing =
    missingRecruitmentUrls(
      recoveredCandidate
    );

  const evidence = {
    authority:
      'secondary_only',

    official_source:
      officialSource.name,

    portals: [
      first.portal.name,
      second.portal.name
    ],

    portal_agreement:
      portalAgreement,

    recovered,

    still_missing:
      recoveredMissing
  };

  /*
    We NEVER mark this as verified merely
    because two portals agree.
  */
  const target =
    existing ||
    await findExistingItem(
      db,
      officialCandidate,
      candidateKey(
        officialCandidate
      )
    );

  if (target) {
    /*
      Only fill fields that are currently
      missing. Never overwrite an official
      value with portal data.
    */
    const updates = [];

    const values = [];

    for (
      const [field, value]
      of Object.entries(recovered)
    ) {
      if (
        !hasUsableUrl(value)
      ) {
        continue;
      }

      if (
        hasUsableUrl(
          target[field]
        )
      ) {
        continue;
      }

      updates.push(
        `${field}=?`
      );

      values.push(value);
    }

    /*
      Evidence status.
    */
    updates.push(
      `evidence_json=?`
    );

    values.push(
      safeJson(evidence)
    );

    updates.push(
      `last_seen_at=?`
    );

    values.push(
      iso(now)
    );

    /*
      Portal recovery NEVER changes a
      published record to verification_required.
      Existing published data remains public.
    */
    if (
      target.status !==
      'published'
    ) {
      updates.push(
        `status=?`
      );

      values.push(
        'verification_required'
      );

      updates.push(
        `verification_status=?`
      );

      values.push(
        'secondary_crosscheck'
      );

      updates.push(
        `confidence_score=?`
      );

      values.push(
        portalAgreement
          ? 65
          : 50
      );
    }

    values.push(
      target.id
    );

    await db
      .prepare(`
        UPDATE items
        SET
          ${updates.join(',')},
          updated_at=CURRENT_TIMESTAMP
        WHERE id=?
      `)
      .bind(
        ...values
      )
      .run();

  } else {
    /*
      No official item exists yet.
      Create only a verification_required
      secondary record.
    */
    const key =
      candidateKey(
        officialCandidate
      );

    if (key) {
      const slug =
        `${slugify(
          officialCandidate.title
        )}-${(
          await sha256Hex(key)
        ).slice(0, 8)}`;

      await db
        .prepare(`
          INSERT OR IGNORE INTO items(
            slug,
            notification_key,
            type,
            title,
            organization,
            category,
            location,
            description,
            qualification,
            vacancies,
            age_limit,
            fee,
            selection_process,
            salary,
            application_start,
            last_date,
            exam_date,
            official_url,
            apply_url,
            notification_url,
            source_url,
            source_name,
            source_id,
            canonical_url,
            status,
            verification_status,
            confidence_score,
            evidence_json,
            last_seen_at
          )
          VALUES(
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
          )
        `)
        .bind(
          slug,
          key,
          officialCandidate.type || 'job',
          officialCandidate.title,
          officialCandidate.organization || null,
          officialCandidate.category || null,
          officialCandidate.location || null,
          officialCandidate.description || null,
          recoveredCandidate.qualification || null,
          recoveredCandidate.vacancies || null,
          recoveredCandidate.age_limit || null,
          recoveredCandidate.fee || null,
          recoveredCandidate.selection_process || null,
          recoveredCandidate.salary || null,
          recoveredCandidate.application_start || null,
          recoveredCandidate.last_date || null,
          recoveredCandidate.exam_date || null,
          officialCandidate.official_url || null,
          recoveredCandidate.apply_url || null,
          recoveredCandidate.notification_url || null,
          officialCandidate.source_url,
          officialSource.name,
          officialSource.id,
          officialCandidate.canonical_url ||
            officialCandidate.source_url,
          'verification_required',
          'secondary_crosscheck',
          portalAgreement
            ? 65
            : 50,
          safeJson(evidence),
          iso(now)
        )
        .run();
    }
  }

  /*
    If both portals recovered the missing URL,
    Admin still receives a task because official
    confirmation is required.
  */
  await notify(
    db,
    'secondary_crosscheck',
    'Admin verification required',
    `${officialCandidate.title}: Portal 1/2 recovered ${Object.keys(recovered).join(', ') || 'information'}, but official confirmation is still required.`,
    target?.id || null
  );

  await recordEvent(
    db,
    {
      itemId:
        target?.id || null,

      sourceId:
        officialSource.id,

      eventType:
        'portal_fallback_recovered',

      severity:
        'warning',

      message:
        `Portal fallback recovered information for: ${officialCandidate.title}`,

      evidence
    }
  );

  return true;
}


/* -------------------------------------------------------------------------- */
/* Portal fallback after official source is unavailable                       */
/* -------------------------------------------------------------------------- */

async function runPortalsForFallback(
  db,
  official,
  now,
  stats
) {
  /*
    If official source is completely unavailable,
    find existing recent items belonging to this
    official source and try to recover them.
  */
  const rows =
    await db
      .prepare(`
        SELECT *
        FROM items
        WHERE
          source_id=?
          AND status IN(
            'published',
            'verification_required'
          )
        ORDER BY
          updated_at DESC
        LIMIT ?
      `)
      .bind(
        official.id,
        CANDIDATE_LIMIT
      )
      .all();

  const items =
    rows.results || [];

  /*
    If there is no existing item, we cannot safely
    invent a recruitment identity from portals.
  */
  if (!items.length) {
    await notify(
      db,
      'source_unavailable',
      'Admin action required: official source unavailable',
      `${official.name} reached its daily retry limit and there are no existing recruitment records available for portal cross-check.`
    );

    return;
  }

  const portals =
    await getPortalSources(
      db,
      official
    );

  if (
    portals.length < 2
  ) {
    await notify(
      db,
      'configuration',
      'Portal fallback not configured',
      `${official.name} reached its daily retry limit. Two enabled portal sources are required.`
    );

    return;
  }

  /*
    Query both portals once.
  */
  const portalResults = [];

  for (
    const portal of portals
  ) {
    try {
      const candidates =
        await discoverPortal(
          portal
        );

      portalResults.push({
        portal,
        candidates:
          candidates || []
      });

    } catch (error) {
      stats.errors++;

      await recordEvent(
        db,
        {
          sourceId:
            portal.id,

          eventType:
            'portal_error',

          severity:
            'warning',

          message:
            `${portal.name}: ${
              error?.message || error
            }`
        }
      );
    }
  }

  /*
    For each existing official recruitment,
    compare both portal results.
  */
  for (
    const item of items
  ) {
    const first =
      portalResults[0];

    const second =
      portalResults[1];

    const firstCandidate =
      first?.candidates?.find(
        candidate =>
          sameRecruitment(
            item,
            candidate
          )
      ) || null;

    const secondCandidate =
      second?.candidates?.find(
        candidate =>
          sameRecruitment(
            item,
            candidate
          )
      ) || null;

    if (
      !firstCandidate ||
      !secondCandidate
    ) {
      await notify(
        db,
        'source_unavailable',
        'Admin verification required',
        `${item.title}: official source unavailable and Portal 1/2 could not both confirm the recruitment.`,
        item.id
      );

      continue;
    }

    const agreement =
      comparable(
        firstCandidate
      ) ===
      comparable(
        secondCandidate
      );

    const recovered = {};

    for (
      const field of [
        'notification_url',
        'apply_url',
        'last_date',
        'application_start',
        'exam_date',
        'vacancies',
        'qualification',
        'eligibility',
        'fee',
        'selection_process',
        'salary'
      ]
    ) {
      if (
        hasUsableUrl(
          item[field]
        )
      ) {
        continue;
      }

      const a =
        firstCandidate[field];

      const b =
        secondCandidate[field];

      if (
        hasUsableUrl(a) &&
        hasUsableUrl(b) &&
        normalizeComparable(a) ===
        normalizeComparable(b)
      ) {
        recovered[field] =
          a;
      }
    }

    const evidence = {
      authority:
        'secondary_only',

      official_source:
        official.name,

      portals: [
        first.portal.name,
        second.portal.name
      ],

      agreement,

      recovered,

      official_source_status:
        'unavailable'
    };

    const updates = [];
    const values = [];

    for (
      const [field, value]
      of Object.entries(recovered)
    ) {
      if (
        !hasUsableUrl(
          item[field]
        )
      ) {
        updates.push(
          `${field}=?`
        );

        values.push(value);
      }
    }

    updates.push(
      `evidence_json=?`
    );

    values.push(
      safeJson(evidence)
    );

    updates.push(
      `last_seen_at=?`
    );

    values.push(
      iso(now)
    );

    /*
      NEVER demote an already published
      recruitment merely because the official
      site is temporarily unavailable.
    */
    if (
      item.status !== 'published'
    ) {
      updates.push(
        `status=?`
      );

      values.push(
        'verification_required'
      );

      updates.push(
        `verification_status=?`
      );

      values.push(
        'secondary_crosscheck'
      );

      updates.push(
        `confidence_score=?`
      );

      values.push(
        agreement
          ? 65
          : 50
      );
    }

    values.push(
      item.id
    );

    await db
      .prepare(`
        UPDATE items
        SET
          ${updates.join(',')},
          updated_at=CURRENT_TIMESTAMP
        WHERE id=?
      `)
      .bind(
        ...values
      )
      .run();

    await notify(
      db,
      'secondary_crosscheck',
      'Admin verification required',
      `${item.title}: Portal 1/2 ${agreement ? 'agree' : 'do not fully agree'}. Official source is currently unavailable.`,
      item.id
    );

    await recordEvent(
      db,
      {
        itemId:
          item.id,

        sourceId:
          official.id,

        eventType:
          'portal_fallback_existing_item',

        severity:
          'warning',

        message:
          `Portal fallback checked existing recruitment: ${item.title}`,

        evidence
      }
    );
  }
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
      const candidate of limited
    ) {
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

        await portalFallbackForCandidate(
          db,
          current,
          candidate,
          verification,
          existing || await findExistingItem(db, candidate, candidateKey(candidate)),
          now,
          stats
        );

        /* Do not publish incomplete recruitment automatically. */
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
      After the official source has exhausted
      its daily retry budget, check Portal 1/2
      for existing records.
    */
    if (
      failure.count >=
      RETRY_LIMIT
    ) {
      await runPortalsForFallback(
        db,
        current,
        now,
        stats
      );
    }
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
