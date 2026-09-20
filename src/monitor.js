/*
  North Bharat Jobs
  Official-source monitoring engine

  Responsibilities:
  - Scan enabled official sources
  - Verify discovered candidates
  - Publish only verified candidates
  - Update existing recruitment records instead of cloning them
  - Keep revision history only when real data changes
  - Prevent duplicate records
  - Handle source failures with retry/circuit-breaker logic
  - Use two configured portal sources as fallback after daily retry exhaustion
  - Remove records older than 365 days
  - Keep D1 workload bounded
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

const RETRY_LIMIT = 20;
const RETRY_MINUTES = 5;
const RETENTION_DAYS = 365;

const SOURCE_BATCH = 4;
const CANDIDATE_LIMIT = 8;

const RETENTION_DELETE_BATCH = 100;
const REVISION_MAX_PER_UPDATE = 1;

function iso(d = new Date()) {
  return d.toISOString();
}

function dayKey(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

function plusMinutes(d, minutes) {
  return new Date(
    d.getTime() + minutes * 60_000
  ).toISOString();
}

function plusDays(d, days) {
  return new Date(
    d.getTime() + days * 86_400_000
  ).toISOString();
}

function errorKind(error) {
  const message = `${error?.message || ''}`.toLowerCase();
  const status = Number(error?.status || 0);

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

  if (status === 401 || status === 403) {
    return 'access_denied';
  }

  if (status === 429) {
    return 'rate_limited';
  }

  if (
    status >= 500 ||
    /fetch-error|timeout|aborted|522|525|network|connection/.test(message)
  ) {
    return 'transient';
  }

  return 'error';
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

function safeJson(value) {
  try {
    return JSON.stringify(value ?? null);
  } catch {
    return JSON.stringify(null);
  }
}

/*
  Reset retry counters at the beginning of a new UTC day.
*/
async function resetRetryIfNewDay(db, source, now) {
  const today = dayKey(now);

  if (source.retry_day === today) {
    return source;
  }

  const nextRetry = iso(now);

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
    .bind(today, nextRetry, source.id)
    .run();

  return {
    ...source,
    retry_day: today,
    retry_count: 0,
    next_retry_at: nextRetry,
    circuit_until: null
  };
}

/*
  Remove old records in bounded batches.

  Important:
  - item_revisions -> ON DELETE CASCADE
  - verification_events -> ON DELETE SET NULL
  - notifications -> ON DELETE SET NULL

  Therefore deleting the item is safe with the current schema.
*/
async function purgeExpiredItems(db, now) {
  const cutoff = new Date(
    now.getTime() - RETENTION_DAYS * 86_400_000
  ).toISOString();

  let deleted = 0;

  for (;;) {
    const rows = await db
      .prepare(`
        SELECT id
        FROM items
        WHERE COALESCE(published_at, created_at) < ?
        LIMIT ?
      `)
      .bind(cutoff, RETENTION_DELETE_BATCH)
      .all();

    const ids = (rows.results || [])
      .map(row => Number(row.id))
      .filter(Number.isInteger);

    if (!ids.length) {
      break;
    }

    const statements = ids.map(id =>
      db
        .prepare(`DELETE FROM items WHERE id=?`)
        .bind(id)
    );

    await db.batch(statements);

    deleted += ids.length;

    if (ids.length < RETENTION_DELETE_BATCH) {
      break;
    }
  }

  return deleted;
}

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
      evidence ? safeJson(evidence) : null
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

/*
  Mark source as successful.

  next_retry_at is deliberately set to current time.
  The main scheduler uses last_checked_at to rotate through
  sources fairly.
*/
async function sourceSuccess(db, source, now) {
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

/*
  Handle official-source failure.
*/
async function sourceFailure(
  db,
  source,
  error,
  now
) {
  const current = await resetRetryIfNewDay(
    db,
    source,
    now
  );

  const kind = errorKind(error);
  const status = Number(error?.status || 0) || null;

  let retryCount =
    Number(current.retry_count || 0) + 1;

  let nextRetry = plusMinutes(
    now,
    RETRY_MINUTES
  );

  let circuitUntil = null;

  if (kind === 'security_challenge') {
    nextRetry = plusDays(now, 1);
    circuitUntil = nextRetry;
  }

  else if (kind === 'not_found') {
    nextRetry = plusDays(now, 1);
    circuitUntil = nextRetry;
  }

  else if (
    kind === 'access_denied' &&
    retryCount < 3
  ) {
    nextRetry = plusMinutes(now, 60);
  }

  else if (kind === 'access_denied') {
    nextRetry = plusDays(now, 1);
    circuitUntil = nextRetry;
  }

  else if (kind === 'rate_limited') {
    const retryAfter =
      Number(error?.retryAfter || 0);

    nextRetry =
      retryAfter > 0
        ? new Date(
            now.getTime() +
            retryAfter * 1000
          ).toISOString()
        : plusMinutes(now, 10);
  }

  if (retryCount >= RETRY_LIMIT) {
    nextRetry = plusDays(now, 1);
    circuitUntil = nextRetry;
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
      String(error?.message || error),
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

/*
  Build the database field set for an official candidate.
*/
function buildOfficialFields(
  candidate,
  verification,
  source,
  now,
  existing,
  hash
) {
  const verified =
    verification.ok &&
    Number(verification.confidence || 0) >= 85;

  const status =
    verified
      ? 'published'
      : 'verification_required';

  return {
    notification_key: candidateKey(candidate),

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

    official_url:
      candidate.official_url || null,

    apply_url:
      candidate.apply_url || null,

    notification_url:
      candidate.notification_url || null,

    source_url:
      candidate.source_url,

    source_name:
      source.name,

    source_id:
      source.id,

    source_hash:
      hash,

    canonical_url:
      candidate.canonical_url ||
      candidate.source_url,

    status,

    verification_status:
      verified
        ? 'verified'
        : 'verification_required',

    confidence_score:
      Number(verification.confidence || 0),

    evidence_json:
      safeJson({
        errors: verification.errors || [],
        warnings: verification.warnings || [],
        authority: 'official'
      }),

    last_verified_at:
      verified
        ? iso(now)
        : null,

    last_seen_at:
      iso(now),

    /*
      Never reset the original publication date
      when an existing item is updated.
    */
    published_at:
      existing?.published_at ||
      (
        verified
          ? iso(now)
          : null
      )
  };
}

/*
  Find an existing item using stable identity.

  Priority:
  1. notification_key
  2. canonical_url
  3. source_url

  This is important because a changed PDF URL should not
  automatically create a second recruitment record when the
  canonical recruitment page remains the same.
*/
async function findExistingItem(
  db,
  candidate,
  key
) {
  const canonical =
    candidate.canonical_url ||
    candidate.source_url ||
    null;

  const sourceUrl =
    candidate.source_url ||
    null;

  if (key) {
    const byKey = await db
      .prepare(`
        SELECT *
        FROM items
        WHERE notification_key=?
        ORDER BY id
        LIMIT 1
      `)
      .bind(key)
      .first();

    if (byKey) {
      return byKey;
    }
  }

  if (canonical) {
    const byCanonical = await db
      .prepare(`
        SELECT *
        FROM items
        WHERE canonical_url=?
        ORDER BY id
        LIMIT 1
      `)
      .bind(canonical)
      .first();

    if (byCanonical) {
      return byCanonical;
    }
  }

  if (sourceUrl) {
    const bySource = await db
      .prepare(`
        SELECT *
        FROM items
        WHERE source_url=?
        ORDER BY id
        LIMIT 1
      `)
      .bind(sourceUrl)
      .first();

    if (bySource) {
      return bySource;
    }
  }

  return null;
}

/*
  Compare database fields with candidate fields.
*/
function getChangedFields(
  existing,
  fields
) {
  return Object.keys(fields).filter(
    field =>
      String(existing[field] ?? '') !==
      String(fields[field] ?? '')
  );
}

/*
  Upsert an official-source candidate.

  Critical behavior:
  - Existing record keeps the same ID.
  - No new slug is generated for an existing record.
  - Revision is created only when real fields changed.
  - No revision is created on an identical scan.
*/
async function upsertOfficial(
  db,
  candidate,
  verification,
  source,
  now
) {
  const key = candidateKey(candidate);

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
    Existing item
  */
  if (existing) {
    const changedFields =
      getChangedFields(
        existing,
        fields
      );

    /*
      Nothing actually changed.
      Only update last_seen_at and updated_at.
      Do NOT create a revision.
    */
    if (changedFields.length === 0) {
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
          existing.status === 'published',
        verificationRequired:
          existing.status ===
          'verification_required',
        blocked: false
      };
    }

    /*
      Record exactly one revision for this scan.
    */
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

    const revision =
      Math.max(
        1,
        revisionNo
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
        revision,
        safeJson(changedFields),
        safeJson(fields)
      )
      .run();

    const assignments =
      Object.keys(fields)
        .map(field => `${field}=?`)
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

    const wasPublished =
      existing.status === 'published';

    const isPublished =
      fields.status === 'published';

    return {
      id: existing.id,
      created: false,
      updated: true,
      changed: true,
      published:
        !wasPublished && isPublished,
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
    columns.map(() => '?').join(',');

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
    result.meta?.last_row_id || null;

  return {
    id,
    created: true,
    updated: false,
    changed: true,
    published:
      fields.status === 'published',
    verificationRequired:
      fields.status ===
      'verification_required',
    blocked: false
  };
}

/*
  Process one official source.
*/
async function runOfficial(
  db,
  source,
  now,
  stats
) {
  const sourceFresh =
    await resetRetryIfNewDay(
      db,
      source,
      now
    );

  /*
    Circuit breaker.
  */
  if (
    sourceFresh.circuit_until &&
    new Date(
      sourceFresh.circuit_until
    ) > now
  ) {
    return;
  }

  /*
    Retry delay.
  */
  if (
    sourceFresh.next_retry_at &&
    new Date(
      sourceFresh.next_retry_at
    ) > now
  ) {
    return;
  }

  /*
    Daily retry limit.
  */
  if (
    Number(sourceFresh.retry_count || 0) >=
    RETRY_LIMIT
  ) {
    return;
  }

  try {
    const candidates =
      await discoverFromSource(
        sourceFresh
      );

    const limited =
      (candidates || []).slice(
        0,
        CANDIDATE_LIMIT
      );

    for (const candidate of limited) {
      stats.discovered++;

      let verification;

      try {
        verification =
          await verifyCandidate(
            candidate,
            sourceFresh
          );
      } catch (error) {
        stats.errors++;

        await recordEvent(
          db,
          {
            sourceId: sourceFresh.id,
            eventType:
              'candidate_verification_error',
            severity: 'error',
            message:
              `Candidate verification failed: ${
                error?.message || error
              }`,
            evidence: {
              title:
                candidate?.title || null,
              source:
                sourceFresh.name
            }
          }
        );

        continue;
      }

      /*
        Invalid candidate is not allowed to
        become a public job.
      */
      if (
        !verification ||
        verification.ok !== true ||
        Number(
          verification.confidence || 0
        ) < 85
      ) {
        stats.blocked++;

        /*
          We still store a verification_required
          item only if it has a valid stable key.
        */
      }

      const result =
        await upsertOfficial(
          db,
          candidate,
          verification,
          sourceFresh,
          now
        );

      if (result.blocked) {
        stats.blocked++;

        await recordEvent(
          db,
          {
            sourceId: sourceFresh.id,
            eventType:
              'candidate_blocked',
            severity: 'warning',
            message:
              'Candidate did not have a valid stable notification identity.',
            evidence: {
              title:
                candidate?.title || null
            }
          }
        );

        continue;
      }

      if (result.published) {
        stats.published++;
      }

      if (result.updated) {
        stats.updated++;
      }

      if (result.verificationRequired) {
        stats.verificationRequired++;

        await recordEvent(
          db,
          {
            itemId: result.id,
            sourceId: sourceFresh.id,
            eventType:
              'verification_required',
            severity: 'warning',
            message:
              'Automatic official-source verification incomplete.',
            evidence: {
              errors:
                verification.errors || [],
              warnings:
                verification.warnings || [],
              confidence:
                verification.confidence || 0
            }
          }
        );

        /*
          Avoid notification spam for every
          identical scan. A notification is
          generated only when this scan created
          or changed the verification state.
        */
        if (
          result.created ||
          result.changed
        ) {
          await notify(
            db,
            'verification_required',
            'Verification required',
            `Review: ${candidate.title}`,
            result.id
          );
        }
      }
    }

    await sourceSuccess(
      db,
      sourceFresh,
      now
    );

  } catch (error) {
    stats.errors++;

    const failure =
      await sourceFailure(
        db,
        sourceFresh,
        error,
        now
      );

    await recordEvent(
      db,
      {
        sourceId: sourceFresh.id,
        eventType:
          'source_error',
        severity: 'error',
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
      Portal fallback is attempted only
      after the official source reaches
      the daily retry limit.
    */
    if (
      failure.count >= RETRY_LIMIT
    ) {
      await runPortalsForFallback(
        db,
        sourceFresh,
        now,
        stats
      );
    }
  }
}

/*
  Portal fallback.

  Two independent enabled portal sources
  must discover the same recruitment.

  Portal-only data is NEVER published
  automatically.
*/
async function runPortalsForFallback(
  db,
  official,
  now,
  stats
) {
  const portalRows =
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
        ORDER BY priority ASC, id ASC
        LIMIT 2
      `)
      .bind(
        official.fallback_key
      )
      .all();

  const portals =
    portalRows.results || [];

  if (portals.length < 2) {
    await notify(
      db,
      'configuration',
      'Portal fallback not configured',
      `Official source ${official.name} reached its daily retry limit. Configure two enabled portal sources for fallback_key=${official.fallback_key}.`
    );

    return;
  }

  const found = [];

  for (const portal of portals) {
    try {
      const candidates =
        await discoverPortal(
          portal
        );

      found.push({
        portal,
        candidates:
          candidates || []
      });

    } catch (error) {
      stats.errors++;

      await recordEvent(
        db,
        {
          sourceId: portal.id,
          eventType:
            'portal_error',
          severity: 'warning',
          message:
            `${portal.name}: ${
              error?.message || error
            }`
        }
      );
    }
  }

  /*
    Group portal candidates by stable identity.
  */
  const grouped =
    new Map();

  for (const group of found) {
    for (
      const candidate of
      group.candidates.slice(
        0,
        CANDIDATE_LIMIT
      )
    ) {
      const key =
        candidateKey(candidate);

      if (!key) {
        continue;
      }

      const list =
        grouped.get(key) || [];

      list.push({
        ...candidate,
        _portal:
          group.portal.name
      });

      grouped.set(
        key,
        list
      );
    }
  }

  for (
    const [key, candidates]
    of grouped
  ) {
    const firstPortal =
      portals[0];

    const secondPortal =
      portals[1];

    const fromFirst =
      candidates.find(
        candidate =>
          candidate._portal ===
          firstPortal.name
      );

    const fromSecond =
      candidates.find(
        candidate =>
          candidate._portal ===
          secondPortal.name
      );

    /*
      Both portals must contain the same
      stable recruitment identity.
    */
    if (
      !fromFirst ||
      !fromSecond
    ) {
      continue;
    }

    const same =
      comparable(fromFirst) ===
      comparable(fromSecond);

    const merged = {
      ...fromFirst,

      /*
        Portal-only data must never pretend
        to be an official source.
      */
      official_url:
        null,

      source_name:
        `${firstPortal.name} + ${secondPortal.name}`,

      source_id:
        null,

      source_url:
        fromFirst.source_url
    };

    const existing =
      await findExistingItem(
        db,
        merged,
        key
      );

    const confidence =
      same ? 65 : 35;

    const evidence =
      {
        authority:
          'secondary_only',

        portals: [
          firstPortal.name,
          secondPortal.name
        ],

        consistent:
          same
      };

    if (existing) {
      await db
        .prepare(`
          UPDATE items
          SET
            status='verification_required',
            verification_status='secondary_crosscheck',
            confidence_score=?,
            evidence_json=?,
            last_seen_at=?,
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(
          confidence,
          safeJson(evidence),
          iso(now),
          existing.id
        )
        .run();

    } else {
      const slug =
        `${slugify(
          merged.title
        )}-${(
          await sha256Hex(key)
        ).slice(0, 8)}`;

      await db
        .prepare(`
          INSERT INTO items(
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
            status,
            verification_status,
            confidence_score,
            evidence_json,
            last_seen_at,
            created_at,
            updated_at
          )
          VALUES(
            ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
          )
        `)
        .bind(
          slug,
          key,
          merged.type || 'job',
          merged.title,
          merged.organization || null,
          merged.category || null,
          merged.location || null,
          merged.description || null,
          merged.qualification || null,
          merged.vacancies || null,
          merged.age_limit || null,
          merged.fee || null,
          merged.selection_process || null,
          merged.salary || null,
          merged.application_start || null,
          merged.last_date || null,
          merged.exam_date || null,
          null,
          merged.apply_url || null,
          merged.notification_url || null,
          merged.source_url,
          merged.source_name,
          'verification_required',
          'secondary_crosscheck',
          confidence,
          safeJson(evidence),
          iso(now)
        )
        .run();
    }

    stats.verificationRequired++;

    await notify(
      db,
      'verification_required',
      same
        ? 'Two-portal match needs admin verification'
        : 'Portal mismatch needs admin verification',
      `${merged.title}. Official source was unavailable after the daily retry budget.`,
      existing?.id || null
    );
  }
}

/*
  Main monitoring entry point.
*/
export async function runMonitor(
  env,
  requestedSource = null
) {
  const db = env.DB;

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

  /*
    365-day cleanup first.
  */
  stats.archived =
    await purgeExpiredItems(
      db,
      started
    );

  let sources;

  /*
    Manual/admin requested source.
  */
  if (requestedSource) {
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

  }

  /*
    Normal scheduled monitoring.

    last_checked_at is included so that
    the 4-source batch rotates fairly.
  */
  else {
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
          ORDER BY
            priority ASC,
            COALESCE(
              last_checked_at,
              '1970-01-01'
            ) ASC,
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

  for (const source of sources) {
    stats.sources++;

    const errorsBefore =
      stats.errors;

    try {
      await runOfficial(
        db,
        source,
        new Date(),
        stats
      );
    } catch (error) {
      /*
        Last-resort protection so one source
        cannot stop the entire monitoring run.
      */
      stats.errors++;

      await recordEvent(
        db,
        {
          sourceId: source.id,
          eventType:
            'monitor_source_unhandled_error',
          severity: 'error',
          message:
            String(
              error?.message || error
            )
        }
      );
    }

    stats.details.push({
      source:
        source.name,

      error:
        stats.errors >
        errorsBefore
    });
  }

  const finished =
    new Date();

  /*
    Keep a permanent monitor-run summary.
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
      safeJson(stats.details)
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
