const JOB_TYPES = new Set(['job', 'recruitment']);

const PDF_RE = /\.pdf(?:[?#]|$)/i;

const GENERIC_PAGE_RE =
  /(?:^|[\/_-])(about|contact|privacy|terms|disclaimer|login|signin|sign-in|home|index)(?:[\/_.?#-]|$)/i;

const GENERIC_CAREER_RE =
  /\b(?:career|careers)\b/i;

const APPLY_RE =
  /\b(?:apply|application|registration|register|candidate\s*login)\b/i;

/* -------------------------------------------------------------------------- */
/* URL helpers                                                                */
/* -------------------------------------------------------------------------- */

export function isHttpUrl(value) {
  try {
    const u = new URL(value);

    return (
      u.protocol === 'https:' ||
      u.protocol === 'http:'
    );
  } catch {
    return false;
  }
}

export function sameHostOrAllowed(
  url,
  allowedDomains = ''
) {
  try {
    const host =
      new URL(url)
        .hostname
        .toLowerCase();

    return allowedDomains
      .split(';')
      .map(x => x.trim().toLowerCase())
      .filter(Boolean)
      .some(domain =>
        host === domain ||
        host.endsWith(`.${domain}`)
      );
  } catch {
    return false;
  }
}

export function isPdfUrl(url) {
  return PDF_RE.test(
    String(url || '')
  );
}

export function normalizeUrl(value) {
  if (!value || !isHttpUrl(value)) {
    return null;
  }

  try {
    const u = new URL(value);

    u.hash = '';
    u.hostname =
      u.hostname.toLowerCase();

    /*
      Remove default ports.
    */
    if (
      (u.protocol === 'https:' && u.port === '443') ||
      (u.protocol === 'http:' && u.port === '80')
    ) {
      u.port = '';
    }

    /*
      Keep query parameters because government
      application links may require them.
    */

    return u.toString();
  } catch {
    return null;
  }
}

export function distinctUrls(values = []) {
  return [
    ...new Set(
      values
        .map(normalizeUrl)
        .filter(Boolean)
    )
  ];
}

/* -------------------------------------------------------------------------- */
/* URL comparison                                                             */
/* -------------------------------------------------------------------------- */

function sameUrl(a, b) {
  const x = normalizeUrl(a);
  const y = normalizeUrl(b);

  return Boolean(
    x &&
    y &&
    x === y
  );
}

function isExternalApplyAllowed(
  applyUrl,
  source
) {
  /*
    Some official organisations use a separate
    government application portal.

    Example:
      official source domain
      +
      separate official application domain.

    Therefore external apply URL is allowed,
    but only when it is HTTPS/HTTP and not a PDF.
  */
  if (!applyUrl) {
    return false;
  }

  if (isPdfUrl(applyUrl)) {
    return false;
  }

  if (!isHttpUrl(applyUrl)) {
    return false;
  }

  if (
    source?.allowed_domains &&
    sameHostOrAllowed(
      applyUrl,
      source.allowed_domains
    )
  ) {
    return true;
  }

  /*
    External application domains are allowed as
    a warning, not automatically rejected.
  */
  return true;
}

/* -------------------------------------------------------------------------- */
/* Generic page detection                                                     */
/* -------------------------------------------------------------------------- */

function looksGenericPage(url) {
  return GENERIC_PAGE_RE.test(
    String(url || '')
  );
}

function looksGenericCareerPage(
  url,
  title = ''
) {
  const value =
    `${url || ''} ${title || ''}`;

  /*
    A career page is not itself an application
    unless it also contains an application signal.
  */
  return (
    GENERIC_CAREER_RE.test(value) &&
    !APPLY_RE.test(value)
  );
}

/* -------------------------------------------------------------------------- */
/* Slug / hash                                                                */
/* -------------------------------------------------------------------------- */

export function slugify(value) {
  return String(value || '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(
      /[^\p{Letter}\p{Number}]+/gu,
      '-'
    )
    .replace(
      /^-+|-+$/g,
      ''
    )
    .slice(0, 110)
    ||
    `item-${Date.now()}`;
}

export async function sha256Hex(value) {
  const bytes =
    new TextEncoder().encode(
      String(value)
    );

  const digest =
    await crypto.subtle.digest(
      'SHA-256',
      bytes
    );

  return [
    ...new Uint8Array(digest)
  ]
    .map(
      b =>
        b.toString(16).padStart(2, '0')
    )
    .join('');
}

/* -------------------------------------------------------------------------- */
/* Stable identity                                                            */
/* -------------------------------------------------------------------------- */

export function canonicalNotificationKey(
  candidate
) {
  /*
    IMPORTANT:
    Do NOT make the notification PDF URL the
    primary identity.

    A revised PDF for the same recruitment should
    update the existing item instead of creating
    another recruitment.

    sources.js now supplies:
      source.id + canonical detail page URL
  */

  if (
    candidate.notification_key &&
    String(candidate.notification_key).trim()
  ) {
    return String(
      candidate.notification_key
    ).trim();
  }

  const canonical =
    normalizeUrl(
      candidate.canonical_url
    );

  if (canonical) {
    return canonical;
  }

  const source =
    normalizeUrl(
      candidate.source_url
    );

  if (source) {
    return source;
  }

  /*
    Last-resort fallback.
  */
  return [
    candidate.organization || '',
    candidate.title || '',
    candidate.type || '',
    candidate.last_date || ''
  ]
    .map(x =>
      String(x)
        .trim()
        .toLowerCase()
    )
    .join('|');
}

/* -------------------------------------------------------------------------- */
/* Candidate validation                                                       */
/* -------------------------------------------------------------------------- */

export function validateCandidate(
  candidate,
  source
) {
  const errors = [];
  const warnings = [];

  const type =
    candidate?.type || 'update';

  const official =
    normalizeUrl(
      candidate?.official_url
    );

  const notification =
    normalizeUrl(
      candidate?.notification_url
    );

  const apply =
    normalizeUrl(
      candidate?.apply_url
    );

  const sourceUrl =
    normalizeUrl(
      candidate?.source_url
    );

  /* ---------------------------------------------------------------------- */
  /* Basic validation                                                       */
  /* ---------------------------------------------------------------------- */

  if (
    !candidate?.title ||
    !String(candidate.title).trim()
  ) {
    errors.push(
      'Missing title'
    );
  }

  if (!sourceUrl) {
    errors.push(
      'Missing valid source URL'
    );
  }

  if (
    source?.role === 'official' &&
    sourceUrl &&
    !sameHostOrAllowed(
      sourceUrl,
      source.allowed_domains
    )
  ) {
    errors.push(
      'Source URL outside allowed official domain'
    );
  }

  /*
    Generic pages should not become recruitment
    records.
  */
  if (
    JOB_TYPES.has(type) &&
    sourceUrl &&
    looksGenericPage(sourceUrl)
  ) {
    errors.push(
      'Generic page cannot be used as recruitment source'
    );
  }

  /* ---------------------------------------------------------------------- */
  /* Recruitment validation                                                */
  /* ---------------------------------------------------------------------- */

  if (JOB_TYPES.has(type)) {

    if (!official) {
      errors.push(
        'Recruitment item missing official URL'
      );
    }

    if (!notification) {
      errors.push(
        'Recruitment item missing notification PDF URL'
      );
    } else if (
      !isPdfUrl(notification)
    ) {
      errors.push(
        'Notification URL is not a PDF URL'
      );
    }

    if (!apply) {
      errors.push(
        'Recruitment item missing apply URL'
      );
    } else if (
      isPdfUrl(apply)
    ) {
      errors.push(
        'Apply URL must not be a PDF'
      );
    }

    /*
      All three URLs must be different.
    */
    if (
      official &&
      notification &&
      sameUrl(
        official,
        notification
      )
    ) {
      errors.push(
        'Official URL and notification URL must differ'
      );
    }

    if (
      official &&
      apply &&
      sameUrl(
        official,
        apply
      )
    ) {
      errors.push(
        'Official URL and apply URL must differ'
      );
    }

    if (
      notification &&
      apply &&
      sameUrl(
        notification,
        apply
      )
    ) {
      errors.push(
        'Notification URL and apply URL must differ'
      );
    }

    /*
      Apply URL must be a real HTTP(S) URL.
    */
    if (
      apply &&
      !isExternalApplyAllowed(
        apply,
        source
      )
    ) {
      errors.push(
        'Invalid application URL'
      );
    }

    /*
      Official URL must stay inside the
      official source domain.
    */
    if (
      source?.role === 'official' &&
      official &&
      !sameHostOrAllowed(
        official,
        source.allowed_domains
      )
    ) {
      errors.push(
        'Official URL outside allowed official domain'
      );
    }

    /*
      Notification should normally be hosted by
      the official source.
    */
    if (
      source?.role === 'official' &&
      notification &&
      !sameHostOrAllowed(
        notification,
        source.allowed_domains
      )
    ) {
      warnings.push(
        'Notification PDF is outside official domain'
      );
    }

    /*
      External application portals are possible.
    */
    if (
      source?.role === 'official' &&
      apply &&
      !sameHostOrAllowed(
        apply,
        source.allowed_domains
      )
    ) {
      warnings.push(
        'Application URL is on an external domain'
      );
    }

    /*
      A generic careers page must not be treated
      as the application URL.
    */
    if (
      apply &&
      looksGenericCareerPage(
        apply,
        candidate.title
      )
    ) {
      errors.push(
        'Generic careers page cannot be used as apply URL'
      );
    }
  }

  return {
    ok:
      errors.length === 0,

    errors,
    warnings
  };
}

/* -------------------------------------------------------------------------- */
/* Evidence scoring                                                           */
/* -------------------------------------------------------------------------- */

function calculateConfidence(
  candidate,
  source,
  validation
) {
  let score = 0;

  /*
    Start from evidence, NOT from source type.
    This prevents every official page from
    automatically receiving 85 points.
  */

  if (
    source?.role === 'official'
  ) {
    score += 25;
  } else {
    score += 5;
  }

  if (
    candidate?.title &&
    String(candidate.title).trim()
  ) {
    score += 10;
  }

  if (
    candidate?.official_url
  ) {
    score += 10;
  }

  if (
    candidate?.notification_url &&
    isPdfUrl(
      candidate.notification_url
    )
  ) {
    score += 20;
  }

  if (
    candidate?.apply_url &&
    !isPdfUrl(
      candidate.apply_url
    )
  ) {
    score += 20;
  }

  if (
    candidate?.qualification ||
    candidate?.eligibility
  ) {
    score += 5;
  }

  if (
    candidate?.last_date
  ) {
    score += 4;
  }

  if (
    candidate?.application_start
  ) {
    score += 2;
  }

  if (
    candidate?.vacancies
  ) {
    score += 2;
  }

  if (
    candidate?.selection_process
  ) {
    score += 2;
  }

  /*
    Warnings reduce confidence slightly.
  */
  score -=
    Math.min(
      10,
      (validation?.warnings?.length || 0) * 2
    );

  /*
    Invalid candidate can never receive a
    publish-ready confidence.
  */
  if (!validation?.ok) {
    score = Math.min(
      score,
      59
    );
  }

  return Math.max(
    0,
    Math.min(
      100,
      score
    )
  );
}

/* -------------------------------------------------------------------------- */
/* Verification                                                              */
/* -------------------------------------------------------------------------- */

export async function verifyCandidate(
  candidate,
  source
) {
  const validation =
    validateCandidate(
      candidate,
      source
    );

  /*
    Fingerprint intentionally excludes volatile
    fields that may change during an update.
  */
  const fingerprintPayload = {
    title:
      candidate?.title || '',

    organization:
      candidate?.organization || '',

    type:
      candidate?.type || '',

    canonical_key:
      canonicalNotificationKey(
        candidate
      ),

    source_url:
      normalizeUrl(
        candidate?.source_url
      ),

    notification_url:
      normalizeUrl(
        candidate?.notification_url
      ),

    apply_url:
      normalizeUrl(
        candidate?.apply_url
      )
  };

  const fingerprint =
    await sha256Hex(
      JSON.stringify(
        fingerprintPayload
      )
    );

  const confidence =
    calculateConfidence(
      candidate,
      source,
      validation
    );

  /*
    Auto-publish threshold is deliberately
    high.

    monitor.js currently checks >= 85.
    Therefore a valid recruitment candidate
    must contain strong evidence before it
    can reach that threshold.
  */

  const autoPublishEligible =
    validation.ok &&
    confidence >= 85;

  return {
    ...validation,

    fingerprint,

    confidence,

    autoPublishEligible
  };
}
