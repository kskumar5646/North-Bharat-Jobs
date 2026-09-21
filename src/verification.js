/*
  North Bharat Jobs
  Strict verification engine

  PURPOSE
  -------
  This file is the final safety gate before an item can become
  publishable.

  RULES
  -----
  1. Official domain alone is NOT enough.
  2. Generic pages are rejected.
  3. RTI / policy / affidavit / forms / syllabus-list pages
     cannot become recruitment notifications.
  4. Old recruitment/application links are rejected.
  5. Recruitment requires:
       official_url
       notification_url
       apply_url
  6. Notification must be a genuine recruitment/update PDF.
  7. Apply URL must be a real application/registration page.
  8. Admit/result/answer/syllabus/admission pages require
     category-specific evidence.
  9. Portal evidence is secondary only.
  10. Confidence >= 85 is possible only for strong evidence.
*/


/* -------------------------------------------------------------------------- */
/* Types                                                                      */
/* -------------------------------------------------------------------------- */

const JOB_TYPES =
  new Set([
    'job',
    'recruitment'
  ]);

const VALID_TYPES =
  new Set([
    'job',
    'recruitment',
    'admit_card',
    'result',
    'answer_key',
    'syllabus',
    'admission',
    'scholarship'
  ]);


/* -------------------------------------------------------------------------- */
/* URL patterns                                                               */
/* -------------------------------------------------------------------------- */

const PDF_RE =
  /\.pdf(?:[?#]|$)/i;

const GENERIC_PAGE_RE =
  /(?:^|[\/_-])(?:about|contact|privacy|terms|disclaimer|login|signin|sign-in|home|index|faq|feedback|tender|policy|rti|sitemap)(?:[\/_.?#-]|$)/i;

const GENERIC_TITLE_RE =
  /\b(?:home|welcome|about us|contact us|privacy policy|terms and conditions|disclaimer|site map|sitemap|feedback|rti|right to information|tender|policy|citizen charter)\b/i;

const GENERIC_CAREER_RE =
  /\b(?:career|careers|recruitment|employment)\b/i;

const APPLY_RE =
  /\b(?:apply|application|registration|register|candidate\s*login|online\s*form|apply\s*online)\b/i;


/* -------------------------------------------------------------------------- */
/* False-document patterns                                                    */
/* -------------------------------------------------------------------------- */

const NON_NOTIFICATION_PDF_RE =
  /\b(?:rti|right[\s_-]*to[\s_-]*information|policy|policies|privacy|affidavit|undertaking|declaration|certificate|proforma|proformae|form(?:s)?|application[\s_-]*form|answer[\s_-]*sheet|syllabus|scheme|rules|manual|guidelines|annual[\s_-]*report|audit|tender|quotation|notice[\s_-]*board|office[\s_-]*order|press[\s_-]*release|calendar|schedule|corrigendum[\s_-]*format)\b/i;

const RECRUITMENT_PDF_RE =
  /\b(?:advertisement|advert|notification|recruitment|recruit|vacancy|vacancies|employment|selection|appointment|engagement|post|posts|exam|examination|direct[\s_-]*recruitment|combined[\s_-]*competitive|application[\s_-]*notice|notice[\s_-]*for[\s_-]*recruitment)\b/i;

const ADMIT_PDF_RE =
  /\b(?:admit|admit[\s_-]*card|hall[\s_-]*ticket|e[\s_-]*admit|call[\s_-]*letter|entrance[\s_-]*card)\b/i;

const RESULT_PDF_RE =
  /\b(?:result|results|merit|merit[\s_-]*list|selection[\s_-]*list|final[\s_-]*result|score|marks|qualified|shortlisted|rank[\s_-]*list)\b/i;

const ANSWER_PDF_RE =
  /\b(?:answer[\s_-]*key|answer[\s_-]*keys|provisional[\s_-]*answer|final[\s_-]*answer)\b/i;

const SYLLABUS_PDF_RE =
  /\b(?:syllabus|scheme[\s_-]*of[\s_-]*examination|exam[\s_-]*scheme|course[\s_-]*outline)\b/i;

const ADMISSION_RE =
  /\b(?:admission|entrance|entrance[\s_-]*exam|application[\s_-]*form|counselling|counseling|university|college|nta|jee|neet)\b/i;


/* -------------------------------------------------------------------------- */
/* Old-link protection                                                        */
/* -------------------------------------------------------------------------- */

const YEAR_RE =
  /\b(19\d{2}|20\d{2}|21\d{2})\b/g;

function currentYear() {
  return new Date().getUTCFullYear();
}

function extractYears(value) {
  return [
    ...String(value || '')
      .matchAll(YEAR_RE)
  ]
    .map(match =>
      Number(match[1])
    )
    .filter(Number.isFinite);
}

function containsClearlyOldYear(
  value
) {
  const years =
    extractYears(value);

  if (!years.length) {
    return false;
  }

  const year =
    currentYear();

  /*
    Keep current year and immediately previous
    year because government recruitment cycles
    can legitimately continue across a year.
  */
  return years.some(
    y =>
      y < year - 1
  );
}

function containsFutureImpossibleYear(
  value
) {
  const years =
    extractYears(value);

  if (!years.length) {
    return false;
  }

  const year =
    currentYear();

  return years.some(
    y =>
      y > year + 1
  );
}


/* -------------------------------------------------------------------------- */
/* URL helpers                                                                */
/* -------------------------------------------------------------------------- */

export function isHttpUrl(value) {
  try {
    const u =
      new URL(value);

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

    return String(
      allowedDomains || ''
    )
      .split(';')
      .map(
        x =>
          x.trim()
            .toLowerCase()
      )
      .filter(Boolean)
      .some(domain =>
        host === domain ||
        host.endsWith(
          `.${domain}`
        )
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
  if (
    !value ||
    !isHttpUrl(value)
  ) {
    return null;
  }

  try {
    const u =
      new URL(value);

    u.hash = '';

    u.hostname =
      u.hostname.toLowerCase();

    if (
      (
        u.protocol ===
        'https:' &&
        u.port === '443'
      ) ||
      (
        u.protocol ===
        'http:' &&
        u.port === '80'
      )
    ) {
      u.port = '';
    }

    return u.toString();

  } catch {
    return null;
  }
}

export function distinctUrls(
  values = []
) {
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
  const x =
    normalizeUrl(a);

  const y =
    normalizeUrl(b);

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
  if (!applyUrl) {
    return false;
  }

  if (
    isPdfUrl(applyUrl)
  ) {
    return false;
  }

  if (
    !isHttpUrl(applyUrl)
  ) {
    return false;
  }

  /*
    Official application portals may use
    another government domain.

    External domain is therefore allowed,
    but later checks still apply.
  */
  return true;
}


/* -------------------------------------------------------------------------- */
/* Generic page detection                                                     */
/* -------------------------------------------------------------------------- */

function looksGenericPage(
  url
) {
  return GENERIC_PAGE_RE.test(
    String(url || '')
  );
}

function looksGenericTitle(
  title
) {
  return GENERIC_TITLE_RE.test(
    String(title || '')
  );
}

function looksGenericCareerPage(
  url,
  title = ''
) {
  const value =
    `${url || ''} ${title || ''}`;

  return (
    GENERIC_CAREER_RE.test(
      value
    ) &&
    !APPLY_RE.test(value)
  );
}


/* -------------------------------------------------------------------------- */
/* Category-specific false-positive checks                                    */
/* -------------------------------------------------------------------------- */

function looksNonNotificationPdf(
  url,
  title = ''
) {
  return NON_NOTIFICATION_PDF_RE.test(
    `${url || ''} ${title || ''}`
  );
}

function looksRecruitmentPdf(
  url,
  title = ''
) {
  return RECRUITMENT_PDF_RE.test(
    `${url || ''} ${title || ''}`
  );
}

function looksAdmitEvidence(
  candidate
) {
  return (
    ADMIT_PDF_RE.test(
      `${candidate?.title || ''} ${candidate?.notification_url || ''} ${candidate?.official_url || ''}`
    ) ||
    /\badmit[\s_-]*card\b/i.test(
      `${candidate?.title || ''} ${candidate?.description || ''} ${candidate?.source_url || ''}`
    )
  );
}

function looksResultEvidence(
  candidate
) {
  return (
    RESULT_PDF_RE.test(
      `${candidate?.title || ''} ${candidate?.notification_url || ''} ${candidate?.official_url || ''}`
    ) ||
    /\bresult\b/i.test(
      `${candidate?.title || ''} ${candidate?.description || ''} ${candidate?.source_url || ''}`
    )
  );
}

function looksAnswerKeyEvidence(
  candidate
) {
  return ANSWER_PDF_RE.test(
    `${candidate?.title || ''} ${candidate?.notification_url || ''} ${candidate?.official_url || ''}`
  );
}

function looksSyllabusEvidence(
  candidate
) {
  return SYLLABUS_PDF_RE.test(
    `${candidate?.title || ''} ${candidate?.notification_url || ''} ${candidate?.official_url || ''}`
  );
}

function looksAdmissionEvidence(
  candidate
) {
  return ADMISSION_RE.test(
    `${candidate?.title || ''} ${candidate?.description || ''} ${candidate?.official_url || ''} ${candidate?.notification_url || ''}`
  );
}


/* -------------------------------------------------------------------------- */
/* Evidence score from sources.js                                             */
/* -------------------------------------------------------------------------- */

function sourceEvidenceScore(
  candidate
) {
  const score =
    Number(
      candidate?._evidence_score || 0
    );

  return Number.isFinite(score)
    ? score
    : 0;
}

function hasStrongSourceEvidence(
  candidate
) {
  /*
    sources.js is expected to provide its own
    evidence score.

    A zero score means we do not have enough
    discovery evidence to trust the page.
  */
  return (
    sourceEvidenceScore(
      candidate
    ) >= 8
  );
}


/* -------------------------------------------------------------------------- */
/* Title quality                                                              */
/* -------------------------------------------------------------------------- */

function hasSpecificTitle(
  candidate
) {
  const title =
    String(
      candidate?.title || ''
    ).trim();

  if (
    title.length < 8
  ) {
    return false;
  }

  if (
    looksGenericTitle(title)
  ) {
    return false;
  }

  /*
    A title that consists only of the organisation
    name is not a specific update.
  */
  const organization =
    String(
      candidate?.organization || ''
    )
      .trim()
      .toLowerCase();

  if (
    organization &&
    title.toLowerCase() ===
      organization
  ) {
    return false;
  }

  return true;
}


/* -------------------------------------------------------------------------- */
/* Category validation                                                        */
/* -------------------------------------------------------------------------- */

function validateCategoryEvidence(
  candidate,
  type,
  errors
) {
  const text =
    [
      candidate?.title,
      candidate?.description,
      candidate?.official_url,
      candidate?.notification_url,
      candidate?.source_url
    ]
      .filter(Boolean)
      .join(' ');

  /*
    All public update categories require a
    specific title/evidence signal.
  */
  if (
    !hasSpecificTitle(candidate)
  ) {
    errors.push(
      'Candidate title is too generic'
    );
  }

  if (
    !hasStrongSourceEvidence(
      candidate
    )
  ) {
    errors.push(
      'Insufficient source evidence'
    );
  }

  if (
    type === 'admit_card' &&
    !looksAdmitEvidence(candidate)
  ) {
    errors.push(
      'No strong admit-card evidence'
    );
  }

  if (
    type === 'result' &&
    !looksResultEvidence(candidate)
  ) {
    errors.push(
      'No strong result evidence'
    );
  }

  if (
    type === 'answer_key' &&
    !looksAnswerKeyEvidence(candidate)
  ) {
    errors.push(
      'No strong answer-key evidence'
    );
  }

  if (
    type === 'syllabus' &&
    !looksSyllabusEvidence(candidate)
  ) {
    errors.push(
      'No strong syllabus evidence'
    );
  }

  if (
    type === 'admission' &&
    !looksAdmissionEvidence(candidate)
  ) {
    errors.push(
      'No strong admission evidence'
    );
  }

  /*
    Reject obvious administrative documents
    regardless of category.
  */
  if (
    NON_NOTIFICATION_PDF_RE.test(text) &&
    (
      type === 'answer_key' ||
      type === 'admit_card' ||
      type === 'result'
    )
  ) {
    errors.push(
      'Administrative/non-publication document cannot represent this category'
    );
  }

  /*
    An RTI/policy page cannot become a public
    recruitment/update item.
  */
  if (
    /\b(?:rti|right to information|privacy policy|terms|disclaimer|tender|policy)\b/i.test(
      text
    )
  ) {
    errors.push(
      'Administrative page cannot be used as public update evidence'
    );
  }
}


/* -------------------------------------------------------------------------- */
/* Slug / hash                                                                */
/* -------------------------------------------------------------------------- */

export function slugify(
  value
) {
  return String(
    value || ''
  )
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
    .slice(
      0,
      110
    )
    ||
    `item-${Date.now()}`;
}

export async function sha256Hex(
  value
) {
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
    ...new Uint8Array(
      digest
    )
  ]
    .map(
      b =>
        b.toString(16)
          .padStart(2, '0')
    )
    .join('');
}


/* -------------------------------------------------------------------------- */
/* Stable notification identity                                               */
/* -------------------------------------------------------------------------- */

export function canonicalNotificationKey(
  candidate
) {
  if (
    candidate?.notification_key &&
    String(
      candidate.notification_key
    ).trim()
  ) {
    return String(
      candidate.notification_key
    ).trim();
  }

  /*
    Prefer a canonical detail page over a
    changing PDF URL.
  */
  const canonical =
    normalizeUrl(
      candidate?.canonical_url
    );

  if (canonical) {
    return canonical;
  }

  const source =
    normalizeUrl(
      candidate?.source_url
    );

  if (source) {
    return source;
  }

  /*
    Last-resort stable identity.
  */
  return [
    candidate?.organization || '',
    candidate?.title || '',
    candidate?.type || ''
  ]
    .map(
      x =>
        String(x)
          .trim()
          .toLowerCase()
    )
    .join('|');
}


/* -------------------------------------------------------------------------- */
/* Main validation                                                            */
/* -------------------------------------------------------------------------- */

export function validateCandidate(
  candidate,
  source
) {
  const errors = [];
  const warnings = [];

  const type =
    String(
      candidate?.type || ''
    )
      .trim()
      .toLowerCase();

  /*
    Unknown types are never publishable.
  */
  if (
    !VALID_TYPES.has(type)
  ) {
    errors.push(
      `Unsupported candidate type: ${type || 'empty'}`
    );
  }

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

  const canonical =
    normalizeUrl(
      candidate?.canonical_url
    );

  /* ---------------------------------------------------------------------- */
  /* Basic validation                                                       */
  /* ---------------------------------------------------------------------- */

  if (
    !candidate?.title ||
    !String(
      candidate.title
    ).trim()
  ) {
    errors.push(
      'Missing title'
    );
  }

  if (
    !sourceUrl
  ) {
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

  if (
    canonical &&
    source?.role === 'official' &&
    !sameHostOrAllowed(
      canonical,
      source.allowed_domains
    )
  ) {
    errors.push(
      'Canonical URL outside allowed official domain'
    );
  }

  /* ---------------------------------------------------------------------- */
  /* Generic page protection                                                */
  /* ---------------------------------------------------------------------- */

  if (
    sourceUrl &&
    looksGenericPage(sourceUrl)
  ) {
    errors.push(
      'Generic page cannot be used as update source'
    );
  }

  if (
    looksGenericTitle(
      candidate?.title
    )
  ) {
    errors.push(
      'Generic page title cannot be published'
    );
  }

  /*
    A bare organisation homepage cannot be a
    meaningful update.
  */
  if (
    candidate?.organization &&
    normalizeComparable(
      candidate.title
    ) ===
    normalizeComparable(
      candidate.organization
    )
  ) {
    errors.push(
      'Title is only the organisation name'
    );
  }

  /* ---------------------------------------------------------------------- */
  /* Old/future URL protection                                              */
  /* ---------------------------------------------------------------------- */

  const allUrls =
    [
      sourceUrl,
      canonical,
      official,
      notification,
      apply
    ]
      .filter(Boolean)
      .join(' ');

  if (
    containsClearlyOldYear(
      allUrls
    )
  ) {
    errors.push(
      'URL contains an outdated recruitment year'
    );
  }

  if (
    containsFutureImpossibleYear(
      allUrls
    )
  ) {
    errors.push(
      'URL contains an impossible future year'
    );
  }

  /* ---------------------------------------------------------------------- */
  /* Recruitment validation                                                 */
  /* ---------------------------------------------------------------------- */

  if (
    JOB_TYPES.has(type)
  ) {
    if (!official) {
      errors.push(
        'Recruitment item missing official URL'
      );
    }

    if (!notification) {
      errors.push(
        'Recruitment item missing notification PDF URL'
      );
    }
    else if (
      !isPdfUrl(notification)
    ) {
      errors.push(
        'Notification URL is not a PDF URL'
      );
    }
    else if (
      looksNonNotificationPdf(
        notification,
        candidate?.title
      )
    ) {
      errors.push(
        'PDF is not a recruitment notification'
      );
    }
    else if (
      !looksRecruitmentPdf(
        notification,
        candidate?.title
      )
    ) {
      errors.push(
        'PDF does not contain strong recruitment/advertisement evidence'
      );
    }

    if (!apply) {
      errors.push(
        'Recruitment item missing apply URL'
      );
    }
    else if (
      isPdfUrl(apply)
    ) {
      errors.push(
        'Apply URL must not be a PDF'
      );
    }

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
      Official URL must belong to official
      source.
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
      Notification normally should be official.
      We keep this as an error for recruitment,
      because the notification is authoritative.
    */
    if (
      source?.role === 'official' &&
      notification &&
      !sameHostOrAllowed(
        notification,
        source.allowed_domains
      )
    ) {
      errors.push(
        'Recruitment notification PDF is outside official domain'
      );
    }

    if (
      apply &&
      looksGenericCareerPage(
        apply,
        candidate?.title
      )
    ) {
      errors.push(
        'Generic careers page cannot be used as apply URL'
      );
    }

    /*
      Recruitment needs at least one meaningful
      recruitment signal in the title/evidence.
    */
    const recruitmentText =
      [
        candidate?.title,
        candidate?.description,
        candidate?.official_url,
        candidate?.notification_url,
        candidate?.apply_url
      ]
        .filter(Boolean)
        .join(' ');

    if (
      !RECRUITMENT_PDF_RE.test(
        recruitmentText
      ) &&
      !/\b(?:vacancy|post|posts|recruitment|advertisement|notification|employment)\b/i.test(
        recruitmentText
      )
    ) {
      errors.push(
        'Insufficient recruitment-specific evidence'
      );
    }

    /*
      Strong source evidence is mandatory.
    */
    if (
      !hasStrongSourceEvidence(
        candidate
      )
    ) {
      errors.push(
        'Insufficient official discovery evidence'
      );
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Non-recruitment category validation                                     */
  /* ---------------------------------------------------------------------- */

  if (
    !JOB_TYPES.has(type) &&
    VALID_TYPES.has(type)
  ) {
    validateCategoryEvidence(
      candidate,
      type,
      errors
    );

    /*
      These categories do not need an apply URL,
      but if notification_url exists and is a PDF,
      it must not be an administrative PDF.
    */
    if (
      notification &&
      isPdfUrl(notification) &&
      looksNonNotificationPdf(
        notification,
        candidate?.title
      )
    ) {
      errors.push(
        'Administrative PDF cannot be used as update evidence'
      );
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Common apply URL protection                                             */
  /* ---------------------------------------------------------------------- */

  if (
    apply &&
    looksGenericCareerPage(
      apply,
      candidate?.title
    )
  ) {
    errors.push(
      'Generic career page cannot be used as application destination'
    );
  }

  if (
    apply &&
    containsClearlyOldYear(
      apply
    )
  ) {
    errors.push(
      'Application URL belongs to an outdated year'
    );
  }

  /*
    Application URL should not point to a
    generic home page.
  */
  if (
    apply &&
    looksGenericPage(apply)
  ) {
    errors.push(
      'Generic page cannot be used as application URL'
    );
  }

  /* ---------------------------------------------------------------------- */
  /* Warnings                                                               */
  /* ---------------------------------------------------------------------- */

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

  if (
    candidate?.last_date &&
    containsClearlyOldYear(
      candidate.last_date
    )
  ) {
    warnings.push(
      'Last-date text contains an old year'
    );
  }

  return {
    ok:
      errors.length === 0,

    errors,
    warnings
  };
}


/* -------------------------------------------------------------------------- */
/* Confidence scoring                                                        */
/* -------------------------------------------------------------------------- */

function calculateConfidence(
  candidate,
  source,
  validation
) {
  /*
    INVALID CANDIDATES CANNOT BE HIGH CONFIDENCE.
  */
  if (
    !validation?.ok
  ) {
    return Math.min(
      59,
      Math.max(
        0,
        source?.role === 'official'
          ? 40
          : 15
      )
    );
  }

  let score = 0;

  /*
    Official source.
  */
  if (
    source?.role === 'official'
  ) {
    score += 25;
  }
  else {
    score += 5;
  }

  /*
    Strong discovery evidence.
  */
  if (
    hasStrongSourceEvidence(
      candidate
    )
  ) {
    score += 15;
  }

  /*
    Specific title.
  */
  if (
    hasSpecificTitle(
      candidate
    )
  ) {
    score += 10;
  }

  /*
    Official URL.
  */
  if (
    candidate?.official_url
  ) {
    score += 10;
  }

  /*
    Recruitment notification.
  */
  if (
    JOB_TYPES.has(
      candidate?.type
    ) &&
    candidate?.notification_url &&
    isPdfUrl(
      candidate.notification_url
    ) &&
    looksRecruitmentPdf(
      candidate.notification_url,
      candidate.title
    )
  ) {
    score += 20;
  }

  /*
    Real application page.
  */
  if (
    JOB_TYPES.has(
      candidate?.type
    ) &&
    candidate?.apply_url &&
    !isPdfUrl(
      candidate.apply_url
    ) &&
    !looksGenericPage(
      candidate.apply_url
    ) &&
    !looksGenericCareerPage(
      candidate.apply_url,
      candidate.title
    )
  ) {
    score += 20;
  }

  /*
    Useful job details.
  */
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
    Category-specific evidence.
  */
  if (
    candidate?.type === 'admit_card' &&
    looksAdmitEvidence(candidate)
  ) {
    score += 8;
  }

  if (
    candidate?.type === 'result' &&
    looksResultEvidence(candidate)
  ) {
    score += 8;
  }

  if (
    candidate?.type === 'answer_key' &&
    looksAnswerKeyEvidence(candidate)
  ) {
    score += 8;
  }

  if (
    candidate?.type === 'syllabus' &&
    looksSyllabusEvidence(candidate)
  ) {
    score += 6;
  }

  if (
    candidate?.type === 'admission' &&
    looksAdmissionEvidence(candidate)
  ) {
    score += 6;
  }

  /*
    Warnings reduce confidence.
  */
  score -=
    Math.min(
      10,
      (
        validation?.warnings?.length ||
        0
      ) * 2
    );

  return Math.max(
    0,
    Math.min(
      100,
      score
    )
  );
}


/* -------------------------------------------------------------------------- */
/* Final verification                                                         */
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
    Stable fingerprint.
    Volatile discovery fields are intentionally
    excluded so that the same item does not create
    fake revisions.
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

    official_url:
      normalizeUrl(
        candidate?.official_url
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
    Automatic publication requires:
      - complete validation
      - confidence >= 85
      - supported type
      - official source
  */
  const autoPublishEligible =
    validation.ok &&
    source?.role === 'official' &&
    VALID_TYPES.has(
      candidate?.type
    ) &&
    confidence >= 85;

  return {
    ...validation,

    fingerprint,

    confidence,

    autoPublishEligible
  };
        }
