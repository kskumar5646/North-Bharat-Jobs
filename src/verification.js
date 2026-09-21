/*
  North Bharat Jobs
  Strict verification engine

  Compatible with:
    - sources.js
    - monitor.js
    - D1 verification flow

  IMPORTANT RULES
  ----------------
  JOB / RECRUITMENT
    - Official source required
    - Real recruitment notification PDF required
    - Real apply URL required
    - Notification and apply URLs must be different
    - Generic/career/home/RTI/policy PDFs are rejected

  ADMIT CARD
    - Official source required
    - Admit-card evidence required
    - Apply URL NOT required

  RESULT
    - Official source required
    - Result evidence required
    - Apply URL NOT required

  ANSWER KEY
    - Official source required
    - Answer-key evidence required
    - Apply URL NOT required

  SYLLABUS
    - Official source required
    - Syllabus evidence required

  ADMISSION
    - Official source required
    - Admission/entrance evidence required

  SCHOLARSHIP
    - Official source required
    - Scholarship evidence required

  NEVER AUTO-PUBLISH
    - Home pages
    - Organisation-only pages
    - RTI
    - Policy
    - Forms
    - Affidavit
    - Certificate
    - Tender
    - Annual report
    - Generic recruitment pages
    - Old unrelated years
*/

const CURRENT_YEAR = new Date().getUTCFullYear();
const PREVIOUS_YEAR = CURRENT_YEAR - 1;

/* -------------------------------------------------------
   VALID TYPES
------------------------------------------------------- */

export const VALID_TYPES = new Set([
  "job",
  "recruitment",
  "admit_card",
  "result",
  "answer_key",
  "syllabus",
  "admission",
  "scholarship",
]);

const JOB_TYPES = new Set([
  "job",
  "recruitment",
]);

const DOCUMENT_TYPES = new Set([
  "admit_card",
  "result",
  "answer_key",
  "syllabus",
  "admission",
  "scholarship",
]);

/* -------------------------------------------------------
   BASIC HELPERS
------------------------------------------------------- */

function text(value) {
  return String(value ?? "").trim();
}

function lower(value) {
  return text(value).toLowerCase();
}

function normalizeSpaces(value) {
  return text(value).replace(/\s+/g, " ").trim();
}

function safeUrl(value) {
  try {
    return new URL(text(value));
  } catch {
    return null;
  }
}

/* -------------------------------------------------------
   PUBLIC URL HELPERS
   These are exported because sources.js imports them.
------------------------------------------------------- */

export function normalizeUrl(value) {
  const u = safeUrl(value);

  if (!u) {
    return "";
  }

  u.hash = "";

  const removeParams = [
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
  ];

  for (const param of removeParams) {
    u.searchParams.delete(param);
  }

  return u.toString().replace(/\/$/, "");
}

export function isPdfUrl(value) {
  const u = safeUrl(value);

  if (!u) {
    return false;
  }

  const path = decodeURIComponent(
    u.pathname
  ).toLowerCase();

  return (
    path.endsWith(".pdf") ||
    /\/pdf(?:\/|$)/i.test(path) ||
    /document.*pdf/i.test(path)
  );
}

export function sameHostOrAllowed(
  value,
  allowedDomains
) {
  const u = safeUrl(value);

  if (!u) {
    return false;
  }

  const host = u.hostname.toLowerCase();

  const domains = String(
    allowedDomains ?? ""
  )
    .split(/[;,|\s]+/)
    .map(v => v.trim().toLowerCase())
    .filter(Boolean);

  if (!domains.length) {
    return false;
  }

  return domains.some(domain =>
    host === domain ||
    host.endsWith(`.${domain}`)
  );
}

/* -------------------------------------------------------
   INTERNAL URL HELPERS
------------------------------------------------------- */

function isHttpUrl(value) {
  const u = safeUrl(value);

  return (
    !!u &&
    (
      u.protocol === "http:" ||
      u.protocol === "https:"
    )
  );
}

function hostname(value) {
  const u = safeUrl(value);

  return u
    ? u.hostname.toLowerCase()
    : "";
}

function sameUrl(a, b) {
  const ua = safeUrl(a);
  const ub = safeUrl(b);

  if (!ua || !ub) {
    return false;
  }

  ua.hash = "";
  ub.hash = "";

  return (
    ua.toString().replace(/\/$/, "") ===
    ub.toString().replace(/\/$/, "")
  );
}

function urlContains(value, regex) {
  return regex.test(
    decodeURIComponent(
      text(value)
    ).toLowerCase()
  );
}

/* -------------------------------------------------------
   ALLOWED DOMAIN CHECK
------------------------------------------------------- */

function hostnameMatchesAllowed(
  url,
  allowedDomains
) {
  return sameHostOrAllowed(
    url,
    allowedDomains
  );
}

/* -------------------------------------------------------
   YEAR CHECK
------------------------------------------------------- */

function currentOrPreviousYear(value) {
  const s = text(value);

  const years = [
    ...s.matchAll(/\b(20\d{2})\b/g)
  ].map(match =>
    Number(match[1])
  );

  if (!years.length) {
    return true;
  }

  return years.some(year =>
    year === CURRENT_YEAR ||
    year === PREVIOUS_YEAR
  );
}

/* -------------------------------------------------------
   GENERIC / ADMIN PAGE DETECTION
------------------------------------------------------- */

const GENERIC_PAGE_RE = [
  /^home\b/i,
  /^welcome\b/i,
  /^homepage\b/i,

  /^upsc$/i,
  /^ssc$/i,
  /^mpsc$/i,
  /^bpsc$/i,
  /^jpsc$/i,
  /^uppsc$/i,
  /^mp psc$/i,
  /^psc$/i,

  /^recruitment$/i,
  /^recruitment section$/i,
  /^recruitment cases$/i,
  /^recruitment requisition$/i,

  /^career(?:s)?$/i,
  /^careers and recruitment$/i,

  /^latest news$/i,
  /^what'?s new$/i,

  /^notifications?$/i,
  /^advertisements?$/i,
  /^forms?$/i,
  /^downloads?$/i,
  /^important links$/i,
  /^notice board$/i,
  /^notices?$/i,
  /^circulars?$/i,
];

const GENERIC_TITLE_RE = new RegExp(
  [
    "^home\\b",
    "^welcome\\b",
    "^homepage$",

    "^upsc$",
    "^ssc$",
    "^mpsc$",
    "^bpsc$",
    "^jpsc$",
    "^uppsc$",
    "^mp psc$",
    "^psc$",

    "^career[s]?$",
    "^recruitment$",
    "^notification[s]?$",
    "^advertisement[s]?$",
    "^result[s]?$",
    "^answer key$",
    "^admit card$",
    "^syllabus$",
    "^forms?$",
    "^downloads?$",
    "^notice board$",
    "^notices?$",
    "^circulars?$",
  ].join("|"),
  "i"
);

const ADMIN_PAGE_RE =
  /\b(rti|right\s+to\s+information|policy|policies|tender|annual\s+report|affidavit|certificate|proforma|forms?|manual|guidelines?|rules?|terms?|privacy|contact\s+us|about\s+us|organisation|organization|citizen\s+charter|press\s+release)\b/i;

const GENERIC_CAREER_RE =
  /\b(careers?|career\s+opportunities|work\s+with\s+us|join\s+us|employment\s+section)\b/i;
/*
  JavaScript does not support x-mode regex flags.
  Therefore create safe equivalent regexes.
*/

const ADMIN_PAGE_SAFE_RE =
  /\b(rti|right\s+to\s+information|policy|policies|tender|annual\s+report|affidavit|certificate|proforma|forms?|manual|guidelines?|rules?|terms?|privacy|contact\s+us|about\s+us|organisation|organization|citizen\s+charter|press\s+release)\b/i;

const GENERIC_CAREER_SAFE_RE =
  /\b(careers?|career\s+opportunities|work\s+with\s+us|join\s+us|employment\s+section)\b/i;

/* -------------------------------------------------------
   PDF CLASSIFICATION
------------------------------------------------------- */

const NON_NOTIFICATION_PDF_RE =
  /\b(rti|right.?to.?information|policy|policies|affidavit|certificate|proforma|forms?|form\b|syllabus|rules?|manual|guidelines?|annual.?report|tender|office.?order|press.?release|calendar|minutes|agenda|notice\s+board|citizen.?charter|terms|privacy)\b/i;

const RECRUITMENT_PDF_RE =
  /\b(advt|advt\.|advertisement|advert|notification|recruitment|vacancy|vacancies|employment|selection|appointment|engagement|recruit|hiring|exam|examination)\b/i;

const ADMIT_PDF_RE =
  /\b(admit.?card|e.?admit|hall.?ticket|call.?letter|admission.?ticket|download.?admit)\b/i;

const RESULT_PDF_RE =
  /\b(result|written.?result|final.?result|merit|selection.?list|qualified|shortlisted|roll.?number|rank.?list|score.?card)\b/i;

const ANSWER_KEY_PDF_RE =
  /\b(answer.?key|provisional.?answer|final.?answer|response.?key|answer.?sheet|objection)\b/i;

const SYLLABUS_PDF_RE =
  /\b(syllabus|curriculum|exam.?pattern|course.?content|scheme.?of.?examination)\b/i;

const ADMISSION_PDF_RE =
  /\b(admission|entrance|entrance.?exam|prospectus|counselling|counseling|enrolment|enrollment)\b/i;

const SCHOLARSHIP_PDF_RE =
  /\b(scholarship|fellowship|financial.?assistance|stipend)\b/i;

/* -------------------------------------------------------
   CATEGORY SIGNALS
------------------------------------------------------- */

const CATEGORY_SIGNALS = {
  admit_card: [
    /\badmit[\s-]?card\b/i,
    /\be[\s-]?admit\b/i,
    /\bhall[\s-]?ticket\b/i,
    /\bcall[\s-]?letter\b/i,
    /\badmission[\s-]?ticket\b/i,
  ],

  result: [
    /\bresult\b/i,
    /\bwritten[\s-]?result\b/i,
    /\bfinal[\s-]?result\b/i,
    /\bmerit[\s-]?list\b/i,
    /\bselection[\s-]?list\b/i,
    /\bqualified\b/i,
    /\bshortlisted\b/i,
    /\bscore[\s-]?card\b/i,
  ],

  answer_key: [
    /\banswer[\s-]?key\b/i,
    /\bprovisional[\s-]?answer\b/i,
    /\bfinal[\s-]?answer\b/i,
    /\bresponse[\s-]?key\b/i,
    /\banswer[\s-]?sheet\b/i,
    /\bobjection\b/i,
  ],

  syllabus: [
    /\bsyllabus\b/i,
    /\bcurriculum\b/i,
    /\bexam[\s-]?pattern\b/i,
    /\bscheme[\s-]?of[\s-]?examination\b/i,
  ],

  admission: [
    /\badmission\b/i,
    /\bentrance\b/i,
    /\bentrance[\s-]?exam\b/i,
    /\bprospectus\b/i,
    /\bcounselling\b/i,
    /\bcounseling\b/i,
    /\benrolment\b/i,
    /\benrollment\b/i,
  ],

  scholarship: [
    /\bscholarship\b/i,
    /\bfellowship\b/i,
    /\bfinancial[\s-]?assistance\b/i,
    /\bstipend\b/i,
  ],
};

/* -------------------------------------------------------
   APPLY URL
------------------------------------------------------- */

const APPLY_RE =
  /\b(apply|application|registration|register|online.?form|apply.?online|candidate.?login|login|portal)\b/i;

function isLikelyApplyUrl(url) {
  if (!isHttpUrl(url)) {
    return false;
  }

  if (isPdfUrl(url)) {
    return false;
  }

  return APPLY_RE.test(
    decodeURIComponent(
      text(url)
    ).toLowerCase()
  );
}

/* -------------------------------------------------------
   SEARCH TEXT
------------------------------------------------------- */

function candidateSearchText(candidate) {
  return [
    candidate?.title,
    candidate?.description,
    candidate?.eligibility,
    candidate?.qualification,
    candidate?.source_url,
    candidate?.official_url,
    candidate?.notification_url,
    candidate?.apply_url,
    candidate?.canonical_url,
  ]
    .map(text)
    .filter(Boolean)
    .join(" ");
}

/* -------------------------------------------------------
   TITLE VALIDATION
------------------------------------------------------- */

function hasSpecificTitle(candidate) {
  const title =
    normalizeSpaces(
      candidate?.title
    );

  if (!title || title.length < 8) {
    return false;
  }

  if (GENERIC_TITLE_RE.test(title)) {
    return false;
  }

  const org =
    normalizeSpaces(
      candidate?.organization
    );

  if (
    org &&
    title.toLowerCase() ===
      org.toLowerCase()
  ) {
    return false;
  }

  if (
    /^home\s*\|/i.test(title) ||
    /^home\s*-/i.test(title) ||
    /^welcome\s*\|/i.test(title)
  ) {
    return false;
  }

  return true;
}

/* -------------------------------------------------------
   GENERIC / ADMIN VALIDATION
------------------------------------------------------- */

function isGenericOrAdminPage(candidate) {
  const title =
    normalizeSpaces(
      candidate?.title
    );

  const search =
    candidateSearchText(candidate);

  if (
    GENERIC_PAGE_RE.some(
      re => re.test(title)
    )
  ) {
    return true;
  }

  if (
    ADMIN_PAGE_SAFE_RE.test(title)
  ) {
    return true;
  }

  if (
    ADMIN_PAGE_SAFE_RE.test(search) &&
    !RECRUITMENT_PDF_RE.test(search) &&
    !ANSWER_KEY_PDF_RE.test(search) &&
    !RESULT_PDF_RE.test(search) &&
    !ADMIT_PDF_RE.test(search)
  ) {
    return true;
  }

  if (
    GENERIC_CAREER_SAFE_RE.test(title) &&
    !/\b(post|posts|vacancy|vacancies|recruitment|advertisement|notification)\b/i.test(
      search
    )
  ) {
    return true;
  }

  return false;
}

/* -------------------------------------------------------
   EVIDENCE
------------------------------------------------------- */

function getEvidenceScore(candidate) {
  const value =
    Number(
      candidate?._evidence_score
    );

  if (Number.isFinite(value)) {
    return value;
  }

  return 0;
}

function hasStrongSourceEvidence(candidate) {
  return (
    getEvidenceScore(candidate) >= 8
  );
}

function hasCategorySignal(
  candidate,
  type
) {
  const rules =
    CATEGORY_SIGNALS[type];

  if (!rules) {
    return false;
  }

  const search =
    candidateSearchText(candidate);

  return rules.some(
    re => re.test(search)
  );
}

function notificationMatchesCategory(
  candidate,
  type
) {
  const notification =
    text(
      candidate?.notification_url
    );

  if (!notification) {
    return false;
  }

  if (!isPdfUrl(notification)) {
    return false;
  }

  const decoded =
    decodeURIComponent(
      notification
    ).toLowerCase();

  if (
    NON_NOTIFICATION_PDF_RE.test(
      decoded
    )
  ) {
    return false;
  }

  switch (type) {
    case "admit_card":
      return ADMIT_PDF_RE.test(
        decoded
      );

    case "result":
      return RESULT_PDF_RE.test(
        decoded
      );

    case "answer_key":
      return ANSWER_KEY_PDF_RE.test(
        decoded
      );

    case "syllabus":
      return SYLLABUS_PDF_RE.test(
        decoded
      );

    case "admission":
      return ADMISSION_PDF_RE.test(
        decoded
      );

    case "scholarship":
      return SCHOLARSHIP_PDF_RE.test(
        decoded
      );

    default:
      return false;
  }
}

/* -------------------------------------------------------
   OFFICIAL URL VALIDATION
------------------------------------------------------- */

function officialUrlIsValid(candidate) {
  const url =
    candidate?.official_url ||
    candidate?.source_url;

  if (!isHttpUrl(url)) {
    return false;
  }

  const allowed =
    candidate?.allowed_domains ||
    candidate?.source_allowed_domains ||
    candidate?._allowed_domains;

  if (!allowed) {
    return (
      candidate?._official === true ||
      candidate?.authority === "official" ||
      candidate?.source_role === "official"
    );
  }

  return hostnameMatchesAllowed(
    url,
    allowed
  );
}

/* -------------------------------------------------------
   JOB VALIDATION
------------------------------------------------------- */

function validateJobCandidate(
  candidate
) {
  const errors = [];
  const warnings = [];

  const officialUrl =
    candidate?.official_url ||
    candidate?.source_url;

  const notificationUrl =
    candidate?.notification_url;

  const applyUrl =
    candidate?.apply_url;

  if (!isHttpUrl(officialUrl)) {
    errors.push(
      "missing_official_url"
    );
  }

  if (!isPdfUrl(notificationUrl)) {
    errors.push(
      "missing_notification_pdf"
    );
  }

  if (!isLikelyApplyUrl(applyUrl)) {
    errors.push(
      "missing_apply_url"
    );
  }

  if (
    sameUrl(
      notificationUrl,
      applyUrl
    )
  ) {
    errors.push(
      "notification_apply_same_url"
    );
  }

  if (
    sameUrl(
      officialUrl,
      applyUrl
    )
  ) {
    errors.push(
      "official_apply_same_url"
    );
  }

  if (
    isPdfUrl(notificationUrl) &&
    NON_NOTIFICATION_PDF_RE.test(
      decodeURIComponent(
        notificationUrl
      ).toLowerCase()
    )
  ) {
    errors.push(
      "invalid_notification_pdf"
    );
  }

  if (
    isPdfUrl(notificationUrl) &&
    !RECRUITMENT_PDF_RE.test(
      decodeURIComponent(
        notificationUrl
      ).toLowerCase()
    )
  ) {
    errors.push(
      "weak_recruitment_pdf_signal"
    );
  }

  const search =
    candidateSearchText(candidate);

  if (
    !/\b(recruitment|vacancy|vacancies|advertisement|notification|post|posts|employment|selection)\b/i.test(
      search
    )
  ) {
    errors.push(
      "weak_recruitment_signal"
    );
  }

  if (
    !hasSpecificTitle(candidate)
  ) {
    errors.push(
      "generic_title"
    );
  }

  if (
    !currentOrPreviousYear(search)
  ) {
    errors.push(
      "old_year"
    );
  }

  if (
    !hasStrongSourceEvidence(candidate)
  ) {
    errors.push(
      "weak_source_evidence"
    );
  }

  if (
    !officialUrlIsValid(candidate)
  ) {
    errors.push(
      "official_domain_not_verified"
    );
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
  };
}

/* -------------------------------------------------------
   DOCUMENT VALIDATION
------------------------------------------------------- */

function validateDocumentCandidate(
  candidate,
  type
) {
  const errors = [];
  const warnings = [];

  const officialUrl =
    candidate?.official_url ||
    candidate?.source_url;

  const search =
    candidateSearchText(candidate);

  if (!isHttpUrl(officialUrl)) {
    errors.push(
      "missing_official_url"
    );
  }

  if (
    !hasSpecificTitle(candidate)
  ) {
    errors.push(
      "generic_title"
    );
  }

  if (
    isGenericOrAdminPage(candidate)
  ) {
    errors.push(
      "generic_or_admin_page"
    );
  }

  if (
    !currentOrPreviousYear(search)
  ) {
    errors.push(
      "old_year"
    );
  }

  if (
    !hasStrongSourceEvidence(candidate)
  ) {
    errors.push(
      "weak_source_evidence"
    );
  }

  if (
    !officialUrlIsValid(candidate)
  ) {
    errors.push(
      "official_domain_not_verified"
    );
  }

  if (
    !hasCategorySignal(
      candidate,
      type
    )
  ) {
    errors.push(
      `missing_${type}_signal`
    );
  }

  if (
    candidate?.notification_url
  ) {
    if (
      !isPdfUrl(
        candidate.notification_url
      )
    ) {
      errors.push(
        "notification_not_pdf"
      );
    } else if (
      NON_NOTIFICATION_PDF_RE.test(
        decodeURIComponent(
          candidate.notification_url
        ).toLowerCase()
      )
    ) {
      errors.push(
        "non_notification_pdf"
      );
    }
  }

  if (
    candidate?.notification_url
  ) {
    if (
      !notificationMatchesCategory(
        candidate,
        type
      )
    ) {
      warnings.push(
        "notification_filename_not_explicitly_category_named"
      );
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
  };
}

/* -------------------------------------------------------
   MAIN VALIDATION
------------------------------------------------------- */

export function validateCandidate(
  candidate = {}
) {
  const type =
    lower(candidate.type);

  if (
    !VALID_TYPES.has(type)
  ) {
    return {
      ok: false,
      errors: [
        "invalid_type"
      ],
      warnings: [],
      type,
    };
  }

  const baseErrors = [];
  const baseWarnings = [];

  if (
    !text(candidate.title)
  ) {
    baseErrors.push(
      "missing_title"
    );
  }

  if (
    !text(candidate.source_name)
  ) {
    baseErrors.push(
      "missing_source_name"
    );
  }

  if (
    isGenericOrAdminPage(candidate)
  ) {
    baseErrors.push(
      "generic_or_admin_page"
    );
  }

  let result;

  if (
    JOB_TYPES.has(type)
  ) {
    result =
      validateJobCandidate(
        candidate
      );
  } else if (
    DOCUMENT_TYPES.has(type)
  ) {
    result =
      validateDocumentCandidate(
        candidate,
        type
      );
  } else {
    result = {
      ok: false,
      errors: [
        "unsupported_type"
      ],
      warnings: [],
    };
  }

  const errors = [
    ...new Set([
      ...baseErrors,
      ...result.errors,
    ]),
  ];

  const warnings = [
    ...new Set([
      ...baseWarnings,
      ...result.warnings,
    ]),
  ];

  return {
    ok:
      errors.length === 0,

    errors,
    warnings,
    type,
  };
}

/* -------------------------------------------------------
   CONFIDENCE
------------------------------------------------------- */

export function calculateConfidence(
  candidate = {},
  validation = null
) {
  const v =
    validation ||
    validateCandidate(
      candidate
    );

  let score = 0;

  const type =
    lower(candidate.type);

  if (
    candidate?._official === true ||
    candidate?.authority === "official" ||
    candidate?.source_role === "official"
  ) {
    score += 30;
  }

  if (
    officialUrlIsValid(candidate)
  ) {
    score += 20;
  }

  const evidenceScore =
    getEvidenceScore(candidate);

  if (evidenceScore >= 8) {
    score += 15;
  } else if (
    evidenceScore >= 5
  ) {
    score += 8;
  }

  if (
    hasSpecificTitle(candidate)
  ) {
    score += 10;
  }

  if (
    DOCUMENT_TYPES.has(type) &&
    hasCategorySignal(
      candidate,
      type
    )
  ) {
    score += 10;
  }

  if (
    JOB_TYPES.has(type)
  ) {
    if (
      isPdfUrl(
        candidate.notification_url
      )
    ) {
      score += 5;
    }

    if (
      isLikelyApplyUrl(
        candidate.apply_url
      )
    ) {
      score += 10;
    }
  } else {
    if (
      isPdfUrl(
        candidate.notification_url
      )
    ) {
      score += 5;
    }
  }

  /*
    Invalid candidate can never
    reach publish-level score.
  */
  if (!v.ok) {
    return Math.min(
      score,
      79
    );
  }

  return Math.min(
    score,
    100
  );
}

/* -------------------------------------------------------
   VERIFY
------------------------------------------------------- */

export function verifyCandidate(
  candidate = {}
) {
  const validation =
    validateCandidate(
      candidate
    );

  const confidence =
    calculateConfidence(
      candidate,
      validation
    );

  const isOfficial =
    candidate?._official === true ||
    candidate?.authority === "official" ||
    candidate?.source_role === "official";

  const autoPublishEligible =
    validation.ok &&
    isOfficial &&
    confidence >= 85;

  const status =
    autoPublishEligible
      ? "verified"
      : "verification_required";

  return {
    ...candidate,

    type:
      lower(candidate.type),

    verification_status:
      status,

    confidence_score:
      confidence,

    autoPublishEligible,

    _verification: {
      ok:
        validation.ok,

      errors:
        validation.errors,

      warnings:
        validation.warnings,
    },

    _evidence: {
      authority:
        isOfficial
          ? "official"
          : "unknown",

      evidence_score:
        getEvidenceScore(
          candidate
        ),

      category:
        lower(candidate.type),

      verified_at:
        new Date().toISOString(),
    },
  };
}

/* -------------------------------------------------------
   NOTIFICATION KEY
------------------------------------------------------- */

export function canonicalNotificationKey(
  candidate = {}
) {
  const explicit =
    text(
      candidate.notification_key
    );

  if (explicit) {
    return explicit
      .toLowerCase()
      .replace(/\s+/g, " ")
      .trim();
  }

  const source =
    lower(
      candidate.source_name
    );

  const canonical =
    text(
      candidate.canonical_url ||
      candidate.notification_url ||
      candidate.official_url ||
      candidate.source_url
    );

  const title =
    normalizeSpaces(
      candidate.title
    ).toLowerCase();

  if (canonical) {
    try {
      const u =
        new URL(canonical);

      u.hash = "";

      [
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "fbclid",
        "gclid",
      ].forEach(
        param =>
          u.searchParams.delete(
            param
          )
      );

      return (
        `${source}|` +
        u.toString()
          .replace(/\/$/, "")
      );
    } catch {
      // fall through
    }
  }

  return (
    `${source}|${title}`
  );
}

/* -------------------------------------------------------
   STABLE FINGERPRINT
------------------------------------------------------- */

function normalizeUrlForFingerprint(
  value
) {
  return normalizeUrl(
    value
  ).toLowerCase();
}

export function stableFingerprint(
  candidate = {}
) {
  const stable = {
    type:
      lower(candidate.type),

    title:
      normalizeSpaces(
        candidate.title
      ).toLowerCase(),

    organization:
      normalizeSpaces(
        candidate.organization
      ).toLowerCase(),

    category:
      normalizeSpaces(
        candidate.category
      ).toLowerCase(),

    qualification:
      normalizeSpaces(
        candidate.qualification
      ).toLowerCase(),

    vacancies:
      normalizeSpaces(
        candidate.vacancies
      ).toLowerCase(),

    age_limit:
      normalizeSpaces(
        candidate.age_limit
      ).toLowerCase(),

    fee:
      normalizeSpaces(
        candidate.fee
      ).toLowerCase(),

    selection_process:
      normalizeSpaces(
        candidate.selection_process
      ).toLowerCase(),

    salary:
      normalizeSpaces(
        candidate.salary
      ).toLowerCase(),

    application_start:
      normalizeSpaces(
        candidate.application_start
      ).toLowerCase(),

    last_date:
      normalizeSpaces(
        candidate.last_date
      ).toLowerCase(),

    exam_date:
      normalizeSpaces(
        candidate.exam_date
      ).toLowerCase(),

    official_url:
      normalizeUrlForFingerprint(
        candidate.official_url
      ),

    notification_url:
      normalizeUrlForFingerprint(
        candidate.notification_url
      ),

    apply_url:
      normalizeUrlForFingerprint(
        candidate.apply_url
      ),
  };

  return JSON.stringify(
    stable
  );
}

/* -------------------------------------------------------
   AUTO PUBLISH
------------------------------------------------------- */

export function canAutoPublish(
  candidate = {}
) {
  const result =
    verifyCandidate(
      candidate
    );

  return (
    result.autoPublishEligible === true &&
    result.verification_status ===
      "verified"
  );
}

/* -------------------------------------------------------
   DEBUG SUMMARY
------------------------------------------------------- */

export function verificationSummary(
  candidate = {}
) {
  const result =
    verifyCandidate(
      candidate
    );

  return {
    title:
      candidate.title || "",

    type:
      candidate.type || "",

    ok:
      result._verification.ok,

    status:
      result.verification_status,

    confidence_score:
      result.confidence_score,

    errors:
      result._verification.errors,

    warnings:
      result._verification.warnings,
  };
      }
export function slugify(value) {
  return String(value || '')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 180);
}

export async function sha256Hex(value) {
  const text = String(value ?? '');
  const data = new TextEncoder().encode(text);

  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(hashBuffer);

  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}
