/*
  North Bharat Jobs
  Official-source verification engine

  IMPORTANT:
  - Never invent URLs.
  - Official source is authoritative.
  - Recruitment/job items require:
      1. Official URL
      2. Notification PDF URL
      3. Apply URL
  - Notification and Apply URLs must be distinct.
  - PDF URL must actually look like a PDF.
  - Generic/home/RTI/policy/careers pages are not automatically jobs.
  - Existing published items are preserved by monitor.js.
*/

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

const RECRUITMENT_TYPES = new Set([
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

const GENERIC_TITLE_PATTERNS = [
  /^home$/i,
  /^homepage$/i,
  /^welcome/i,
  /^about us$/i,
  /^contact us$/i,
  /^login$/i,
  /^sign in$/i,
  /^careers?$/i,
  /^recruitment$/i,
  /^notifications?$/i,
  /^notices?$/i,
  /^circulars?$/i,
  /^downloads?$/i,
  /^important links$/i,
  /^links$/i,
  /^sitemap$/i,
  /^privacy/i,
  /^terms/i,
  /^disclaimer/i,
];

const GENERIC_CONTENT_PATTERNS = [
  /\brti\b/i,
  /\bright to information\b/i,
  /\bprivacy policy\b/i,
  /\bterms (and|&) conditions\b/i,
  /\baccessibility\b/i,
  /\bcontact us\b/i,
  /\bgrievance\b/i,
  /\btender\b/i,
  /\bauction\b/i,
  /\bpolicy\b/i,
  /\bannual report\b/i,
];

const ADMINISTRATIVE_PATTERNS = [
  /\badministrative\b/i,
  /\badministration\b/i,
  /\boffice\s+order\b/i,
  /\boffice\s+memorandum\b/i,
  /\bmemorandum\b/i,
  /\brti\b/i,
  /\bpolicy\b/i,
  /\bpolicies\b/i,
  /\bprocedure\b/i,
  /\bguidelines?\b/i,
  /\bminutes\b/i,
  /\bannual\s+report\b/i,
  /\bfinancial\s+statement\b/i,
  /\bpress\s+release\b/i,
  /\btender\b/i,
  /\bprocurement\b/i,
  /\bvendor\b/i,
  /\bcustomer\s+care\b/i,
  /\bcitizen\s+charter\b/i
];

const STRONG_TYPE_PATTERNS = {
  job: [
    /\brecruitment\b/i, /\brecruitment\s+(?:notice|notification)\b/i,
    /\bvacanc(?:y|ies)\b/i, /\bemployment\s+notice\b/i,
    /\bdirect\s+recruitment\b/i, /\bselection\s+post\b/i,
    /\badvertisement\s+(?:for\s+)?recruitment\b/i,
    /\bengagement\s+of\b/i
  ],
  answer_key: [
    /\banswer\s*key\b/i, /\bprovisional\s+answer\s*key\b/i,
    /\bfinal\s+answer\s*key\b/i
  ],
  result: [
    /\bfinal\s+result\b/i, /\bexam\s+result\b/i,
    /\bresult\s+(?:of|for)\b/i, /\bmerit\s+list\b/i,
    /\bselection\s+list\b/i, /\bscore\s*card\b/i
  ],
  admit_card: [
    /\badmit\s*card\b/i, /\bhall\s*ticket\b/i,
    /\bcall\s+letter\b/i
  ],
  syllabus: [
    /\bsyllabus\b/i, /\bexam\s+pattern\b/i,
    /\bscheme\s+of\s+examination\b/i
  ]
};

const RECRUITMENT_TITLE_PATTERNS = [
  /\brecruitment\b/i,
  /\bvacanc(?:y|ies)\b/i,
  /\bappointment\b/i,
  /\bselection\b/i,
  /\bengagement\b/i,
  /\bhiring\b/i,
  /\bapply\b/i,
  /\bposts?\b/i,
  /\bgroup[- ]?[abc]\b/i,
  /\bconstable\b/i,
  /\bclerk\b/i,
  /\bassistant\b/i,
  /\bengineer\b/i,
  /\bteacher\b/i,
  /\bofficer\b/i,
  /\bprofessor\b/i,
  /\blecturer\b/i,
  /\bapprentice\b/i,
  /\btrainee\b/i,
  /\bmanager\b/i,
  /\btechnician\b/i,
];

const DOCUMENT_TITLE_PATTERNS = {
  admit_card: [
    /\badmit\s*card\b/i,
    /\bhall\s*ticket\b/i,
    /\bcall\s*letter\b/i,
    /\bdownload\s*letter\b/i,
  ],

  result: [
    /\bresult\b/i,
    /\bmerit\s*list\b/i,
    /\bselected\s*candidates?\b/i,
    /\bselection\s*list\b/i,
    /\bfinal\s*list\b/i,
    /\bscore\s*card\b/i,
  ],

  answer_key: [
    /\banswer\s*key\b/i,
    /\banswer\s*sheet\b/i,
    /\bprovisional\s*key\b/i,
    /\bfinal\s*key\b/i,
  ],

  syllabus: [
    /\bsyllabus\b/i,
    /\bcurriculum\b/i,
    /\bexam\s*pattern\b/i,
  ],

  admission: [
    /\badmission\b/i,
    /\bentrance\b/i,
    /\bcounselling\b/i,
    /\bcounseling\b/i,
    /\benrollment\b/i,
    /\benrolment\b/i,
  ],

  scholarship: [
    /\bscholarship\b/i,
    /\bfellowship\b/i,
    /\bstipend\b/i,
  ],
};

function text(value) {
  return String(value ?? "").trim();
}

function lower(value) {
  return text(value).toLowerCase();
}

function cleanUrl(value) {
  return text(value);
}

function isHttpUrl(value) {
  try {
    const url = new URL(value);
    return (
      url.protocol === "http:" ||
      url.protocol === "https:"
    );
  } catch {
    return false;
  }
}

export function normalizeUrl(value) {
  const raw = cleanUrl(value);

  if (!raw) {
    return "";
  }

  try {
    const url = new URL(raw);

    url.hash = "";

    if (
      url.pathname.length > 1 &&
      url.pathname.endsWith("/")
    ) {
      url.pathname =
        url.pathname.replace(/\/+$/, "");
    }

    const trackingParams = [
      "utm_source",
      "utm_medium",
      "utm_campaign",
      "utm_term",
      "utm_content",
      "fbclid",
      "gclid",
    ];

    for (const param of trackingParams) {
      url.searchParams.delete(param);
    }

    return url.toString();
  } catch {
    return raw;
  }
}

export function isPdfUrl(value) {
  const url = cleanUrl(value);

  if (!url) {
    return false;
  }

  try {
    const parsed = new URL(url);

    const path =
      parsed.pathname.toLowerCase();

    if (path.endsWith(".pdf")) {
      return true;
    }

    const query =
      parsed.search.toLowerCase();

    if (
      /[?&](file|document|doc|download)=.*\.pdf\b/i.test(
        query
      )
    ) {
      return true;
    }

    return false;
  } catch {
    return /\.pdf(?:$|[?#])/i.test(url);
  }
}

export function sameHostOrAllowed(
  value,
  allowedDomains = ""
) {
  const raw = cleanUrl(value);

  if (!raw || !isHttpUrl(raw)) {
    return false;
  }

  let hostname = "";

  try {
    hostname =
      new URL(raw).hostname
        .toLowerCase()
        .replace(/^www\./, "");
  } catch {
    return false;
  }

  const domains = String(
    allowedDomains ?? ""
  )
    .split(/[;,|\s]+/)
    .map((item) =>
      item
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, "")
        .replace(/^www\./, "")
        .replace(/\/.*$/, "")
    )
    .filter(Boolean);

  if (!domains.length) {
    return false;
  }

  return domains.some((domain) => {
    return (
      hostname === domain ||
      hostname.endsWith("." + domain)
    );
  });
}

function hasSpecificTitle(title) {
  const value = text(title);

  if (!value) {
    return false;
  }

  if (value.length < 8) {
    return false;
  }

  if (
    GENERIC_TITLE_PATTERNS.some(
      (pattern) =>
        pattern.test(value)
    )
  ) {
    return false;
  }

  return true;
}

function hasAdministrativeContent(candidate) {
  const combined = [
    candidate?.title,
    candidate?.description,
    candidate?.category,
    candidate?.source_url,
    candidate?.official_url
  ].map(text).filter(Boolean).join(" ");

  return ADMINISTRATIVE_PATTERNS.some(
    pattern => pattern.test(combined)
  );
}

function hasGenericContent(candidate) {
  const combined = [
    candidate?.title,
    candidate?.description,
    candidate?.category,
    candidate?.source_url,
    candidate?.official_url,
  ]
    .map(text)
    .filter(Boolean)
    .join(" ");

  return GENERIC_CONTENT_PATTERNS.some(
    (pattern) => pattern.test(combined)
  );
}

function hasStrongTypeSignal(candidate) {
  const type = lower(candidate?.type);
  const title = text(candidate?.title);
  const patterns = STRONG_TYPE_PATTERNS[type] || [];
  return patterns.some(pattern => pattern.test(title));
}

function hasConsistentDates(candidate) {
  const parse = value => {
    const raw = text(value);
    if (!raw) return null;
    const m = raw.match(/^(\d{1,2})[\/-](\d{1,2})[\/-](20\d{2})$/);
    if (m) {
      const d = new Date(Date.UTC(Number(m[3]), Number(m[2]) - 1, Number(m[1])));
      return Number.isNaN(d.getTime()) ? null : d;
    }
    const d = new Date(raw);
    return Number.isNaN(d.getTime()) ? null : d;
  };
  const start = parse(candidate?.application_start);
  const last = parse(candidate?.last_date);
  const exam = parse(candidate?.exam_date);
  if (start && last && last < start) return false;
  if (start && exam && exam < start) return false;
  return true;
}

function hasCurrentYearSignal(candidate) {
  const currentYear =
    new Date().getUTCFullYear();

  const previousYear =
    currentYear - 1;

  const combined = [
    candidate?.title,
    candidate?.description,
    candidate?.qualification,
    candidate?.eligibility,
    candidate?.important_dates,
    candidate?.application_start,
    candidate?.last_date,
    candidate?.exam_date,
    candidate?.notification_url,
    candidate?.apply_url,
    candidate?.official_url,
  ]
    .map(text)
    .join(" ");

  return (
    combined.includes(String(currentYear)) ||
    combined.includes(String(previousYear))
  );
}

function hasStrongRecruitmentSignal(candidate) {
  const combined = [
    candidate?.title,
    candidate?.description,
    candidate?.category,
    candidate?.qualification,
    candidate?.eligibility,
    candidate?.vacancies,
    candidate?.selection_process,
    candidate?.how_to_apply,
    candidate?.important_dates,
  ]
    .map(text)
    .join(" ");

  return RECRUITMENT_TITLE_PATTERNS.some(
    (pattern) =>
      pattern.test(combined)
  );
}

function hasDocumentSignal(candidate) {
  const type =
    lower(candidate?.type);

  const title =
    text(candidate?.title);

  const patterns =
    DOCUMENT_TITLE_PATTERNS[type] || [];

  return patterns.some(
    (pattern) =>
      pattern.test(title)
  );
}

function hasDateOrExamSignal(candidate) {
  return Boolean(
    text(candidate?.last_date) ||
    text(candidate?.application_start) ||
    text(candidate?.exam_date) ||
    text(candidate?.important_dates)
  );
}

function hasApplicationSignal(candidate) {
  const combined = [
    candidate?.title,
    candidate?.description,
    candidate?.how_to_apply,
    candidate?.apply_url,
    candidate?.important_dates,
  ]
    .map(text)
    .join(" ");

  return (
    /\bapply\b/i.test(combined) ||
    /\bonline\b/i.test(combined) ||
    /\bapplication\b/i.test(combined)
  );
}

function isOfficialCandidate(candidate) {
  return Boolean(
    candidate?._official === true ||
    candidate?.authority === "official" ||
    candidate?.source_role === "official" ||
    candidate?.role === "official"
  );
}

function getAllowedDomains(candidate) {
  return [
    candidate?.allowed_domains,
    candidate?.source_allowed_domains,
    candidate?.official_domain,
    candidate?.domain,
  ]
    .map(text)
    .filter(Boolean)
    .join(";");
}

export function validateCandidate(
  candidate = {}
) {
  const errors = [];
  const warnings = [];

  const type =
    lower(candidate.type);

  const title =
    text(candidate.title);

  const officialUrl =
    normalizeUrl(candidate.official_url);

  const notificationUrl =
    normalizeUrl(candidate.notification_url);

  const applyUrl =
    normalizeUrl(candidate.apply_url);

  const sourceUrl =
    normalizeUrl(candidate.source_url);

  if (!VALID_TYPES.has(type)) {
    errors.push(
      "Invalid or missing item type."
    );
  }

  if (!hasSpecificTitle(title)) {
    errors.push(
      "Title is missing, too generic, or too short."
    );
  }

  if (
    officialUrl &&
    !isHttpUrl(officialUrl)
  ) {
    errors.push(
      "Official URL is not a valid HTTP/HTTPS URL."
    );
  }

  if (
    notificationUrl &&
    !isHttpUrl(notificationUrl)
  ) {
    errors.push(
      "Notification URL is not a valid HTTP/HTTPS URL."
    );
  }

  if (
    applyUrl &&
    !isHttpUrl(applyUrl)
  ) {
    errors.push(
      "Apply URL is not a valid HTTP/HTTPS URL."
    );
  }

  if (
    sourceUrl &&
    !isHttpUrl(sourceUrl)
  ) {
    errors.push(
      "Source URL is not a valid HTTP/HTTPS URL."
    );
  }

  if (!officialUrl) {
    errors.push(
      "Official URL is required."
    );
  }

  const allowedDomains =
    getAllowedDomains(candidate);

  if (
    allowedDomains &&
    officialUrl &&
    !sameHostOrAllowed(
      officialUrl,
      allowedDomains
    )
  ) {
    errors.push(
      "Official URL is outside the allowed official domain."
    );
  }

  if (hasAdministrativeContent(candidate) &&
      !(RECRUITMENT_TYPES.has(type) && hasStrongTypeSignal(candidate))) {
    errors.push("Administrative/policy content is not a publishable update.");
  }

  if (!hasConsistentDates(candidate)) {
    errors.push("Application, last-date, or exam-date values are inconsistent.");
  }

  if (RECRUITMENT_TYPES.has(type)) {
    if (!hasStrongTypeSignal(candidate)) {
      errors.push("Job title lacks a strong recruitment signal.");
    }
    if (!notificationUrl) {
      errors.push(
        "Recruitment requires a notification PDF URL."
      );
    }

    if (!applyUrl) {
      errors.push(
        "Recruitment requires an Apply Online URL."
      );
    }

    if (
      notificationUrl &&
      !isPdfUrl(notificationUrl)
    ) {
      errors.push(
        "Notification URL must be a PDF URL."
      );
    }

    if (
      notificationUrl &&
      applyUrl &&
      normalizeUrl(notificationUrl) ===
        normalizeUrl(applyUrl)
    ) {
      errors.push(
        "Notification URL and Apply URL must be different."
      );
    }

    if (
      applyUrl &&
      isPdfUrl(applyUrl)
    ) {
      errors.push(
        "Apply URL must be a real non-PDF application page."
      );
    }

    if (!hasStrongRecruitmentSignal(candidate)) {
      errors.push(
        "No strong recruitment/job signal found."
      );
    }

    if (!hasCurrentYearSignal(candidate)) {
      warnings.push(
        "No current or previous year signal found."
      );
    }

    if (!hasApplicationSignal(candidate)) {
      warnings.push(
        "No strong application signal found."
      );
    }
  }

  if (DOCUMENT_TYPES.has(type)) {
    if (!hasStrongTypeSignal(candidate) && !hasDocumentSignal(candidate)) {
      errors.push("Document title lacks a strong signal for its declared type.");
    }
    if (!hasDocumentSignal(candidate)) {
      errors.push(
        "Title does not contain a strong signal for this document type."
      );
    }

    if (
      hasGenericContent(candidate)
    ) {
      warnings.push(
        "Candidate contains generic/admin content signals."
      );
    }

    if (!hasCurrentYearSignal(candidate)) {
      warnings.push(
        "No current or previous year signal found."
      );
    }
  }

  if (
    hasGenericContent(candidate)
  ) {
    warnings.push(
      "Generic/non-recruitment content signal detected."
    );
  }

  if (
    RECRUITMENT_TYPES.has(type) &&
    !isOfficialCandidate(candidate)
  ) {
    warnings.push(
      "Candidate is not explicitly marked as official."
    );
  }

  return {
    ok: errors.length === 0,
    errors,
    warnings,
  };
}

function getEvidenceScore(
  candidate = {}
) {
  let score = 0;

  if (isOfficialCandidate(candidate)) {
    score += 35;
  }

  if (
    normalizeUrl(candidate.official_url)
  ) {
    score += 10;
  }

  if (
    normalizeUrl(candidate.notification_url)
  ) {
    score += 15;
  }

  if (
    normalizeUrl(candidate.apply_url)
  ) {
    score += 15;
  }

  if (
    isPdfUrl(candidate.notification_url)
  ) {
    score += 10;
  }

  if (
    hasSpecificTitle(candidate.title)
  ) {
    score += 5;
  }

  if (
    hasCurrentYearSignal(candidate)
  ) {
    score += 5;
  }

  if (
    hasDateOrExamSignal(candidate)
  ) {
    score += 5;
  }

  return Math.min(score, 100);
}

export function calculateConfidence(
  candidate = {},
  validation = validateCandidate(candidate)
) {
  let score =
    getEvidenceScore(candidate);

  const type =
    lower(candidate.type);

  if (!validation.ok) {
    return Math.min(score, 79);
  }

  if (
    RECRUITMENT_TYPES.has(type)
  ) {
    if (
      !isPdfUrl(
        candidate.notification_url
      )
    ) {
      score -= 20;
    }

    if (
      !candidate.apply_url
    ) {
      score -= 20;
    }

    if (
      candidate.apply_url &&
      isPdfUrl(candidate.apply_url)
    ) {
      score -= 20;
    }

    if (
      normalizeUrl(
        candidate.notification_url
      ) ===
      normalizeUrl(
        candidate.apply_url
      )
    ) {
      score -= 30;
    }
  }

  if (
    hasGenericContent(candidate)
  ) {
    score -= 15;
  }

  if (
    !hasCurrentYearSignal(candidate)
  ) {
    score -= 10;
  }

  return Math.max(
    0,
    Math.min(
      100,
      Math.round(score)
    )
  );
}

export function canAutoPublish(
  candidate = {},
  validation = validateCandidate(candidate)
) {
  const confidence =
    calculateConfidence(
      candidate,
      validation
    );

  return (
    validation.ok === true &&
    isOfficialCandidate(candidate) &&
    confidence >= 85
  );
}

export function verifyCandidate(
  candidate = {}
) {
  const validation =
    validateCandidate(candidate);

  const confidence =
    calculateConfidence(
      candidate,
      validation
    );

  const isOfficial =
    isOfficialCandidate(candidate);

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

    /*
      IMPORTANT:
      monitor.js directly reads:
        verification.ok
        verification.confidence

      Therefore these MUST be top-level.
    */
    ok:
      validation.ok,

    confidence:
      confidence,

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

export function verificationSummary(
  verification = {}
) {
  return {
    ok:
      verification.ok === true,

    confidence:
      Number(
        verification.confidence ?? 0
      ),

    verification_status:
      verification.verification_status ||
      "verification_required",

    errors:
      Array.isArray(
        verification?._verification?.errors
      )
        ? verification._verification.errors
        : [],

    warnings:
      Array.isArray(
        verification?._verification?.warnings
      )
        ? verification._verification.warnings
        : [],

    autoPublishEligible:
      verification.autoPublishEligible === true,
  };
}

export function canonicalNotificationKey(
  candidate = {}
) {
  const type = lower(candidate.type);
  const organization = lower(candidate.organization);
  const title = lower(candidate.title);

  const canonicalUrl = normalizeUrl(candidate.canonical_url);
  const officialUrl = normalizeUrl(candidate.official_url);
  const notificationUrl = normalizeUrl(candidate.notification_url);

  /*
    Identity order:
    1. Recruitment/detail page (stable across date/vacancy revisions).
    2. Official URL.
    3. Notification PDF.
    4. Title fallback.

    A changed PDF/corrigendum must not create a new recruitment when
    the same official detail page remains the canonical identity.
  */
  if (canonicalUrl) {
    return ["canonical", canonicalUrl].join("|");
  }

  if (officialUrl) {
    return ["official", officialUrl].join("|");
  }

  if (notificationUrl) {
    return ["notification", notificationUrl].join("|");
  }

  return [type, organization, title]
    .filter(Boolean)
    .join("|");
}

function stableStringify(value) {
  if (
    value === null ||
    typeof value !== "object"
  ) {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return (
      "[" +
      value
        .map(stableStringify)
        .join(",") +
      "]"
    );
  }

  const keys =
    Object.keys(value)
      .sort();

  return (
    "{" +
    keys
      .map(
        (key) =>
          JSON.stringify(key) +
          ":" +
          stableStringify(value[key])
      )
      .join(",") +
    "}"
  );
}

export function stableFingerprint(
  candidate = {}
) {
  const relevant = {
    type:
      lower(candidate.type),

    title:
      text(candidate.title),

    organization:
      text(candidate.organization),

    category:
      text(candidate.category),

    location:
      text(candidate.location),

    eligibility:
      text(candidate.eligibility),

    qualification:
      text(candidate.qualification),

    vacancies:
      text(candidate.vacancies),

    age_limit:
      text(candidate.age_limit),

    fee:
      text(candidate.fee),

    selection_process:
      text(candidate.selection_process),

    salary:
      text(candidate.salary),

    application_start:
      text(candidate.application_start),

    last_date:
      text(candidate.last_date),

    exam_date:
      text(candidate.exam_date),

    important_dates:
      text(candidate.important_dates),

    official_url:
      normalizeUrl(candidate.official_url),

    apply_url:
      normalizeUrl(candidate.apply_url),

    notification_url:
      normalizeUrl(
        candidate.notification_url
      ),
  };

  return stableStringify(
    relevant
  );
}

export function slugify(
  value
) {
  return text(value)
    .toLowerCase()
    .normalize("NFKD")
    .replace(
      /[\u0300-\u036f]/g,
      ""
    )
    .replace(
      /[^a-z0-9]+/g,
      "-"
    )
    .replace(
      /^-+|-+$/g,
      ""
    )
    .slice(0, 180);
}

export async function sha256Hex(
  value
) {
  const input =
    text(value);

  const data =
    new TextEncoder().encode(
      input
    );

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return Array.from(
    new Uint8Array(digest)
  )
    .map(
      (byte) =>
        byte
          .toString(16)
          .padStart(2, "0")
    )
    .join("");
}
