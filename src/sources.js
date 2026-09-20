import {
  isPdfUrl,
  normalizeUrl,
  sameHostOrAllowed
} from './verification.js';

/*
  North Bharat Jobs
  Official-source discovery engine

  CORE RULES
  ----------
  1. Never invent URLs.
  2. Official domain alone is NOT job evidence.
  3. A PDF alone is NOT a recruitment notification.
  4. Generic Home / RTI / Syllabus / Policy / Careers pages
     must never become recruitment records.
  5. Recruitment jobs require:
       - real recruitment evidence
       - real notification PDF
       - real application/registration URL
       - distinct URLs
       - official-domain validation
  6. Old application links must not be reused as current jobs.
  7. The stable identity is the official detail page, not the PDF.
     Therefore revised notifications update the same item.
*/

const WORDS = {
  job:
    /\b(recruitment|recruit|vacanc(?:y|ies)|appointment|advertisement|employment\s+notice|job\s+notification|post(?:s)?\s+of|hiring|engagement|selection\s+process|application\s+form)\b/i,

  admit:
    /\b(admit\s*card|hall\s*ticket|call\s*letter|e[-\s]?admit)\b/i,

  result:
    /\b(result|merit|score|selection\s*list|shortlist|final\s*result|provisional\s*result)\b/i,

  answer:
    /\b(answer\s*key|response\s*sheet|answer\s*sheet)\b/i,

  syllabus:
    /\b(syllabus|scheme\s+and\s+syllabus)\b/i,

  admission:
    /\b(admission|entrance|counselling|counseling|entrance\s*test)\b/i,

  scholarship:
    /\bscholarship\b/i,

  update:
    /\b(notice|latest|important|extension|corrigendum|exam\s*date|schedule|public\s*notice|official\s*notice)\b/i
};

/*
  Apply links must contain an actual application/registration signal.

  Generic:
    /careers
    /login
    /home

  are NOT automatically accepted.
*/
const APPLY =
  /\b(apply\s*(online|now|here)|online\s*application|application\s*(form|portal)|registration\s*(link|portal)?|register\s*(online|now)|apply\s*link|online\s*registration)\b/i;

/*
  Notification PDF must contain a recruitment-related signal.

  IMPORTANT:
  A random PDF such as:
    RTI_Policy.pdf
    annual_report.pdf
    syllabus.pdf
    tender.pdf

  must NOT be accepted.
*/
const NOTIFICATION_SIGNAL =
  /\b(notification|advertisement|recruitment|recruitment\s*notice|employment\s*notice|vacancy|vacancies|selection\s*notice|appointment|corrigendum|extension|job\s*notice|employment)\b/i;

/*
  Pages that are almost never individual recruitment detail pages.
*/
const BLOCKED_PAGE =
  /\b(home|homepage|about|contact|feedback|privacy|terms|disclaimer|rti|right\s*to\s*information|syllabus|scheme|tender|procurement|policy|annual\s*report|archive|gallery|photo|press\s*release|login|sign\s*in|careers?|career)\b/i;

/*
  File/path signals which commonly indicate old/static material.
*/
const BLOCKED_FILE =
  /\b(rti|policy|syllabus|curriculum|annual[_-]?report|tender|procurement|minutes|meeting|budget|press[_-]?release)\b/i;

const MAX_LINKS = 220;
const MAX_PAGES = 22;
const MAX_LINKS_PER_PAGE = 150;

const FETCH_TIMEOUT_MS = 12000;

/*
  Do not accept links that clearly contain an old recruitment year.

  Current year is taken from the runtime, so this remains useful
  as the calendar changes.
*/
const CURRENT_YEAR = new Date().getUTCFullYear();
const MIN_ACCEPTABLE_YEAR = CURRENT_YEAR - 1;

/* -------------------------------------------------------------------------- */
/* Text helpers                                                               */
/* -------------------------------------------------------------------------- */

function decodeEntities(value = '') {
  return String(value)
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&#x27;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>');
}

function textOf(html = '') {
  return decodeEntities(
    String(html)
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
      .replace(/<svg[\s\S]*?<\/svg>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
  )
    .replace(/\s+/g, ' ')
    .trim();
}

function cleanTitle(value = '') {
  return textOf(value)
    .replace(/\s+/g, ' ')
    .replace(/^[|:\-–—]+|[|:\-–—]+$/g, '')
    .trim()
    .slice(0, 220);
}

function normalizedText(value = '') {
  return String(value)
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

/* -------------------------------------------------------------------------- */
/* URL helpers                                                                */
/* -------------------------------------------------------------------------- */

function isHttp(value) {
  return Boolean(normalizeUrl(value));
}

function sameUrl(a, b) {
  const x = normalizeUrl(a);
  const y = normalizeUrl(b);

  if (!x || !y) return false;

  return x === y;
}

function urlHasOldYear(url = '') {
  const matches = String(url).match(/\b(19|20)\d{2}\b/g);

  if (!matches?.length) {
    return false;
  }

  return matches.some(year => {
    const y = Number(year);
    return y < MIN_ACCEPTABLE_YEAR;
  });
}

function isBlockedPath(url = '', text = '') {
  const value = normalizedText(`${url} ${text}`);

  /*
    These are strong negative signals.

    A recruitment detail page may contain the word "career"
    somewhere in its content, so this check is primarily used
    against the URL/link itself.
  */
  return BLOCKED_FILE.test(value);
}

function isGenericPage(url = '', text = '') {
  const value = normalizedText(`${url} ${text}`);

  /*
    Generic homepage/root pages.
  */
  try {
    const parsed = new URL(url);

    const path =
      parsed.pathname
        .replace(/\/+/g, '/')
        .replace(/\/$/, '')
        .toLowerCase();

    if (
      path === '' ||
      path === '/' ||
      path === '/index.html' ||
      path === '/index.htm' ||
      path === '/default.aspx' ||
      path === '/default.asp'
    ) {
      return true;
    }
  } catch {
    /* Ignore malformed URL */
  }

  if (BLOCKED_PAGE.test(value)) {
    /*
      Do not reject every page containing "notice".
      Notice can be a legitimate recruitment page.
    */
    if (
      /\b(home|homepage|about|contact|rti|syllabus|policy|tender|procurement|annual\s*report|login|sign\s*in|careers?)\b/i.test(
        value
      )
    ) {
      return true;
    }
  }

  return false;
}

function looksLikeGenericCareerPage(url = '', text = '') {
  const value = normalizedText(`${url} ${text}`);

  return (
    /\bcareers?\b/.test(value) &&
    !/\bapply\b/.test(value) &&
    !/\bapplication\b/.test(value) &&
    !/\bregistration\b/.test(value) &&
    !/\brecruitment\b/.test(value)
  );
}

function looksLikeLoginOnly(url = '', text = '') {
  const value = normalizedText(`${url} ${text}`);

  return (
    /\blogin\b|\bsign[\s-]?in\b/.test(value) &&
    !/\bapplication\b/.test(value) &&
    !/\bregistration\b/.test(value) &&
    !/\bapply\b/.test(value)
  );
}

/* -------------------------------------------------------------------------- */
/* Link parser                                                                */
/* -------------------------------------------------------------------------- */

function linksOf(html, base) {
  const out = [];

  if (!html || !base) return out;

  const re =
    /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

  let match;

  while ((match = re.exec(html)) && out.length < MAX_LINKS) {
    try {
      const rawHref = match[1]?.trim();

      if (!rawHref) continue;

      if (
        /^javascript:/i.test(rawHref) ||
        /^mailto:/i.test(rawHref) ||
        /^tel:/i.test(rawHref) ||
        /^#/i.test(rawHref)
      ) {
        continue;
      }

      const url =
        normalizeUrl(
          new URL(rawHref, base).toString()
        );

      if (!url) continue;

      const text =
        textOf(match[2]).slice(0, 500);

      out.push({
        url,
        text
      });
    } catch {
      /* Ignore malformed links */
    }
  }

  return out;
}

/* -------------------------------------------------------------------------- */
/* Fetch helper                                                               */
/* -------------------------------------------------------------------------- */

async function fetchWithTimeout(url) {
  const controller = new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    FETCH_TIMEOUT_MS
  );

  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      cache: 'no-store',
      signal: controller.signal,
      headers: {
        'User-Agent':
          'NorthBharatJobs/1.0 (+official-source-monitor)',
        Accept:
          'text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.5'
      }
    });

    const contentType =
      response.headers.get('content-type') || '';

    const isTextResponse =
      /text\/html|application\/xhtml\+xml|text\/plain/i.test(
        contentType
      );

    const body =
      isTextResponse
        ? await response.text()
        : '';

    return {
      ok: response.ok,
      status: response.status,
      body,
      contentType,
      finalUrl:
        normalizeUrl(response.url || url) || url,
      retryAfter:
        response.headers.get('retry-after'),
      isPdf:
        /application\/pdf/i.test(contentType) ||
        isPdfUrl(response.url || url)
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      body: '',
      contentType: '',
      finalUrl: url,
      retryAfter: null,
      isPdf: false,
      error: String(error?.message || error)
    };
  } finally {
    clearTimeout(timer);
  }
}

/* -------------------------------------------------------------------------- */
/* Classification                                                             */
/* -------------------------------------------------------------------------- */

function classify(title, body) {
  const combined =
    `${title} ${body.slice(0, 12000)}`;

  if (WORDS.admit.test(combined)) {
    return 'admit_card';
  }

  if (WORDS.result.test(combined)) {
    return 'result';
  }

  if (WORDS.answer.test(combined)) {
    return 'answer_key';
  }

  if (WORDS.syllabus.test(combined)) {
    return 'syllabus';
  }

  if (WORDS.admission.test(combined)) {
    return 'admission';
  }

  if (WORDS.scholarship.test(combined)) {
    return 'scholarship';
  }

  if (WORDS.job.test(combined)) {
    return 'job';
  }

  return 'update';
}

/* -------------------------------------------------------------------------- */
/* Date extraction                                                            */
/* -------------------------------------------------------------------------- */

function extractDate(text, labels) {
  const month =
    '(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)';

  const patterns = [
    new RegExp(
      `(?:${labels})[^\\d]{0,70}(\\d{1,2}[\\/-]\\d{1,2}[\\/-]\\d{2,4})`,
      'i'
    ),

    new RegExp(
      `(?:${labels})[^\\d]{0,70}(\\d{1,2}\\s+${month}\\s+\\d{4})`,
      'i'
    ),

    new RegExp(
      `(?:${labels})[^\\d]{0,70}(${month}\\s+\\d{1,2},?\\s+\\d{4})`,
      'i'
    )
  ];

  for (const pattern of patterns) {
    const match = text.match(pattern);

    if (match?.[1]) {
      return match[1].trim();
    }
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Recruitment evidence                                                      */
/* -------------------------------------------------------------------------- */

function recruitmentEvidence(title, body, links) {
  const titleText =
    normalizedText(title);

  const bodyText =
    normalizedText(body);

  let score = 0;
  const evidence = [];

  if (
    /\brecruitment\b|\brecruit\b|\bvacanc(?:y|ies)\b/.test(
      titleText
    )
  ) {
    score += 3;
    evidence.push('recruitment-title');
  }

  if (
    /\badvertisement\b|\bemployment\s+notice\b|\bjob\s+notification\b/.test(
      titleText
    )
  ) {
    score += 3;
    evidence.push('recruitment-advertisement-title');
  }

  if (
    /\bnumber of posts\b|\bno\.?\s*of posts\b|\btotal posts\b|\bvacanc(?:y|ies)\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('vacancy-or-post-count');
  }

  if (
    /\bonline application\b|\bapplication form\b|\bregistration\b|\bapply online\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('application-signal');
  }

  if (
    /\blast date\b|\bclosing date\b|\bapply by\b|\bdeadline\b|\bclosing\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('last-date');
  }

  if (
    /\beligib(?:ility|le)\b|\bqualification\b|\beducational qualification\b|\bessential qualification\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('eligibility');
  }

  if (
    /\bselection process\b|\bselection procedure\b|\bwritten examination\b|\binterview\b|\bskill test\b/.test(
      bodyText
    )
  ) {
    score += 1;
    evidence.push('selection-process');
  }

  if (
    /\bapplication fee\b|\bexam fee\b|\bprocessing fee\b/.test(
      bodyText
    )
  ) {
    score += 1;
    evidence.push('fee');
  }

  /*
    A PDF counts only when the link itself carries
    recruitment/notification meaning.

    A random PDF does NOT count.
  */
  const hasNotification =
    links.some(link => {
      if (!isPdfUrl(link.url)) {
        return false;
      }

      if (urlHasOldYear(link.url)) {
        return false;
      }

      return NOTIFICATION_SIGNAL.test(
        `${link.text} ${link.url}`
      );
    });

  if (hasNotification) {
    score += 3;
    evidence.push('recruitment-notification-pdf');
  }

  const hasApply =
    links.some(link => {
      if (isPdfUrl(link.url)) {
        return false;
      }

      if (urlHasOldYear(link.url)) {
        return false;
      }

      return APPLY.test(
        `${link.text} ${link.url}`
      );
    });

  if (hasApply) {
    score += 3;
    evidence.push('current-apply-link');
  }

  return {
    score,
    evidence
  };
}

/* -------------------------------------------------------------------------- */
/* Notification selection                                                     */
/* -------------------------------------------------------------------------- */

function findNotificationLink(links, source) {
  for (const link of links) {
    if (!isHttp(link.url)) {
      continue;
    }

    if (
      source?.role === 'official' &&
      !sameHostOrAllowed(
        link.url,
        source.allowed_domains
      )
    ) {
      continue;
    }

    /*
      Must actually be a PDF.
    */
    if (!isPdfUrl(link.url)) {
      continue;
    }

    /*
      Never accept clearly old material.
    */
    if (urlHasOldYear(link.url)) {
      continue;
    }

    /*
      RTI, policy, syllabus, tender etc. are never
      recruitment notifications.
    */
    if (
      isBlockedPath(
        link.url,
        link.text
      )
    ) {
      continue;
    }

    /*
      THIS IS THE IMPORTANT FIX:

      A PDF is not enough.
      The PDF URL/text itself must carry a
      recruitment/notification signal.
    */
    if (
      !NOTIFICATION_SIGNAL.test(
        `${link.text} ${link.url}`
      )
    ) {
      continue;
    }

    return link;
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Apply link selection                                                       */
/* -------------------------------------------------------------------------- */

function findApplyLink(
  links,
  sourceUrl,
  notificationUrl
) {
  for (const link of links) {
    if (!isHttp(link.url)) {
      continue;
    }

    if (isPdfUrl(link.url)) {
      continue;
    }

    if (sameUrl(link.url, sourceUrl)) {
      continue;
    }

    if (
      notificationUrl &&
      sameUrl(link.url, notificationUrl)
    ) {
      continue;
    }

    /*
      Do not use links containing clearly old years.
    */
    if (urlHasOldYear(link.url)) {
      continue;
    }

    const label =
      `${link.text} ${link.url}`;

    if (!APPLY.test(label)) {
      continue;
    }

    if (
      looksLikeGenericCareerPage(
        link.url,
        link.text
      )
    ) {
      continue;
    }

    if (
      looksLikeLoginOnly(
        link.url,
        link.text
      )
    ) {
      continue;
    }

    /*
      Generic blocked paths are not application forms.
    */
    if (
      /\b(home|about|contact|rti|syllabus|policy|tender)\b/i.test(
        link.url
      )
    ) {
      continue;
    }

    return link;
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Candidate creation                                                        */
/* -------------------------------------------------------------------------- */

function makeCandidate(page, source) {
  const titleMatch =
    page.body.match(
      /<title[^>]*>([\s\S]*?)<\/title>/i
    );

  const title =
    cleanTitle(
      titleMatch?.[1] ||
      textOf(page.body).slice(0, 220)
    );

  const body =
    textOf(page.body).slice(0, 18000);

  const sourceUrl =
    normalizeUrl(
      page.finalUrl ||
      page.url
    );

  if (!sourceUrl || !title) {
    return null;
  }

  /*
    A generic page must never become an item.
  */
  if (
    isGenericPage(
      sourceUrl,
      title
    )
  ) {
    return null;
  }

  /*
    Clearly blocked URL/file paths are ignored.
  */
  if (
    isBlockedPath(
      sourceUrl,
      title
    )
  ) {
    return null;
  }

  /*
    Do not turn old static pages into current items.
  */
  if (
    urlHasOldYear(sourceUrl)
  ) {
    return null;
  }

  const links =
    linksOf(
      page.body,
      page.finalUrl || page.url
    ).slice(
      0,
      MAX_LINKS_PER_PAGE
    );

  const notification =
    findNotificationLink(
      links,
      source
    );

  const apply =
    findApplyLink(
      links,
      sourceUrl,
      notification?.url || null
    );

  const type =
    classify(
      title,
      body
    );

  const evidence =
    recruitmentEvidence(
      title,
      body,
      links
    );

  /*
    ------------------------------------------------------------
    RECRUITMENT GATE
    ------------------------------------------------------------

    A recruitment candidate must have:

      1. Strong recruitment evidence
      2. Recruitment notification PDF
      3. Current apply/registration URL
      4. Three distinct URLs
      5. Official domain
    */
  if (type === 'job') {
    const strongEvidence =
      evidence.score >= 8;

    if (!strongEvidence) {
      return null;
    }

    if (!notification?.url) {
      return null;
    }

    if (!apply?.url) {
      return null;
    }

    if (
      sameUrl(
        sourceUrl,
        notification.url
      ) ||
      sameUrl(
        sourceUrl,
        apply.url
      ) ||
      sameUrl(
        notification.url,
        apply.url
      )
    ) {
      return null;
    }

    if (
      source.role === 'official' &&
      !sameHostOrAllowed(
        sourceUrl,
        source.allowed_domains
      )
    ) {
      return null;
    }
  }

  /*
    Only create non-job public records when
    they have a meaningful category signal.
  */
  if (
    type !== 'job' &&
    type !== 'admit_card' &&
    type !== 'result' &&
    type !== 'answer_key' &&
    type !== 'syllabus' &&
    type !== 'admission' &&
    type !== 'scholarship'
  ) {
    return null;
  }

  /*
    Official URL.
  */
  const officialUrl =
    source.role === 'official'
      ? sourceUrl
      : null;

  /*
    Stable identity:
      source ID + canonical official detail page.

    PDF changes do not create a new recruitment.
    The existing item can be updated.
  */
  const canonicalPage =
    sourceUrl;

  return {
    type,
    title,

    organization:
      source.name,

    category:
      type,

    description:
      body.slice(0, 5000),

    eligibility: null,
    qualification: null,

    vacancies: null,
    age_limit: null,
    age_relaxation: null,

    fee: null,

    selection_process: null,
    salary: null,

    application_start:
      extractDate(
        body,
        '(?:application|registration|online application).*?(?:start|from|begins?)'
      ),

    last_date:
      extractDate(
        body,
        '(?:last date|closing date|apply by|deadline|application.*?ends?)'
      ),

    exam_date:
      extractDate(
        body,
        '(?:exam date|examination date|written exam|test date)'
      ),

    how_to_apply: null,
    important_dates: null,

    official_url:
      officialUrl,

    apply_url:
      apply?.url || null,

    notification_url:
      notification?.url || null,

    source_url:
      sourceUrl,

    source_name:
      source.name,

    source_id:
      source.id,

    canonical_url:
      canonicalPage,

    notification_key:
      `${source.id}|${canonicalPage}`,

    _source_role:
      source.role,

    _evidence_score:
      evidence.score,

    _evidence:
      evidence.evidence,

    _links:
      links.slice(0, 25)
  };
}

/* -------------------------------------------------------------------------- */
/* Source discovery                                                          */
/* -------------------------------------------------------------------------- */

export async function discoverFromSource(source) {
  if (!source?.base_url) {
    throw new Error(
      'Source base URL missing'
    );
  }

  const home =
    await fetchWithTimeout(
      source.base_url
    );

  if (!home.ok) {
    throw Object.assign(
      new Error(
        `HTTP ${home.status || 'fetch-error'}`
      ),
      {
        status:
          home.status,
        retryAfter:
          home.retryAfter
      }
    );
  }

  const homeIsHtml =
    /text\/html|application\/xhtml\+xml/i.test(
      home.contentType || ''
    ) ||
    /<html[\s>]/i.test(
      home.body.slice(0, 5000)
    );

  if (!homeIsHtml) {
    throw Object.assign(
      new Error(
        'Security or unsupported content response'
      ),
      {
        status:
          home.status
      }
    );
  }

  const all =
    linksOf(
      home.body,
      home.finalUrl ||
      source.base_url
    ).filter(link =>
      sameHostOrAllowed(
        link.url,
        source.allowed_domains
      )
    );

  /*
    Select useful links from the source homepage.

    We deliberately do NOT use every link.
  */
  const selected =
    all
      .filter(link => {
        const text =
          `${link.text} ${link.url}`;

        if (
          isGenericPage(
            link.url,
            link.text
          )
        ) {
          return false;
        }

        if (
          isBlockedPath(
            link.url,
            link.text
          )
        ) {
          return false;
        }

        if (
          urlHasOldYear(
            link.url
          )
        ) {
          return false;
        }

        return (
          WORDS.job.test(text) ||
          WORDS.admit.test(text) ||
          WORDS.result.test(text) ||
          WORDS.answer.test(text) ||
          WORDS.syllabus.test(text) ||
          WORDS.admission.test(text) ||
          WORDS.scholarship.test(text)
        );
      })
      .slice(
        0,
        MAX_PAGES
      );

  /*
    IMPORTANT:
    Homepage itself is NOT converted into a candidate.

    Previously this was one of the reasons
    "Home | UPPSC" became a record.
  */
  const pages = [];

  for (const link of selected) {
    if (
      pages.length >= MAX_PAGES
    ) {
      break;
    }

    if (
      sameUrl(
        link.url,
        home.finalUrl ||
        source.base_url
      )
    ) {
      continue;
    }

    const response =
      await fetchWithTimeout(
        link.url
      );

    const isHtml =
      /text\/html|application\/xhtml\+xml/i.test(
        response.contentType || ''
      ) ||
      /<html[\s>]/i.test(
        response.body.slice(0, 3000)
      );

    if (
      response.ok &&
      isHtml &&
      response.body
    ) {
      pages.push({
        url:
          link.url,

        body:
          response.body,

        finalUrl:
          response.finalUrl ||
          link.url,

        isHome:
          false
      });
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Candidate generation                                                   */
  /* ---------------------------------------------------------------------- */

  const seen =
    new Set();

  const candidates =
    [];

  for (const page of pages) {
    const candidate =
      makeCandidate(
        page,
        source
      );

    if (!candidate) {
      continue;
    }

    const pageKey =
      normalizeUrl(
        candidate.canonical_url ||
        candidate.source_url
      );

    if (
      !pageKey ||
      seen.has(pageKey)
    ) {
      continue;
    }

    seen.add(pageKey);

    candidates.push(
      candidate
    );
  }

  return candidates;
}

/* -------------------------------------------------------------------------- */
/* Portal fallback                                                            */
/* -------------------------------------------------------------------------- */

export async function discoverPortal(source) {
  return discoverFromSource(
    source
  );
      }
