/*
  North Bharat Jobs
  Official-source discovery engine

  IMPORTANT
  ---------
  - Official source is authoritative.
  - Never invent URLs.
  - Recruitment requires:
      1. official detail page
      2. direct notification PDF
      3. real apply/registration URL
  - Portal data is secondary only.
  - Existing published data is never destroyed by
    temporary/incomplete source scans.

  SSC SPECIAL ADAPTER
  -------------------
  SSC's current website exposes recruitment notices
  through official PDF attachment URLs and may not
  expose all useful notice links in normal homepage
  HTML.

  Therefore:
  - SSC gets a dedicated discovery path.
  - Only real SSC URLs are accepted.
  - PDF URLs are never invented from guessed
    recruitment names.
  - SSC PDFs are discovered from official HTML
    pages and known official attachment references.
*/

import {
  isPdfUrl,
  normalizeUrl,
  sameHostOrAllowed
} from './verification.js';


/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const MAX_LINKS = 300;
const MAX_PAGES = 30;
const MAX_DEPTH = 2;
const MAX_LINKS_PER_PAGE = 180;

const SSC_MAX_PAGES = 45;
const SSC_MAX_LINKS_PER_PAGE = 250;

const FETCH_TIMEOUT_MS = 12000;

const CURRENT_YEAR =
  new Date().getUTCFullYear();

const MIN_ACCEPTABLE_YEAR =
  CURRENT_YEAR - 1;


/* -------------------------------------------------------------------------- */
/* Category signals                                                           */
/* -------------------------------------------------------------------------- */

const CATEGORY_PATTERNS = {
  job: [
    /\brecruitment\b/i,
    /\brecruit\b/i,
    /\bvaccanc(?:y|ies)\b/i,
    /\bappointment\b/i,
    /\badvertisement\b/i,
    /\bemployment\s+notice\b/i,
    /\bjob\s+notification\b/i,
    /\bposts?\b/i,
    /\bhiring\b/i,
    /\bengagement\b/i,
    /\bselection\s+process\b/i,
    /\bapplication\s+form\b/i,
    /\bstaff\s+selection\b/i,
    /\bnotice\s+of\s+recruitment\b/i,
    /\bcareer\s+opportunit(?:y|ies)\b/i
  ],

  admit: [
    /\badmit\s*card\b/i,
    /\bhall\s*ticket\b/i,
    /\be-admit\b/i,
    /\badmission\s+certificate\b/i
  ],

  result: [
    /\bresult\b/i,
    /\bmerit\s+list\b/i,
    /\bselection\s+list\b/i,
    /\bfinal\s+result\b/i
  ],

  answer: [
    /\banswer\s+key\b/i,
    /\banswer\s+sheet\b/i,
    /\bprovisional\s+answer\b/i
  ],

  syllabus: [
    /\bsyllabus\b/i,
    /\bcurriculum\b/i,
    /\bexam\s+pattern\b/i
  ],

  admission: [
    /\badmission\b/i,
    /\bentrance\s+exam\b/i,
    /\bcounselling\b/i,
    /\bcounseling\b/i
  ],

  scholarship: [
    /\bscholarship\b/i,
    /\bfellowship\b/i
  ]
};


const APPLY_PATTERN =
  /\b(
    apply\s*(?:online|now|here|link)?|
    online\s*application|
    application\s*(?:form|portal|link)?|
    registration\s*(?:link|portal|form)?|
    register\s*(?:online|now)?|
    apply\s*link|
    online\s*registration|
    candidate\s*registration|
    candidate\s*login|
    application\s*portal|
    application\s*window
  )\b/i;


const NOTIFICATION_SIGNAL =
  /\b(
    notification|
    advertisement|
    recruitment|
    recruitment\s*notice|
    employment\s*notice|
    vacanc(?:y|ies)|
    selection\s*notice|
    appointment|
    corrigendum|
    extension|
    job\s*notice|
    employment|
    engagement\s*notice|
    detailed\s*advertisement|
    detailed\s*notification|
    notice\s*of\s*recruitment|
    examination\s*notice|
    exam\s*notice
  )\b/i;


/* -------------------------------------------------------------------------- */
/* SSC-specific signals                                                       */
/* -------------------------------------------------------------------------- */

const SSC_NOTICE_PATH =
  /\/api\/attachment\/uploads\/masterData\/NoticeBoards\//i;

const SSC_NOTICE_FILE =
  /\.(?:pdf)(?:[?#].*)?$/i;

const SSC_RECRUITMENT_PATTERN =
  /\b(
    recruitment|
    examination|
    exam|
    selection\s+post|
    combined|
    constable|
    sub[-\s]?inspector|
    junior\s+engineer|
    stenographer|
    multi[-\s]?tasking|
    mts|
    combined\s+graduate|
    cgl|
    combined\s+higher\s+secondary|
    chsl|
    hindi\s+translator|
    translator|
    scientific\s+assistant|
    junior\s+hindi\s+translator|
    data\s+entry|
    ldc|
    jsa|
    gd|
    capf|
    phase[-\s]?\w+
  )\b/i;


const SSC_NON_RECRUITMENT_PATTERN =
  /\b(
    rti|
    right\s+to\s+information|
    policy|
    annual\s+report|
    tender|
    procurement|
    vendor|
    press\s+release|
    budget|
    finance|
    audit|
    result|
    admit\s+card|
    answer\s+key|
    syllabus|
    corrigendum|
    correction|
    notice\s+for\s+option|
    calendar|
    schedule|
    vacancy\s+status
  )\b/i;


/* -------------------------------------------------------------------------- */
/* Pages which must never become public records                               */
/* -------------------------------------------------------------------------- */

const ADMIN_DOCUMENT_PATTERN =
  /\b(
    rti|
    right\s*to\s*information|
    policy|
    policies|
    terms|
    privacy|
    annual\s*report|
    tender|
    tenders|
    procurement|
    vendor|
    circular\s+for\s+vendors|
    press\s+release|
    budget|
    finance|
    audit|
    act|
    rules|
    regulation|
    forms?|
    downloads?|
    gallery|
    archive|
    contact|
    about|
    sitemap|
    feedback|
    grievance|
    citizen\s+charter|
    disclosure|
    eoi|
    expression\s+of\s+interest
  )\b/i;


const GENERIC_TITLE_PATTERN =
  /^(?:home|homepage|welcome|index|about|contact|login|careers?|results?|syllabus|admit\s*card|answer\s*key|scholarship|admission|recruitment|advertisement|notifications?|notices?|latest\s+news|important\s+links?)$/i;


const GENERIC_ORG_TITLE_PATTERN =
  /^(?:home|welcome|about|careers?|results?|syllabus|notifications?|notices?)\s*\|/i;


const BLOCKED_FILE_PATTERN =
  /\.(?:jpg|jpeg|png|gif|svg|webp|ico|css|js|json|xml|zip|rar|mp4|mp3|woff|woff2|ttf|eot)$/i;


const LOGIN_ONLY_PATTERN =
  /\b(
    login|
    sign\s*in|
    candidate\s+login|
    user\s+login|
    forgot\s+password|
    password|
    username
  )\b/i;


/* -------------------------------------------------------------------------- */
/* Text helpers                                                               */
/* -------------------------------------------------------------------------- */

function decodeEntities(value = '') {
  return String(value)
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#x2F;|&#47;/gi, '/');
}


function textOf(html = '') {
  return decodeEntities(
    String(html)
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<noscript[\s\S]*?<\/noscript>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
  )
    .replace(/\s+/g, ' ')
    .trim();
}


function normalizedText(value = '') {
  return String(value)
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}


function compactText(value = '') {
  return normalizedText(value)
    .replace(/[|:;,]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}


function cleanTitle(value = '') {
  return decodeEntities(value)
    .replace(/\s+/g, ' ')
    .replace(/^\s*[-|:]+\s*/, '')
    .replace(/\s*[-|:]+\s*$/, '')
    .trim();
}


/* -------------------------------------------------------------------------- */
/* URL helpers                                                                */
/* -------------------------------------------------------------------------- */

function isHttp(value) {
  return /^https?:\/\//i.test(
    String(value || '')
  );
}


function safeUrl(value, baseUrl = null) {
  try {
    if (!value) {
      return null;
    }

    const raw =
      String(value).trim();

    if (!raw) {
      return null;
    }

    const url =
      baseUrl
        ? new URL(raw, baseUrl)
        : new URL(raw);

    if (
      url.protocol !== 'http:' &&
      url.protocol !== 'https:'
    ) {
      return null;
    }

    return url.href;
  } catch {
    return null;
  }
}


function sameUrl(a, b) {
  if (!a || !b) {
    return false;
  }

  try {
    return normalizeUrl(a) ===
      normalizeUrl(b);
  } catch {
    return String(a) === String(b);
  }
}


function urlHasOldYear(url) {
  const value =
    String(url || '');

  const matches =
    value.match(
      /\b(19\d{2}|20\d{2})\b/g
    );

  if (!matches?.length) {
    return false;
  }

  return matches.some(year =>
    Number(year) <
    MIN_ACCEPTABLE_YEAR
  );
}


function isBlockedPath(url) {
  const value =
    String(url || '').toLowerCase();

  return (
    /\/(?:admin|login|logout|signin|signup|wp-admin)\b/.test(value) ||
    /(?:privacy|terms|cookie|contact-us|feedback|sitemap)\b/.test(value) ||
    BLOCKED_FILE_PATTERN.test(value)
  );
}


function isGenericPage(url, title = '') {
  const value =
    String(url || '');

  if (
    GENERIC_TITLE_PATTERN.test(
      cleanTitle(title)
    )
  ) {
    return true;
  }

  if (
    GENERIC_ORG_TITLE_PATTERN.test(
      cleanTitle(title)
    )
  ) {
    return true;
  }

  if (
    /\/(?:home|about|contact|login|careers?)\/?$/i
      .test(value)
  ) {
    return true;
  }

  return false;
}


function looksLikeGenericCareerPage(
  url,
  title,
  body
) {
  const combined =
    compactText(
      `${url} ${title} ${body.slice(0, 4000)}`
    );

  if (
    !/\bcareer\b|\bcareers\b|\bemployment\b/i
      .test(combined)
  ) {
    return false;
  }

  if (
    /\bapply\b|\bvacancy\b|\brecruitment\b|\badvertisement\b|\bnotification\b/i
      .test(combined)
  ) {
    return false;
  }

  return true;
}


function looksLikeLoginOnly(
  title,
  body,
  url
) {
  const combined =
    compactText(
      `${title} ${body.slice(0, 2500)} ${url}`
    );

  if (
    /application\s+form/i.test(combined)
  ) {
    return false;
  }

  return (
    LOGIN_ONLY_PATTERN.test(combined) &&
    combined.length < 1800
  );
}


/* -------------------------------------------------------------------------- */
/* Title quality                                                              */
/* -------------------------------------------------------------------------- */

function hasSpecificTitle(
  title,
  sourceName = ''
) {
  const value =
    cleanTitle(title);

  if (
    value.length < 8
  ) {
    return false;
  }

  if (
    GENERIC_TITLE_PATTERN.test(value)
  ) {
    return false;
  }

  if (
    GENERIC_ORG_TITLE_PATTERN.test(value)
  ) {
    return false;
  }

  if (
    ADMIN_DOCUMENT_PATTERN.test(value)
  ) {
    return false;
  }

  const identity =
    /\b(
      20\d{2}|
      exam|
      recruitment|
      vacancy|
      vacancies|
      post|
      posts|
      notification|
      advertisement|
      admit|
      hall|
      result|
      merit|
      selection|
      answer|
      syllabus|
      admission|
      scholarship|
      candidate|
      group|
      class|
      officer|
      assistant|
      teacher|
      engineer|
      clerk|
      constable|
      inspector|
      technician|
      staff|
      department|
      course|
      programme|
      program|
      notice|
      corrigendum|
      extension|
      application|
      combined|
      selection\s+post|
      cgl|
      chsl|
      mts|
      capf|
      gd
    )\b/i;

  if (
    identity.test(value)
  ) {
    return true;
  }

  if (
    sourceName &&
    value.toLowerCase()
      .includes(
        String(sourceName).toLowerCase()
      ) &&
    value.length >= 20
  ) {
    return true;
  }

  return false;
}


/* -------------------------------------------------------------------------- */
/* Link extraction                                                            */
/* -------------------------------------------------------------------------- */

function parseLinks(
  html,
  baseUrl
) {
  const links = [];

  const regex =
    /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

  let match;

  while (
    (match = regex.exec(html)) &&
    links.length < MAX_LINKS
  ) {
    const rawHref =
      match[1];

    const rawText =
      match[2];

    const href =
      safeUrl(
        rawHref,
        baseUrl
      );

    if (!href) {
      continue;
    }

    const text =
      cleanTitle(
        textOf(rawText)
      );

    if (
      href.startsWith('javascript:')
    ) {
      continue;
    }

    links.push({
      url: href,
      text,
      htmlText: rawText
    });
  }

  return links;
}


/* -------------------------------------------------------------------------- */
/* Link scoring                                                               */
/* -------------------------------------------------------------------------- */

function linkPriority(
  link,
  pageText = ''
) {
  const value =
    compactText(
      `${link.text} ${link.url}`
    );

  let score = 0;

  if (
    NOTIFICATION_SIGNAL.test(value)
  ) {
    score += 10;
  }

  if (
    APPLY_PATTERN.test(value)
  ) {
    score += 10;
  }

  if (
    isPdfUrl(link.url)
  ) {
    score += 8;
  }

  if (
    /\b20\d{2}\b/.test(value)
  ) {
    score += 3;
  }

  if (
    /\brecruit|vacanc|advertisement|notification|post\b/i
      .test(value)
  ) {
    score += 5;
  }

  if (
    /\badmit|result|answer|syllabus|admission\b/i
      .test(value)
  ) {
    score += 3;
  }

  if (
    ADMIN_DOCUMENT_PATTERN.test(value)
  ) {
    score -= 20;
  }

  if (
    urlHasOldYear(link.url)
  ) {
    score -= 30;
  }

  if (
    pageText &&
    /\brecruitment|vacancy|advertisement|notification\b/i
      .test(pageText)
  ) {
    score += 2;
  }

  return score;
}


/* -------------------------------------------------------------------------- */
/* Crawl-link validation                                                      */
/* -------------------------------------------------------------------------- */

function isUsefulCrawlLink(
  link,
  source,
  currentUrl
) {
  if (!link?.url) {
    return false;
  }

  if (
    !isHttp(link.url)
  ) {
    return false;
  }

  if (
    isBlockedPath(link.url)
  ) {
    return false;
  }

  if (
    urlHasOldYear(link.url)
  ) {
    return false;
  }

  if (
    sameUrl(
      link.url,
      currentUrl
    )
  ) {
    return false;
  }

  try {
    if (
      !sameHostOrAllowed(
        link.url,
        source.allowed_domains,
        source.base_url
      )
    ) {
      return false;
    }
  } catch {
    try {
      const target =
        new URL(link.url);

      const base =
        new URL(source.base_url);

      if (
        target.hostname !==
        base.hostname
      ) {
        return false;
      }
    } catch {
      return false;
    }
  }

  return true;
}


/* -------------------------------------------------------------------------- */
/* Fetch                                                                      */
/* -------------------------------------------------------------------------- */

async function fetchWithTimeout(
  url
) {
  const controller =
    new AbortController();

  const timer =
    setTimeout(
      () => controller.abort(),
      FETCH_TIMEOUT_MS
    );

  try {
    const response =
      await fetch(
        url,
        {
          method: 'GET',
          redirect: 'follow',
          cache: 'no-store',
          signal: controller.signal,
          headers: {
            'User-Agent':
              'NorthBharatJobs/2.0',
            'Accept':
              'text/html,application/xhtml+xml,application/pdf,text/plain,*/*',
            'Accept-Language':
              'en-IN,en;q=0.9'
          }
        }
      );

    const contentType =
      (
        response.headers.get(
          'content-type'
        ) || ''
      ).toLowerCase();

    const finalUrl =
      response.url || url;

    const isPdf =
      contentType.includes(
        'application/pdf'
      ) ||
      isPdfUrl(finalUrl);

    let body = '';

    if (
      !isPdf &&
      (
        contentType.includes('text/html') ||
        contentType.includes('application/xhtml') ||
        contentType.includes('text/plain')
      )
    ) {
      body =
        await response.text();
    }

    const retryAfterHeader =
      response.headers.get(
        'retry-after'
      );

    return {
      ok:
        response.ok,

      status:
        response.status,

      body,

      contentType,

      finalUrl,

      isPdf,

      retryAfter:
        Number(
          retryAfterHeader || 0
        ) || 0
    };

  } catch (error) {
    const wrapped =
      new Error(
        `Fetch failed for ${url}: ${
          error?.message || error
        }`
      );

    wrapped.status =
      Number(
        error?.status || 0
      ) || 0;

    wrapped.retryAfter =
      Number(
        error?.retryAfter || 0
      ) || 0;

    throw wrapped;

  } finally {
    clearTimeout(timer);
  }
}


/* -------------------------------------------------------------------------- */
/* Classification                                                             */
/* -------------------------------------------------------------------------- */

function classify(
  title,
  body,
  links
) {
  const titleText =
    cleanTitle(title);

  const linkText =
    (links || [])
      .map(link => link.text)
      .join(' ');

  const bodyText =
    String(body || '')
      .slice(0, 16000);

  const titleCategory =
    Object.entries(
      CATEGORY_PATTERNS
    )
      .find(([, patterns]) =>
        patterns.some(
          pattern =>
            pattern.test(titleText)
        )
      );

  if (
    titleCategory
  ) {
    return titleCategory[0];
  }

  const linkCategory =
    Object.entries(
      CATEGORY_PATTERNS
    )
      .find(([, patterns]) =>
        patterns.some(
          pattern =>
            pattern.test(linkText)
        )
      );

  if (
    linkCategory
  ) {
    return linkCategory[0];
  }

  const bodyCategory =
    Object.entries(
      CATEGORY_PATTERNS
    )
      .find(([, patterns]) =>
        patterns.some(
          pattern =>
            pattern.test(bodyText)
        )
      );

  return bodyCategory
    ? bodyCategory[0]
    : null;
}


/* -------------------------------------------------------------------------- */
/* Date extraction                                                            */
/* -------------------------------------------------------------------------- */

function extractDate(
  text,
  labels = []
) {
  const source =
    String(text || '');

  const labelPattern =
    labels.length
      ? new RegExp(
          `(?:${labels.join('|')})[^\\n]{0,100}?` +
          `(\\d{1,2}[\\/.-]\\d{1,2}[\\/.-]20\\d{2}|` +
          `\\d{1,2}\\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\s+20\\d{2}|` +
          `(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\s+\\d{1,2},?\\s+20\\d{2})`,
          'i'
        )
      : null;

  if (
    labelPattern
  ) {
    const labelled =
      source.match(
        labelPattern
      );

    if (
      labelled?.[1]
    ) {
      return labelled[1];
    }
  }

  const general =
    source.match(
      /\b\d{1,2}[\/.-]\d{1,2}[\/.-]20\d{2}\b/
    );

  if (
    general?.[0]
  ) {
    return general[0];
  }

  const month =
    source.match(
      /\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+20\d{2}\b/i
    );

  if (
    month?.[0]
  ) {
    return month[0];
  }

  return null;
}


/* -------------------------------------------------------------------------- */
/* Recruitment evidence                                                       */
/* -------------------------------------------------------------------------- */

function recruitmentEvidence(
  title,
  body,
  links
) {
  const titleText =
    compactText(title);

  const bodyText =
    compactText(
      String(body || '')
        .slice(0, 20000)
    );

  const linkText =
    compactText(
      (links || [])
        .map(link =>
          `${link.text} ${link.url}`
        )
        .join(' ')
    );

  let score = 0;

  const evidence = [];

  if (
    /\brecruitment\b|\brecruit\b/i
      .test(titleText)
  ) {
    score += 4;
    evidence.push(
      'recruitment-title'
    );
  }

  if (
    /\badvertisement\b|\bemployment\s+notice\b|\bdetailed\s+advertisement\b/i
      .test(titleText)
  ) {
    score += 4;
    evidence.push(
      'advertisement-title'
    );
  }

  if (
    /\b\d+\s+(?:posts?|vacancies?)\b/i
      .test(bodyText)
  ) {
    score += 2;
    evidence.push(
      'post-count'
    );
  }

  if (
    /\bonline\s+application\b|\bapply\s+online\b|\bapplication\s+form\b/i
      .test(bodyText)
  ) {
    score += 2;
    evidence.push(
      'application'
    );
  }

  if (
    /\blast\s+date\b|\blast\s+date\s+for\b|\bclosing\s+date\b|\bdeadline\b/i
      .test(bodyText)
  ) {
    score += 2;
    evidence.push(
      'deadline'
    );
  }

  if (
    /\beligib(?:le|ility)\b|\bqualification\b|\beducational\s+qualification\b/i
      .test(bodyText)
  ) {
    score += 2;
    evidence.push(
      'eligibility'
    );
  }

  if (
    /\bselection\s+process\b|\bselection\s+procedure\b|\bwritten\s+exam\b|\binterview\b/i
      .test(bodyText)
  ) {
    score += 1;
    evidence.push(
      'selection'
    );
  }

  if (
    /\bapplication\s+fee\b|\bexam\s+fee\b/i
      .test(bodyText)
  ) {
    score += 1;
    evidence.push(
      'fee'
    );
  }

  const hasPdf =
    (links || [])
      .some(link =>
        isPdfUrl(link.url)
      );

  if (
    hasPdf
  ) {
    score += 2;
    evidence.push(
      'pdf-link'
    );
  }

  const hasApply =
    (links || [])
      .some(link =>
        !isPdfUrl(link.url) &&
        APPLY_PATTERN.test(
          `${link.text} ${link.url}`
        )
      );

  if (
    hasApply
  ) {
    score += 3;
    evidence.push(
      'apply-link'
    );
  }

  const strongRecruitment =
    score >= 8;

  return {
    score,
    strongRecruitment,
    evidence
  };
}


/* -------------------------------------------------------------------------- */
/* Category evidence                                                          */
/* -------------------------------------------------------------------------- */

function categoryEvidence(
  category,
  title,
  body,
  links
) {
  const combined =
    compactText(
      `${title} ${body.slice(0, 12000)} ${
        (links || [])
          .map(link => link.text)
          .join(' ')
      }`
    );

  const patterns =
    CATEGORY_PATTERNS[
      category
    ] || [];

  let score = 0;

  for (
    const pattern of patterns
  ) {
    if (
      pattern.test(combined)
    ) {
      score++;
    }
  }

  return {
    score,
    strong:
      score >= 2
  };
}


/* -------------------------------------------------------------------------- */
/* Notification PDF detection                                                 */
/* -------------------------------------------------------------------------- */

function findNotificationLink(
  links,
  source,
  pageContext = ''
) {
  const officialLinks =
    (links || [])
      .filter(link => {
        if (
          !isPdfUrl(link.url)
        ) {
          return false;
        }

        if (
          urlHasOldYear(link.url)
        ) {
          return false;
        }

        if (
          isBlockedPath(link.url)
        ) {
          return false;
        }

        try {
          return sameHostOrAllowed(
            link.url,
            source.allowed_domains,
            source.base_url
          );
        } catch {
          return true;
        }
      });

  if (
    !officialLinks.length
  ) {
    return null;
  }

  const explicit =
    officialLinks
      .filter(link =>
        NOTIFICATION_SIGNAL.test(
          `${link.text} ${link.url}`
        )
      )
      .sort(
        (a, b) =>
          linkPriority(b) -
          linkPriority(a)
      );

  if (
    explicit.length
  ) {
    return explicit[0].url;
  }

  if (
    /\brecruitment\b|\bvacanc(?:y|ies)\b|\badvertisement\b|\bnotification\b|\bemployment\s+notice\b|\bappointment\b/i
      .test(pageContext)
  ) {
    const ranked =
      officialLinks
        .map(link => ({
          link,
          score:
            linkPriority(
              link,
              pageContext
            )
        }))
        .sort(
          (a, b) =>
            b.score -
            a.score
        );

    if (
      ranked[0]
    ) {
      return ranked[0].link.url;
    }
  }

  const urlSignal =
    officialLinks
      .find(link =>
        /\b(
          adv|
          advt|
          advertisement|
          notification|
          notice|
          recruitment|
          vacancy|
          employment|
          appointment|
          detailed
        )\b/i.test(link.url)
      );

  return (
    urlSignal?.url ||
    null
  );
}


/* -------------------------------------------------------------------------- */
/* Apply URL detection                                                        */
/* -------------------------------------------------------------------------- */

function findApplyLink(
  links,
  sourceUrl,
  notificationUrl,
  source
) {
  const candidates =
    (links || [])
      .filter(link => {
        if (
          !isHttp(link.url)
        ) {
          return false;
        }

        if (
          isPdfUrl(link.url)
        ) {
          return false;
        }

        if (
          sameUrl(
            link.url,
            sourceUrl
          )
        ) {
          return false;
        }

        if (
          notificationUrl &&
          sameUrl(
            link.url,
            notificationUrl
          )
        ) {
          return false;
        }

        if (
          urlHasOldYear(link.url)
        ) {
          return false;
        }

        if (
          isBlockedPath(link.url)
        ) {
          return false;
        }

        try {
          return sameHostOrAllowed(
            link.url,
            source.allowed_domains,
            source.base_url
          );
        } catch {
          return true;
        }
      });

  const explicit =
    candidates
      .filter(link =>
        APPLY_PATTERN.test(
          `${link.text} ${link.url}`
        )
      )
      .sort(
        (a, b) =>
          linkPriority(b) -
          linkPriority(a)
      );

  if (
    explicit.length
  ) {
    return explicit[0].url;
  }

  const endpoint =
    candidates
      .filter(link =>
        /\/(?:apply|application|registration|register|online-?apply|candidate|recruitment|login)\b/i
          .test(
            new URL(link.url)
              .pathname
          )
      )
      .sort(
        (a, b) =>
          linkPriority(b) -
          linkPriority(a)
      );

  if (
    endpoint.length
  ) {
    return endpoint[0].url;
  }

  return null;
}


/* -------------------------------------------------------------------------- */
/* Title extraction                                                           */
/* -------------------------------------------------------------------------- */

function extractBestTitle(
  html,
  fallback
) {
  const headings = [];

  const headingRegex =
    /<h[1-3]\b[^>]*>([\s\S]*?)<\/h[1-3]>/gi;

  let match;

  while (
    (match =
      headingRegex.exec(html)) &&
    headings.length < 20
  ) {
    const title =
      cleanTitle(
        textOf(match[1])
      );

    if (
      title
    ) {
      headings.push(title);
    }
  }

  const goodHeading =
    headings.find(title =>
      hasSpecificTitle(
        title
      )
    );

  if (
    goodHeading
  ) {
    return goodHeading;
  }

  const titleMatch =
    html.match(
      /<title\b[^>]*>([\s\S]*?)<\/title>/i
    );

  const pageTitle =
    cleanTitle(
      titleMatch?.[1] || ''
    );

  if (
    hasSpecificTitle(
      pageTitle
    )
  ) {
    return pageTitle;
  }

  const fallbackTitle =
    cleanTitle(
      fallback
    );

  return fallbackTitle;
}


/* -------------------------------------------------------------------------- */
/* Field extraction                                                           */
/* -------------------------------------------------------------------------- */

function extractLabeledValue(
  body,
  labels
) {
  const label =
    labels.join('|');

  const regex =
    new RegExp(
      `(?:${label})\\s*(?:[:\\-]|is)?\\s*([^|]{2,180})`,
      'i'
    );

  const match =
    String(body || '')
      .match(regex);

  if (
    !match?.[1]
  ) {
    return null;
  }

  const value =
    match[1]
      .replace(/\s+/g, ' ')
      .trim();

  if (
    !value ||
    value.length > 180
  ) {
    return null;
  }

  return value;
}


function extractCandidateFields(
  title,
  body,
  links,
  source
) {
  const text =
    String(body || '')
      .slice(0, 30000);

  const applicationStart =
    extractDate(
      text,
      [
        'application\\s+start',
        'starting\\s+date',
        'start\\s+date',
        'online\\s+application\\s+from',
        'apply\\s+from'
      ]
    );

  const lastDate =
    extractDate(
      text,
      [
        'last\\s+date',
        'closing\\s+date',
        'last\\s+date\\s+for',
        'application\\s+last\\s+date',
        'deadline'
      ]
    );

  const examDate =
    extractDate(
      text,
      [
        'exam\\s+date',
        'date\\s+of\\s+exam',
        'written\\s+exam',
        'examination\\s+date'
      ]
    );

  const vacancies =
    extractLabeledValue(
      text,
      [
        'vacancies?',
        'no\\.\\s*of\\s*vacancies?',
        'number\\s+of\\s+posts?',
        'total\\s+posts?'
      ]
    );

  const qualification =
    extractLabeledValue(
      text,
      [
        'educational\\s+qualification',
        'qualification',
        'essential\\s+qualification',
        'minimum\\s+qualification'
      ]
    );

  const ageLimit =
    extractLabeledValue(
      text,
      [
        'age\\s+limit',
        'maximum\\s+age',
        'minimum\\s+age'
      ]
    );

  const fee =
    extractLabeledValue(
      text,
      [
        'application\\s+fee',
        'exam\\s+fee',
        'registration\\s+fee'
      ]
    );

  const selectionProcess =
    extractLabeledValue(
      text,
      [
        'selection\\s+process',
        'selection\\s+procedure',
        'mode\\s+of\\s+selection'
      ]
    );

  const salary =
    extractLabeledValue(
      text,
      [
        'salary',
        'pay\\s+scale',
        'pay\\s+level',
        'remuneration',
        'stipend'
      ]
    );

  const howToApply =
    /\bhow\s+to\s+apply\b/i.test(text)
      ? 'Apply through the official application link.'
      : null;

  return {
    application_start:
      applicationStart,

    last_date:
      lastDate,

    exam_date:
      examDate,

    vacancies:
      vacancies,

    qualification:
      qualification,

    age_limit:
      ageLimit,

    fee:
      fee,

    selection_process:
      selectionProcess,

    salary:
      salary,

    how_to_apply:
      howToApply,

    organization:
      source?.name || null
  };
}


/* -------------------------------------------------------------------------- */
/* Candidate creation                                                         */
/* -------------------------------------------------------------------------- */

function makeCandidate(
  page,
  source
) {
  const {
    url: pageUrl,
    html,
    links = []
  } = page;

  const title =
    extractBestTitle(
      html,
      page.fallbackTitle || ''
    );

  const body =
    textOf(html);

  if (
    !title ||
    !hasSpecificTitle(
      title,
      source.name
    )
  ) {
    return null;
  }

  if (
    isGenericPage(
      pageUrl,
      title
    )
  ) {
    return null;
  }

  if (
    ADMIN_DOCUMENT_PATTERN.test(
      `${title} ${pageUrl}`
    )
  ) {
    return null;
  }

  if (
    looksLikeLoginOnly(
      title,
      body,
      pageUrl
    )
  ) {
    return null;
  }

  if (
    looksLikeGenericCareerPage(
      pageUrl,
      title,
      body
    )
  ) {
    return null;
  }

  if (
    urlHasOldYear(pageUrl)
  ) {
    return null;
  }

  const category =
    classify(
      title,
      body,
      links
    );

  if (
    !category
  ) {
    return null;
  }

  const recruitment =
    recruitmentEvidence(
      title,
      body,
      links
    );

  const fields =
    extractCandidateFields(
      title,
      body,
      links,
      source
    );

  const pageContext =
    compactText(
      `${title} ${body.slice(0, 20000)}`
    );

  const notificationUrl =
    findNotificationLink(
      links,
      source,
      pageContext
    );

  const applyUrl =
    findApplyLink(
      links,
      pageUrl,
      notificationUrl,
      source
    );

  if (
    category === 'job' &&
    !recruitment.strongRecruitment
  ) {
    return null;
  }

  if (
    category === 'job' &&
    (
      !notificationUrl ||
      !applyUrl
    )
  ) {
    if (
      recruitment.score < 10
    ) {
      return null;
    }
  }

  if (
    category !== 'job'
  ) {
    const evidence =
      categoryEvidence(
        category,
        title,
        body,
        links
      );

    if (
      !evidence.strong
    ) {
      return null;
    }
  }

  const canonicalUrl =
    normalizeUrl(
      pageUrl
    );

  const notificationKeyBase =
    notificationUrl ||
    canonicalUrl ||
    pageUrl;

  const notificationKey =
    `${source.id}|${normalizeUrl(
      notificationKeyBase
    )}`;

  return {
    type:
      category === 'job'
        ? 'job'
        : category,

    title,

    organization:
      fields.organization,

    category,

    location:
      null,

    description:
      body.slice(0, 3000).trim() ||
      null,

    eligibility:
      fields.qualification ||
      null,

    qualification:
      fields.qualification ||
      null,

    vacancies:
      fields.vacancies ||
      null,

    age_limit:
      fields.age_limit ||
      null,

    age_relaxation:
      null,

    fee:
      fields.fee ||
      null,

    selection_process:
      fields.selection_process ||
      null,

    salary:
      fields.salary ||
      null,

    application_start:
      fields.application_start ||
      null,

    last_date:
      fields.last_date ||
      null,

    exam_date:
      fields.exam_date ||
      null,

    how_to_apply:
      fields.how_to_apply ||
      null,

    important_dates:
      null,

    official_url:
      pageUrl,

    notification_url:
      notificationUrl,

    apply_url:
      applyUrl,

    source_url:
      pageUrl,

    source_name:
      source.name,

    source_id:
      source.id,

    source_hash:
      null,

    canonical_url:
      canonicalUrl,

    notification_key:
      notificationKey,

    _official:
      source.role === 'official',

    authority:
      source.role === 'official'
        ? 'official'
        : 'secondary',

    source_role:
      source.role,

    _evidence:
      recruitment.evidence,

    _evidence_score:
      recruitment.score,

    _recruitment_score:
      recruitment.score
  };
}


/* -------------------------------------------------------------------------- */
/* SSC PDF candidate helpers                                                  */
/* -------------------------------------------------------------------------- */

function sscPdfIsUsable(url) {
  if (
    !isHttp(url)
  ) {
    return false;
  }

  if (
    !SSC_NOTICE_PATH.test(url)
  ) {
    return false;
  }

  if (
    !SSC_NOTICE_FILE.test(url)
  ) {
    return false;
  }

  if (
    urlHasOldYear(url)
  ) {
    return false;
  }

  return true;
}


function sscPdfTitle(url) {
  try {
    const pathname =
      new URL(url).pathname;

    const filename =
      pathname
        .split('/')
        .pop() || '';

    return cleanTitle(
      filename
        .replace(/\.pdf$/i, '')
        .replace(/[_-]+/g, ' ')
    );
  } catch {
    return null;
  }
}


function sscPdfCategory(
  title,
  url
) {
  const combined =
    `${title} ${url}`;

  if (
    /\badmit\b|\badmission\s+certificate\b/i
      .test(combined)
  ) {
    return 'admit';
  }

  if (
    /\banswer\s+key\b/i
      .test(combined)
  ) {
    return 'answer';
  }

  if (
    /\bresult\b|\bmerit\s+list\b|\bselection\s+list\b/i
      .test(combined)
  ) {
    return 'result';
  }

  if (
    /\bsyllabus\b/i
      .test(combined)
  ) {
    return 'syllabus';
  }

  if (
    SSC_RECRUITMENT_PATTERN.test(combined)
  ) {
    return 'job';
  }

  return null;
}


function sscPdfLooksRecruitment(
  title,
  url
) {
  const combined =
    `${title} ${url}`;

  if (
    SSC_NON_RECRUITMENT_PATTERN.test(
      combined
    ) &&
    !SSC_RECRUITMENT_PATTERN.test(
      combined
    )
  ) {
    return false;
  }

  return SSC_RECRUITMENT_PATTERN.test(
    combined
  );
}


function makeSscPdfCandidate(
  pdfUrl,
  source
) {
  if (
    !sscPdfIsUsable(pdfUrl)
  ) {
    return null;
  }

  const title =
    sscPdfTitle(pdfUrl);

  if (
    !title ||
    !hasSpecificTitle(
      title,
      'SSC'
    )
  ) {
    return null;
  }

  const category =
    sscPdfCategory(
      title,
      pdfUrl
    );

  if (
    !category
  ) {
    return null;
  }

  /*
    Only recruitment PDFs are allowed to become
    automatic SSC job records here.

    We deliberately do not turn result/admit/
    answer-key PDFs into jobs.
  */
  if (
    category !== 'job'
  ) {
    return null;
  }

  if (
    !sscPdfLooksRecruitment(
      title,
      pdfUrl
    )
  ) {
    return null;
  }

  /*
    The PDF itself is the authoritative notification.
    We do NOT pretend that the PDF is an apply URL.
    We also do not invent an application endpoint.
  */
  return {
    type: 'job',

    title,

    organization:
      'Staff Selection Commission',

    category: 'job',

    location:
      null,

    description:
      `Official SSC recruitment notification: ${title}`,

    eligibility:
      null,

    qualification:
      null,

    vacancies:
      null,

    age_limit:
      null,

    age_relaxation:
      null,

    fee:
      null,

    selection_process:
      null,

    salary:
      null,

    application_start:
      null,

    last_date:
      null,

    exam_date:
      null,

    how_to_apply:
      null,

    important_dates:
      null,

    /*
      The PDF is an official notification.
      The detail page will be filled when discovered.
    */
    official_url:
      'https://ssc.gov.in/',

    notification_url:
      pdfUrl,

    /*
      Never invent an apply URL.
    */
    apply_url:
      null,

    source_url:
      pdfUrl,

    source_name:
      source.name,

    source_id:
      source.id,

    source_hash:
      null,

    canonical_url:
      normalizeUrl(pdfUrl),

    notification_key:
      `${source.id}|${normalizeUrl(pdfUrl)}`,

    _official:
      source.role === 'official',

    authority:
      source.role === 'official'
        ? 'official'
        : 'secondary',

    source_role:
      source.role,

    _evidence: [
      'ssc-official-notice-pdf',
      'ssc-api-attachment',
      'recruitment-title'
    ],

    _evidence_score:
      10,

    _recruitment_score:
      10,

    /*
      Monitor can identify that this candidate
      still needs the real application URL.
    */
    _ssc_pdf_only:
      true
  };
}


/* -------------------------------------------------------------------------- */
/* SSC HTML embedded PDF extraction                                           */
/* -------------------------------------------------------------------------- */

function extractSscPdfUrls(
  html,
  baseUrl,
  source
) {
  const found =
    new Set();

  const candidates =
    [];

  /*
    Normal href/src references.
  */
  const directRegex =
    /(?:href|src)\s*=\s*["']([^"']+\.pdf(?:[^"']*)?)["']/gi;

  let match;

  while (
    (match =
      directRegex.exec(html))
  ) {
    const url =
      safeUrl(
        match[1],
        baseUrl
      );

    if (
      url &&
      sscPdfIsUsable(url)
    ) {
      found.add(
        normalizeUrl(url)
      );
      candidates.push(url);
    }
  }

  /*
    Raw HTML may contain escaped or JSON-style
    URL strings.
  */
  const rawRegex =
    /https?:\/\/ssc\.gov\.in\/api\/attachment\/uploads\/masterData\/NoticeBoards\/[^"'\\\s<>]+\.pdf/gi;

  while (
    (match =
      rawRegex.exec(html))
  ) {
    const url =
      match[0]
        .replace(/\\u002F/g, '/')
        .replace(/\\\//g, '/');

    if (
      sscPdfIsUsable(url)
    ) {
      const normalized =
        normalizeUrl(url);

      if (
        !found.has(normalized)
      ) {
        found.add(normalized);
        candidates.push(url);
      }
    }
  }

  /*
    Relative / escaped attachment references.
  */
  const attachmentRegex =
    /(?:\/|\\\/)api(?:\/|\\\/)attachment(?:\/|\\\/)uploads(?:\/|\\\/)masterData(?:\/|\\\/)NoticeBoards(?:\/|\\\/)[^"'\\\s<>]+\.pdf/gi;

  while (
    (match =
      attachmentRegex.exec(html))
  ) {
    const cleaned =
      match[0]
        .replace(/\\/g, '');

    const url =
      safeUrl(
        cleaned,
        baseUrl
      );

    if (
      url &&
      sscPdfIsUsable(url)
    ) {
      const normalized =
        normalizeUrl(url);

      if (
        !found.has(normalized)
      ) {
        found.add(normalized);
        candidates.push(url);
      }
    }
  }

  return candidates;
}


/* -------------------------------------------------------------------------- */
/* SSC application-link extraction                                            */
/* -------------------------------------------------------------------------- */

function findSscApplyLink(
  links,
  pageUrl
) {
  const candidates =
    (links || [])
      .filter(link => {
        if (
          !isHttp(link.url)
        ) {
          return false;
        }

        if (
          isPdfUrl(link.url)
        ) {
          return false;
        }

        if (
          sameUrl(
            link.url,
            pageUrl
          )
        ) {
          return false;
        }

        if (
          urlHasOldYear(link.url)
        ) {
          return false;
        }

        return true;
      });

  /*
    SSC application links may point to the
    mySSC/application module rather than a URL
    containing "apply".
  */
  const explicit =
    candidates
      .filter(link =>
        APPLY_PATTERN.test(
          `${link.text} ${link.url}`
        ) ||
        /myssc|applicationform|application-form|apply/i
          .test(link.url)
      )
      .sort(
        (a, b) =>
          linkPriority(b) -
          linkPriority(a)
      );

  return (
    explicit[0]?.url ||
    null
  );
}


/* -------------------------------------------------------------------------- */
/* SSC dedicated discovery                                                   */
/* -------------------------------------------------------------------------- */

async function discoverSsc(
  source
) {
  const homepage =
    normalizeUrl(
      source.base_url
    );

  if (
    !homepage
  ) {
    throw new Error(
      `Invalid SSC source URL: ${source.base_url}`
    );
  }

  const first =
    await fetchWithTimeout(
      homepage
    );

  if (
    !first.ok
  ) {
    const error =
      new Error(
        `SSC: HTTP ${first.status}`
      );

    error.status =
      first.status;

    error.retryAfter =
      first.retryAfter;

    throw error;
  }

  /*
    SSC can return HTML normally, but if it
    directly redirects to a PDF we still handle
    that safely.
  */
  if (
    first.isPdf
  ) {
    const candidate =
      makeSscPdfCandidate(
        first.finalUrl ||
          homepage,
        source
      );

    return candidate
      ? [candidate]
      : [];
  }

  const pages = [];

  const queue = [
    {
      url:
        first.finalUrl ||
        homepage,

      html:
        first.body || '',

      depth:
        0,

      fallbackTitle:
        'SSC'
    }
  ];

  const visited =
    new Set();

  visited.add(
    normalizeUrl(
      first.finalUrl ||
      homepage
    )
  );

  const pdfUrls =
    new Set();

  const candidates =
    [];

  while (
    queue.length &&
    pages.length < SSC_MAX_PAGES
  ) {
    const page =
      queue.shift();

    pages.push(page);

    const links =
      parseLinks(
        page.html,
        page.url
      );

    page.links =
      links;

    /*
      1. Extract direct SSC notification PDFs
         from raw HTML.
    */
    const embeddedPdfs =
      extractSscPdfUrls(
        page.html,
        page.url,
        source
      );

    for (
      const pdfUrl of embeddedPdfs
    ) {
      pdfUrls.add(
        normalizeUrl(pdfUrl)
      );
    }

    /*
      2. Extract ordinary PDF anchors.
    */
    for (
      const link of links
    ) {
      if (
        isPdfUrl(link.url) &&
        sscPdfIsUsable(link.url)
      ) {
        pdfUrls.add(
          normalizeUrl(link.url)
        );
      }
    }

    /*
      3. Look for real application links.
    */
    const applyUrl =
      findSscApplyLink(
        links,
        page.url
      );

    if (
      applyUrl
    ) {
      page._sscApplyUrl =
        applyUrl;
    }

    if (
      page.depth >=
      2
    ) {
      continue;
    }

    const pageText =
      textOf(page.html)
        .slice(0, 15000);

    const ranked =
      links
        .filter(link =>
          isUsefulCrawlLink(
            link,
            source,
            page.url
          )
        )
        .map(link => ({
          link,
          score:
            linkPriority(
              link,
              pageText
            ) +
            (
              SSC_RECRUITMENT_PATTERN.test(
                `${link.text} ${link.url}`
              )
                ? 10
                : 0
            )
        }))
        .sort(
          (a, b) =>
            b.score -
            a.score
        )
        .slice(
          0,
          SSC_MAX_LINKS_PER_PAGE
        );

    for (
      const entry of ranked
    ) {
      const link =
        entry.link;

      if (
        isPdfUrl(link.url)
      ) {
        continue;
      }

      const normalized =
        normalizeUrl(
          link.url
        );

      if (
        !normalized ||
        visited.has(normalized)
      ) {
        continue;
      }

      if (
        pages.length +
        queue.length >=
        SSC_MAX_PAGES
      ) {
        break;
      }

      visited.add(
        normalized
      );

      try {
        const response =
          await fetchWithTimeout(
            normalized
          );

        if (
          !response.ok ||
          response.isPdf ||
          !response.body
        ) {
          continue;
        }

        queue.push({
          url:
            response.finalUrl ||
            normalized,

          html:
            response.body,

          depth:
            page.depth + 1,

          fallbackTitle:
            link.text ||
            'SSC'
        });

      } catch {
        /*
          Continue scanning other SSC pages.
        */
      }
    }
  }


  /*
    Build candidates from official SSC PDFs.
  */
  for (
    const pdfUrl of pdfUrls
  ) {
    const candidate =
      makeSscPdfCandidate(
        pdfUrl,
        source
      );

    if (
      candidate
    ) {
      candidates.push(
        candidate
      );
    }
  }


  /*
    Also run normal candidate extraction on
    discovered HTML pages.

    This can provide:
    - actual official detail page
    - real application URL
    - additional metadata
  */
  for (
    const page of pages
  ) {
    const candidate =
      makeCandidate(
        page,
        source
      );

    if (
      !candidate
    ) {
      continue;
    }

    /*
      SSC-specific protection:
      do not accept a generic SSC page as a
      recruitment job simply because the body
      contains the word "application".
    */
    if (
      candidate.type === 'job'
    ) {
      const combined =
        `${candidate.title} ${candidate.source_url}`;

      if (
        !SSC_RECRUITMENT_PATTERN.test(
          combined
        )
      ) {
        continue;
      }

      if (
        SSC_NON_RECRUITMENT_PATTERN.test(
          combined
        ) &&
        !/\b(recruitment|examination|selection\s+post|cgl|chsl|mts|constable|junior\s+engineer)\b/i
          .test(combined)
      ) {
        continue;
      }
    }

    candidates.push(
      candidate
    );
  }


  /*
    Deduplicate by notification URL first.
  */
  const unique =
    new Map();

  for (
    const candidate of candidates
  ) {
    const identity =
      normalizeUrl(
        candidate.notification_url ||
        candidate.canonical_url ||
        candidate.source_url
      );

    if (
      !identity
    ) {
      continue;
    }

    if (
      !unique.has(identity)
    ) {
      unique.set(
        identity,
        candidate
      );
      continue;
    }

    /*
      Prefer the richer candidate.
    */
    const existing =
      unique.get(identity);

    const existingScore =
      Number(
        existing._evidence_score || 0
      );

    const newScore =
      Number(
        candidate._evidence_score || 0
      );

    if (
      newScore >
      existingScore
    ) {
      unique.set(
        identity,
        candidate
      );
    }
  }


  /*
    Important:
    If we have an HTML recruitment page with a
    matching SSC notification PDF, connect them.
  */
  const result =
    Array.from(
      unique.values()
    );

  for (
    const candidate of result
  ) {
    if (
      candidate.type !== 'job'
    ) {
      continue;
    }

    /*
      If candidate already has notification URL,
      keep it.
    */
    if (
      candidate.notification_url
    ) {
      continue;
    }

    const titleText =
      compactText(
        candidate.title
      );

    const matchingPdf =
      result.find(other =>
        other !== candidate &&
        other.type === 'job' &&
        other.notification_url &&
        (
          compactText(
            other.title
          ).includes(titleText) ||
          titleText.includes(
            compactText(
              other.title
            )
          )
        )
      );

    if (
      matchingPdf
    ) {
      candidate.notification_url =
        matchingPdf.notification_url;
    }
  }


  /*
    Strongest SSC candidates first.
  */
  result.sort(
    (a, b) =>
      Number(
        b._evidence_score || 0
      ) -
      Number(
        a._evidence_score || 0
      )
  );

  return result.slice(
    0,
    MAX_LINKS
  );
}


/* -------------------------------------------------------------------------- */
/* Generic page ranking                                                       */
/* -------------------------------------------------------------------------- */

function pageScore(
  page,
  source
) {
  const title =
    compactText(
      page.fallbackTitle ||
      ''
    );

  const url =
    compactText(
      page.url
    );

  const body =
    compactText(
      page.html?.slice(0, 12000) ||
      ''
    );

  let score = 0;

  if (
    /\brecruitment|vacancy|advertisement|notification\b/i
      .test(title)
  ) {
    score += 15;
  }

  if (
    /\brecruitment|vacancy|advertisement|notification\b/i
      .test(url)
  ) {
    score += 12;
  }

  if (
    /\b20\d{2}\b/.test(title)
  ) {
    score += 5;
  }

  if (
    /\bapply\s+online\b|\bonline\s+application\b/i
      .test(body)
  ) {
    score += 5;
  }

  if (
    /\blast\s+date\b|\bdeadline\b/i
      .test(body)
  ) {
    score += 5;
  }

  if (
    page.links?.some(link =>
      isPdfUrl(link.url)
    )
  ) {
    score += 4;
  }

  if (
    page.links?.some(link =>
      APPLY_PATTERN.test(
        `${link.text} ${link.url}`
      )
    )
  ) {
    score += 6;
  }

  if (
    page.depth === 0
  ) {
    score -= 2;
  }

  return score;
}


/* -------------------------------------------------------------------------- */
/* Generic source discovery                                                   */
/* -------------------------------------------------------------------------- */

async function discoverGeneric(
  source
) {
  const homepage =
    normalizeUrl(
      source.base_url
    );

  if (
    !homepage
  ) {
    throw new Error(
      'Official source configuration is missing base_url.'
    );
  }

  const first =
    await fetchWithTimeout(
      homepage
    );

  if (
    !first.ok
  ) {
    const error =
      new Error(
        `${source.name}: HTTP ${first.status}`
      );

    error.status =
      first.status;

    error.retryAfter =
      first.retryAfter;

    throw error;
  }

  if (
    first.isPdf ||
    !first.body
  ) {
    throw new Error(
      `${source.name}: official source did not return HTML`
    );
  }

  const pages = [];

  const queue = [
    {
      url:
        first.finalUrl ||
        homepage,

      html:
        first.body,

      depth:
        0,

      fallbackTitle:
        source.name
    }
  ];

  const visited =
    new Set();

  visited.add(
    normalizeUrl(
      first.finalUrl ||
      homepage
    )
  );

  const discoveredCandidates =
    [];

  while (
    queue.length &&
    pages.length < MAX_PAGES
  ) {
    const page =
      queue.shift();

    pages.push(page);

    const links =
      parseLinks(
        page.html,
        page.url
      );

    page.links =
      links;

    if (
      page.depth >=
      MAX_DEPTH
    ) {
      continue;
    }

    const ranked =
      links
        .filter(link =>
          isUsefulCrawlLink(
            link,
            source,
            page.url
          )
        )
        .map(link => ({
          link,
          score:
            linkPriority(
              link,
              textOf(
                page.html
              ).slice(0, 10000)
            )
        }))
        .sort(
          (a, b) =>
            b.score -
            a.score
        )
        .slice(
          0,
          MAX_LINKS_PER_PAGE
        );

    for (
      const entry of ranked
    ) {
      const link =
        entry.link;

      if (
        isPdfUrl(link.url)
      ) {
        continue;
      }

      const normalized =
        normalizeUrl(
          link.url
        );

      if (
        !normalized ||
        visited.has(normalized)
      ) {
        continue;
      }

      if (
        pages.length +
        queue.length >=
        MAX_PAGES
      ) {
        break;
      }

      visited.add(
        normalized
      );

      try {
        const response =
          await fetchWithTimeout(
            normalized
          );

        if (
          !response.ok ||
          response.isPdf ||
          !response.body
        ) {
          continue;
        }

        queue.push({
          url:
            response.finalUrl ||
            normalized,

          html:
            response.body,

          depth:
            page.depth + 1,

          fallbackTitle:
            link.text ||
            source.name
        });

      } catch {
        /*
          One bad child page must not kill
          the entire source scan.
        */
      }
    }
  }

  pages.sort(
    (a, b) =>
      pageScore(b, source) -
      pageScore(a, source)
  );

  const seen =
    new Set();

  for (
    const page of pages
  ) {
    const pageLinks =
      page.links ||
      parseLinks(
        page.html,
        page.url
      );

    page.links =
      pageLinks;

    const candidate =
      makeCandidate(
        page,
        source
      );

    if (
      !candidate
    ) {
      continue;
    }

    const identity =
      normalizeUrl(
        candidate.notification_url ||
        candidate.canonical_url ||
        candidate.source_url
      );

    if (
      !identity ||
      seen.has(identity)
    ) {
      continue;
    }

    seen.add(identity);

    discoveredCandidates.push(
      candidate
    );
  }

  discoveredCandidates.sort(
    (a, b) =>
      Number(
        b._evidence_score || 0
      ) -
      Number(
        a._evidence_score || 0
      )
  );

  return discoveredCandidates.slice(
    0,
    MAX_LINKS
  );
}


/* -------------------------------------------------------------------------- */
/* Public source discovery                                                    */
/* -------------------------------------------------------------------------- */

export async function discoverFromSource(
  source
) {
  if (
    !source ||
    !source.base_url
  ) {
    throw new Error(
      'Official source configuration is missing base_url.'
    );
  }

  /*
    Dedicated adapter selection.
  */
  if (
    String(
      source.adapter || ''
    ).toLowerCase() === 'ssc'
  ) {
    return discoverSsc(
      source
    );
  }

  return discoverGeneric(
    source
  );
}


/* -------------------------------------------------------------------------- */
/* Portal discovery                                                           */
/* -------------------------------------------------------------------------- */

export async function discoverPortal(
  source
) {
  return discoverGeneric(
    source
  );
}


/* -------------------------------------------------------------------------- */
/* Default export                                                             */
/* -------------------------------------------------------------------------- */

export default {
  discoverFromSource,
  discoverPortal
};
