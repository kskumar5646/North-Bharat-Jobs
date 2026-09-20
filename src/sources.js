import {
  isPdfUrl,
  normalizeUrl,
  sameHostOrAllowed
} from './verification.js';

/*
  North Bharat Jobs
  Official-source discovery engine

  IMPORTANT:
  - Never invent URLs.
  - Recruitment jobs require:
      1. Official source page
      2. Real notification PDF
      3. Real apply/registration URL
  - Official URL, notification URL and apply URL must be distinct.
  - Generic career/login pages are NOT automatically treated as apply links.
  - Weak/ambiguous pages are ignored instead of being published as jobs.
*/

const WORDS = {
  job:
    /(recruitment|recruit|vacan(?:cy|cies)?|appointment|notification|advertisement|post(?:s)?|application|constable|officer|assistant|teacher|engineer|clerk|group\s*[abc]|staff\s*selection|selection\s*process)/i,

  admit:
    /(admit\s*card|hall\s*ticket|call\s*letter|e[-\s]?admit)/i,

  result:
    /\b(result|merit|score|selection\s*list|shortlist|final\s*result|provisional\s*result)\b/i,

  answer:
    /(answer\s*key|response\s*sheet|answer\s*sheet)/i,

  syllabus:
    /\bsyllabus\b/i,

  admission:
    /(admission|entrance|counselling|counseling|entrance\s*test)/i,

  scholarship:
    /\bscholarship\b/i,

  update:
    /(notice|latest|important|extension|corrigendum|exam\s*date|schedule|public\s*notice|official\s*notice)/i
};

/*
  IMPORTANT:
  Do NOT include generic "careers" or "login" here.
  Those links are frequently general pages and not actual application forms.
*/
const APPLY =
  /(apply\s*(online|now|here)|online\s*application|application\s*(form|portal)|registration\s*(link|portal)?|register\s*(online|now)|apply\s*link|online\s*registration|candidate\s*login)/i;

const NOTIFY =
  /(notification|advertisement|detailed\s*advertisement|recruitment|recruitment\s*notice|employment\s*notice|vacancy|prospectus|notice|corrigendum|extension).*\.pdf/i;

const MAX_LINKS = 180;
const MAX_PAGES = 18;
const MAX_LINKS_PER_PAGE = 120;

const FETCH_TIMEOUT_MS = 12000;

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

function isPdfCandidate(url = '', text = '') {
  const combined = `${text} ${url}`.trim();

  if (isPdfUrl(url)) return true;

  return /\.pdf(?:[?#]|$)/i.test(url) ||
    /\bpdf\b/i.test(text) ||
    NOTIFY.test(combined);
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

      /*
        Ignore javascript/mail/tel links.
      */
      if (
        /^javascript:/i.test(rawHref) ||
        /^mailto:/i.test(rawHref) ||
        /^tel:/i.test(rawHref) ||
        /^#/i.test(rawHref)
      ) {
        continue;
      }

      const url = normalizeUrl(new URL(rawHref, base).toString());

      if (!url) continue;

      const text = textOf(match[2]).slice(0, 500);

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
        'Accept':
          'text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.5'
      }
    });

    const contentType =
      response.headers.get('content-type') || '';

    /*
      Only read textual responses as text.
      PDF/binary responses are not parsed as HTML.
    */
    const isTextResponse =
      /text\/html|application\/xhtml\+xml|text\/plain/i.test(
        contentType
      );

    const body = isTextResponse
      ? await response.text()
      : '';

    return {
      ok: response.ok,
      status: response.status,
      body,
      contentType,
      finalUrl: normalizeUrl(response.url || url) || url,
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
    `${title} ${body.slice(0, 9000)}`;

  /*
    More specific types first.
  */
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
      `(?:${labels})[^\\d]{0,50}(\\d{1,2}[\\/-]\\d{1,2}[\\/-]\\d{2,4})`,
      'i'
    ),

    new RegExp(
      `(?:${labels})[^\\d]{0,50}(\\d{1,2}\\s+${month}\\s+\\d{4})`,
      'i'
    ),

    new RegExp(
      `(?:${labels})[^\\d]{0,50}(${month}\\s+\\d{1,2},?\\s+\\d{4})`,
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
  const titleText = normalizedText(title);
  const bodyText = normalizedText(body);

  let score = 0;
  const evidence = [];

  if (/\brecruitment\b|\brecruit\b/.test(titleText)) {
    score += 3;
    evidence.push('recruitment-title');
  }

  if (
    /\bvacanc(?:y|ies)\b|\bnumber of posts\b|\bno\.?\s*of posts\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('vacancy-or-post-count');
  }

  if (
    /\bapplication start\b|\bapplication begins\b|\bregistration starts\b|\bonline application\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('application-period');
  }

  if (
    /\blast date\b|\bclosing date\b|\bapply by\b|\bdeadline\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('last-date');
  }

  if (
    /\beligib(?:ility|le)\b|\bqualification\b|\beducational qualification\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push('eligibility');
  }

  if (
    /\bselection process\b|\bselection procedure\b|\bwritten examination\b|\binterview\b/.test(
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

  const hasNotification =
    links.some(link =>
      isPdfCandidate(link.url, link.text)
    );

  if (hasNotification) {
    score += 2;
    evidence.push('notification-pdf-link');
  }

  const hasApply =
    links.some(link =>
      !isPdfUrl(link.url) &&
      APPLY.test(`${link.text} ${link.url}`)
    );

  if (hasApply) {
    score += 2;
    evidence.push('apply-link');
  }

  return {
    score,
    evidence
  };
}

/* -------------------------------------------------------------------------- */
/* Candidate link selection                                                   */
/* -------------------------------------------------------------------------- */

function findNotificationLink(links, source) {
  for (const link of links) {
    if (!isHttp(link.url)) continue;

    if (
      source?.role === 'official' &&
      !sameHostOrAllowed(
        link.url,
        source.allowed_domains
      )
    ) {
      continue;
    }

    if (
      isPdfCandidate(link.url, link.text) &&
      (
        isPdfUrl(link.url) ||
        NOTIFY.test(`${link.text} ${link.url}`)
      )
    ) {
      return link;
    }
  }

  return null;
}

function findApplyLink(links, sourceUrl, notificationUrl) {
  for (const link of links) {
    if (!isHttp(link.url)) continue;

    if (isPdfUrl(link.url)) continue;

    if (sameUrl(link.url, sourceUrl)) continue;

    if (
      notificationUrl &&
      sameUrl(link.url, notificationUrl)
    ) {
      continue;
    }

    const label =
      `${link.text} ${link.url}`;

    if (!APPLY.test(label)) {
      continue;
    }

    /*
      Do not treat a generic careers/login page as an application link.
    */
    if (
      looksLikeGenericCareerPage(link.url, link.text) ||
      looksLikeLoginOnly(link.url, link.text)
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

  const title = cleanTitle(
    titleMatch?.[1] ||
      textOf(page.body).slice(0, 220)
  );

  const body =
    textOf(page.body).slice(0, 14000);

  const sourceUrl =
    normalizeUrl(
      page.finalUrl ||
      page.url
    );

  if (!sourceUrl || !title) {
    return null;
  }

  const links = linksOf(
    page.body,
    page.finalUrl || page.url
  ).slice(0, MAX_LINKS_PER_PAGE);

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
    classify(title, body);

  const evidence =
    recruitmentEvidence(
      title,
      body,
      links
    );

  /*
    Recruitment page needs strong evidence.
    This blocks generic pages such as:
      - Customer Education
      - About Us
      - General Careers
      - Generic notices
  */
  const strongRecruitmentEvidence =
    evidence.score >= 5;

  /*
    For a recruitment item, both links are mandatory.
  */
  if (
    type === 'job' &&
    (
      !notification?.url ||
      !apply?.url ||
      !strongRecruitmentEvidence
    )
  ) {
    return null;
  }

  /*
    Ensure all three URLs are different.
  */
  if (
    type === 'job' &&
    (
      sameUrl(sourceUrl, notification?.url) ||
      sameUrl(sourceUrl, apply?.url) ||
      sameUrl(notification?.url, apply?.url)
    )
  ) {
    return null;
  }

  /*
    Official source page itself must belong to allowed domain.
  */
  if (
    source.role === 'official' &&
    !sameHostOrAllowed(
      sourceUrl,
      source.allowed_domains
    )
  ) {
    return null;
  }

  /*
    Stable page identity is intentionally based on the
    source detail page, not the PDF URL.

    This is important because a revised notification PDF
    should update the existing recruitment rather than
    create a completely new item.
  */
  const canonicalPage =
    sourceUrl;

  const notificationUrl =
    normalizeUrl(
      notification?.url
    );

  const applyUrl =
    normalizeUrl(
      apply?.url
    );

  return {
    type,
    title,

    organization:
      source.name,

    category:
      type,

    description:
      body.slice(0, 4000),

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

    /*
      Official page URL.
    */
    official_url:
      source.role === 'official'
        ? sourceUrl
        : null,

    /*
      Real application URL.
    */
    apply_url:
      applyUrl,

    /*
      Real notification PDF URL.
    */
    notification_url:
      notificationUrl,

    /*
      Page from which this candidate was discovered.
    */
    source_url:
      sourceUrl,

    source_name:
      source.name,

    source_id:
      source.id,

    /*
      Stable canonical identity.
      PDF URL is deliberately NOT used here.
    */
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
      links.slice(0, 20)
  };
}

/* -------------------------------------------------------------------------- */
/* Source discovery                                                          */
/* -------------------------------------------------------------------------- */

export async function discoverFromSource(source) {
  if (!source?.base_url) {
    throw new Error('Source base URL missing');
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
        status: home.status,
        retryAfter: home.retryAfter
      }
    );
  }

  /*
    A source homepage must be HTML.
  */
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
        status: home.status
      }
    );
  }

  const all =
    linksOf(
      home.body,
      home.finalUrl || source.base_url
    )
      .filter(link =>
        sameHostOrAllowed(
          link.url,
          source.allowed_domains
        )
      );

  /*
    Select only pages that have meaningful
    recruitment/update signals.
  */
  const selected = all
    .filter(link => {
      const text =
        `${link.text} ${link.url}`;

      return (
        WORDS.job.test(text) ||
        WORDS.admit.test(text) ||
        WORDS.result.test(text) ||
        WORDS.answer.test(text) ||
        WORDS.syllabus.test(text) ||
        WORDS.admission.test(text) ||
        WORDS.scholarship.test(text) ||
        WORDS.update.test(text)
      );
    })
    .slice(0, MAX_PAGES);

  /*
    Homepage itself is checked only for non-recruitment
    categories. This prevents a generic homepage from
    becoming a fake job item.
  */
  const pages = [
    {
      url:
        home.finalUrl ||
        source.base_url,

      body:
        home.body,

      finalUrl:
        home.finalUrl ||
        source.base_url,

      isHome: true
    }
  ];

  for (const link of selected) {
    if (pages.length >= MAX_PAGES) {
      break;
    }

    /*
      Never refetch exact homepage.
    */
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
        response.body.slice(0, 2000)
      );

    if (
      response.ok &&
      isHtml &&
      response.body
    ) {
      pages.push({
        url: link.url,
        body: response.body,
        finalUrl:
          response.finalUrl ||
          link.url,
        isHome: false
      });
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Candidate generation                                                   */
  /* ---------------------------------------------------------------------- */

  const seen = new Set();
  const candidates = [];

  for (const page of pages) {
    const candidate =
      makeCandidate(
        page,
        source
      );

    if (!candidate) {
      continue;
    }

    /*
      Do not add the same source page twice.
    */
    const pageKey =
      normalizeUrl(
        candidate.canonical_url ||
        candidate.source_url
      );

    if (!pageKey || seen.has(pageKey)) {
      continue;
    }

    seen.add(pageKey);

    /*
      Recruitment candidates have already passed:
        - notification PDF requirement
        - apply URL requirement
        - evidence threshold
        - URL separation
        - official-domain checks
    */
    candidates.push(candidate);
  }

  return candidates;
}

/* -------------------------------------------------------------------------- */
/* Portal fallback                                                            */
/* -------------------------------------------------------------------------- */

export async function discoverPortal(source) {
  return discoverFromSource(source);
}
