/*
  North Bharat Jobs
  Official-source discovery engine

  Rules:
  - Official source is authoritative.
  - Never invent URLs.
  - Recruitment requires:
      1. official detail page
      2. direct notification PDF
      3. real apply/registration URL
  - Portal data is secondary only.
  - Existing published data is never destroyed by
    temporary/incomplete source scans.
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
const MAX_PAGES = 40;
const MAX_DEPTH = 3;
const MAX_LINKS_PER_PAGE = 180;
const FETCH_TIMEOUT_MS = 12000;

const CURRENT_YEAR = new Date().getUTCFullYear();
const MIN_ACCEPTABLE_YEAR = CURRENT_YEAR - 1;


/* -------------------------------------------------------------------------- */
/* Category patterns                                                          */
/* -------------------------------------------------------------------------- */

const CATEGORY_PATTERNS = {
  job: [
    /\brecruitment\b/i,
    /\brecruit\b/i,
    /\bvaccancy\b/i,
    /\bvacancies\b/i,
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


/* -------------------------------------------------------------------------- */
/* Apply / notification signals                                               */
/* -------------------------------------------------------------------------- */

const APPLY_PATTERN =
  /\b(?:apply|application|registration|register|candidate\s+login|online\s+registration|online\s+application)\b/i;

const STRONG_APPLY_PATTERN =
  /\b(?:apply\s+online|apply\s+now|online\s+application|application\s+form|application\s+portal|registration\s+link|registration\s+portal|online\s+registration|candidate\s+registration|register\s+now)\b/i;

const NOTIFICATION_SIGNAL =
  /\b(?:notification|advertisement|recruitment|recruitment\s+notice|employment\s+notice|vacancy|vacancies|selection\s+notice|appointment|corrigendum|extension|job\s+notice|employment|engagement\s+notice|detailed\s+advertisement|detailed\s+notification|notice\s+of\s+recruitment)\b/i;


/* -------------------------------------------------------------------------- */
/* Pages which must never become public records                               */
/* -------------------------------------------------------------------------- */

const ADMIN_DOCUMENT_PATTERN =
  /\b(?:rti|right\s+to\s+information|policy|policies|terms|privacy|annual\s+report|tender|tenders|procurement|vendor|circular\s+for\s+vendors|press\s+release|budget|finance|audit|act|rules|regulation|forms?|downloads?|gallery|archive|contact|about|sitemap|feedback|grievance|citizen\s+charter|disclosure|eoi|expression\s+of\s+interest)\b/i;

const GENERIC_TITLE_PATTERN =
  /^(?:home|homepage|welcome|index|about|contact|login|careers?|results?|syllabus|admit\s*card|answer\s*key|scholarship|admission|recruitment|advertisement|notifications?|notices?|latest\s+news|important\s+links?)$/i;

const GENERIC_ORG_TITLE_PATTERN =
  /^(?:home|welcome|about|careers?|results?|syllabus|notifications?|notices?)\s*\|/i;

const BLOCKED_FILE_PATTERN =
  /\.(?:jpg|jpeg|png|gif|svg|webp|ico|css|js|json|xml|zip|rar|mp4|mp3|woff|woff2|ttf|eot)$/i;

const LOGIN_ONLY_PATTERN =
  /\b(?:login|sign\s*in|candidate\s+login|user\s+login|forgot\s+password|password|username)\b/i;


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
  return /^https?:\/\//i.test(String(value || ''));
}


function safeUrl(value, baseUrl = null) {
  try {
    if (!value) {
      return null;
    }

    const raw = String(value).trim();

    if (!raw) {
      return null;
    }

    const url = baseUrl
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
    return normalizeUrl(a) === normalizeUrl(b);
  } catch {
    return String(a) === String(b);
  }
}


function urlHasOldYear(url) {
  const value = String(url || '');

  const matches = value.match(/\b(?:19\d{2}|20\d{2})\b/g);

  if (!matches?.length) {
    return false;
  }

  return matches.some(
    year => Number(year) < MIN_ACCEPTABLE_YEAR
  );
}


function isBlockedPath(url) {
  const value = String(url || '').toLowerCase();

  return (
    /\/(?:admin|login|logout|signin|signup|wp-admin)\b/.test(value) ||
    /(?:privacy|terms|cookie|contact-us|feedback|sitemap)\b/.test(value) ||
    BLOCKED_FILE_PATTERN.test(value)
  );
}


function isGenericPage(url, title = '') {
  const value = String(url || '');

  if (GENERIC_TITLE_PATTERN.test(cleanTitle(title))) {
    return true;
  }

  if (GENERIC_ORG_TITLE_PATTERN.test(cleanTitle(title))) {
    return true;
  }

  if (
    /\/(?:home|about|contact|login|careers?)\/?$/i.test(value)
  ) {
    return true;
  }

  return false;
}


function looksLikeGenericCareerPage(url, title, body) {
  const combined = compactText(
    `${url} ${title} ${String(body || '').slice(0, 5000)}`
  );

  if (!/\bcareer\b|\bcareers\b|\bemployment\b/i.test(combined)) {
    return false;
  }

  if (
    /\bapply\b|\bvacancy\b|\brecruitment\b|\badvertisement\b|\bnotification\b/i.test(combined)
  ) {
    return false;
  }

  return true;
}


function looksLikeLoginOnly(title, body, url) {
  const combined = compactText(
    `${title} ${String(body || '').slice(0, 3000)} ${url}`
  );

  if (/application\s+form/i.test(combined)) {
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

function hasSpecificTitle(title, sourceName = '') {
  const value = cleanTitle(title);

  if (value.length < 8) {
    return false;
  }

  if (GENERIC_TITLE_PATTERN.test(value)) {
    return false;
  }

  if (GENERIC_ORG_TITLE_PATTERN.test(value)) {
    return false;
  }

  if (ADMIN_DOCUMENT_PATTERN.test(value)) {
    return false;
  }

  const identity =
    /\b(?:20\d{2}|exam|recruitment|vacancy|vacancies|post|posts|notification|advertisement|admit|hall|result|merit|selection|answer|syllabus|admission|scholarship|candidate|group|class|officer|assistant|teacher|engineer|clerk|constable|inspector|technician|staff|department|course|programme|program|notice|corrigendum|extension|application)\b/i;

  if (identity.test(value)) {
    return true;
  }

  if (
    sourceName &&
    value.toLowerCase().includes(
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

function parseLinks(html, baseUrl) {
  const links = [];

  const regex =
    /<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi;

  let match;

  while (
    (match = regex.exec(html)) &&
    links.length < MAX_LINKS
  ) {
    const href = safeUrl(match[1], baseUrl);

    if (!href) {
      continue;
    }

    const text = cleanTitle(textOf(match[2]));

    if (/^javascript:/i.test(href)) {
      continue;
    }

    links.push({
      url: href,
      text,
      htmlText: match[2]
    });
  }

  return links;
}


/* -------------------------------------------------------------------------- */
/* Link scoring                                                               */
/* -------------------------------------------------------------------------- */

function linkPriority(link, pageText = '') {
  const value = compactText(
    `${link.text} ${link.url}`
  );

  let score = 0;

  if (NOTIFICATION_SIGNAL.test(value)) {
    score += 12;
  }

  if (STRONG_APPLY_PATTERN.test(value)) {
    score += 12;
  } else if (APPLY_PATTERN.test(value)) {
    score += 5;
  }

  if (isPdfUrl(link.url)) {
    score += 10;
  }

  if (/\b20\d{2}\b/.test(value)) {
    score += 3;
  }

  if (/\brecruit|vacanc|advertisement|notification|post\b/i.test(value)) {
    score += 6;
  }

  if (/\badmit|result|answer|syllabus|admission\b/i.test(value)) {
    score += 3;
  }

  if (ADMIN_DOCUMENT_PATTERN.test(value)) {
    score -= 25;
  }

  if (urlHasOldYear(link.url)) {
    score -= 30;
  }

  if (
    pageText &&
    /\brecruitment|vacancy|advertisement|notification\b/i.test(pageText)
  ) {
    score += 2;
  }

  return score;
}


/* -------------------------------------------------------------------------- */
/* Crawl validation                                                           */
/* -------------------------------------------------------------------------- */

function isUsefulCrawlLink(link, source, currentUrl) {
  if (!link?.url) {
    return false;
  }

  if (!isHttp(link.url)) {
    return false;
  }

  if (isBlockedPath(link.url)) {
    return false;
  }

  if (urlHasOldYear(link.url)) {
    return false;
  }

  if (sameUrl(link.url, currentUrl)) {
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
      const target = new URL(link.url);
      const base = new URL(source.base_url);

      if (target.hostname !== base.hostname) {
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

async function fetchWithTimeout(url) {
  const controller = new AbortController();

  const timer = setTimeout(
    () => controller.abort(),
    FETCH_TIMEOUT_MS
  );

  try {
    const response = await fetch(
      url,
      {
        method: 'GET',
        redirect: 'follow',
        cache: 'no-store',
        signal: controller.signal,
        headers: {
          'User-Agent': 'NorthBharatJobs/2.1',
          'Accept':
            'text/html,application/xhtml+xml,application/pdf,text/plain,*/*',
          'Accept-Language':
            'en-IN,en;q=0.9'
        }
      }
    );

    const contentType = (
      response.headers.get('content-type') || ''
    ).toLowerCase();

    const finalUrl = response.url || url;

    const isPdf =
      contentType.includes('application/pdf') ||
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
      body = await response.text();
    }

    const retryAfterHeader =
      response.headers.get('retry-after');

    return {
      ok: response.ok,
      status: response.status,
      body,
      contentType,
      finalUrl,
      isPdf,
      retryAfter:
        Number(retryAfterHeader || 0) || 0
    };
  } catch (error) {
    const wrapped = new Error(
      `Fetch failed for ${url}: ${error?.message || error}`
    );

    wrapped.status =
      Number(error?.status || 0) || 0;

    wrapped.retryAfter =
      Number(error?.retryAfter || 0) || 0;

    throw wrapped;
  } finally {
    clearTimeout(timer);
  }
}


/* -------------------------------------------------------------------------- */
/* SSC-specific discovery                                                     */
/* -------------------------------------------------------------------------- */

/*
  SSC homepage currently contains a Notice Board and many examination links.
  The normal crawler handles these links, but SSC can also use dynamically
  generated pages. These seed paths are only official SSC paths.

  No URL is fabricated from a job title.
*/

const SSC_SEED_PATHS = [
  '/',
  '/notice-board',
  '/noticeboard',
  '/notices',
  '/portal/noticeboard',
  '/for-candidates'
];


async function discoverSSC(source) {
  const base = new URL(source.base_url);

  const seedUrls = [];

  for (const path of SSC_SEED_PATHS) {
    const url = new URL(path, base.href).href;

    if (!seedUrls.some(existing => sameUrl(existing, url))) {
      seedUrls.push(url);
    }
  }

  const results = [];

  for (const seedUrl of seedUrls) {
    try {
      const response = await fetchWithTimeout(seedUrl);

      if (
        !response.ok ||
        response.isPdf ||
        !response.body
      ) {
        continue;
      }

      const page = {
        url:
          response.finalUrl ||
          seedUrl,

        html:
          response.body,

        depth: 0,

        fallbackTitle:
          'SSC'
      };

      const discovered =
        await crawlPagesFromSeed(
          page,
          source
        );

      results.push(...discovered);
    } catch {
      /*
        One SSC seed failure must not stop
        the other official SSC seeds.
      */
    }
  }

  return deduplicateCandidates(results);
}


/* -------------------------------------------------------------------------- */
/* Linked notification discovery                                              */
/* -------------------------------------------------------------------------- */

function isLikelyRecruitmentNoticeTitle(title, url = '') {
  let value = cleanTitle(title);

  if ((!value || value.length < 12) && url) {
    try {
      const pathname = new URL(url).pathname;
      const filename = decodeURIComponent(pathname.split('/').pop() || '')
        .replace(/\.[a-z0-9]+$/i, '')
        .replace(/[_-]+/g, ' ');
      value = cleanTitle(filename);
    } catch {}
  }

  if (!value || value.length < 12) {
    return false;
  }

  if (/\b(?:result|answer\s*key|admit\s*card|hall\s*ticket|final\s+marks|merit\s+list|shortlisted|selected\s+candidates?|cancellation|postponement|tentative\s+allocation)\b/i.test(value)) {
    return false;
  }

  const yearSignal = new RegExp('\\b(?:' + CURRENT_YEAR + '|' + MIN_ACCEPTABLE_YEAR + ')\\b', 'i').test(value);
  const recruitmentSignal = /\b(?:recruitment|vacanc(?:y|ies)|advertisement|advt?|employment\s+notice|appointment|engagement|application|apply|registration|post|posts|constable|clerk|assistant|engineer|teacher|officer|technician|apprentice|trainee)\b/i.test(value);
  const examinationNoticeSignal = /\bexamination\b/i.test(value) && /\b(?:notice|notification|advertisement|application|recruitment)\b/i.test(value);

  return yearSignal && (recruitmentSignal || examinationNoticeSignal);
}

function makeLinkedNotificationCandidates(page, source) {
  const links = page.links || [];
  const output = [];

  for (const link of links) {
    if (!isPdfUrl(link.url)) {
      continue;
    }

    if (urlHasOldYear(link.url) || isBlockedPath(link.url)) {
      continue;
    }

    try {
      if (!sameHostOrAllowed(link.url, source.allowed_domains, source.base_url)) {
        continue;
      }
    } catch {
      continue;
    }

    const title = cleanTitle(link.text);
    const urlRecruitmentSignal = /(?:notice[_-]?of[_-]?(?:adv|advt|advertisement)|recruitment|vacanc|advertisement|employment|appointment)/i.test(link.url);

    if (!isLikelyRecruitmentNoticeTitle(title, link.url) && !urlRecruitmentSignal) {
      continue;
    }

    const notificationUrl = normalizeUrl(link.url);
    const applyUrl = findApplyLink(links, page.url, notificationUrl, source);
    const body = textOf(page.html || '');
    const fields = extractCandidateFields(body, source);
    const canonicalUrl = normalizeUrl(page.url);

    output.push({
      type: 'job',
      title,
      organization: source.name,
      category: 'job',
      location: null,
      description: body.slice(0, 3000).trim() || null,
      eligibility: fields.qualification || null,
      qualification: fields.qualification || null,
      vacancies: fields.vacancies || null,
      age_limit: fields.age_limit || null,
      age_relaxation: null,
      fee: fields.fee || null,
      selection_process: fields.selection_process || null,
      salary: fields.salary || null,
      application_start: fields.application_start || null,
      last_date: fields.last_date || null,
      exam_date: fields.exam_date || null,
      how_to_apply: fields.how_to_apply || null,
      important_dates: null,
      official_url: page.url,
      notification_url: notificationUrl,
      apply_url: applyUrl,
      source_url: page.url,
      source_name: source.name,
      source_id: source.id,
      source_hash: null,
      canonical_url: canonicalUrl,
      notification_key: String(source.id) + '|' + notificationUrl,
      _official: source.role === 'official',
      authority: source.role === 'official' ? 'official' : 'secondary',
      source_role: source.role,
      _linked_notification: true,
      _evidence: ['linked-notification-pdf', 'recruitment-notice-title'],
      _evidence_score: 12,
      _recruitment_score: 12
    });
  }

  return output;
}

/* -------------------------------------------------------------------------- */
/* Generic crawler                                                            */
/* -------------------------------------------------------------------------- */

async function crawlPagesFromSeed(
  firstPage,
  source
) {
  const pages = [];
  const queue = [firstPage];
  const visited = new Set();

  visited.add(
    normalizeUrl(firstPage.url)
  );

  while (
    queue.length &&
    pages.length < MAX_PAGES
  ) {
    const page = queue.shift();

    if (!page?.html) {
      continue;
    }

    pages.push(page);

    const links = parseLinks(
      page.html,
      page.url
    );

    page.links = links;

    /* Notification PDFs are not HTML pages, so create candidates from their anchor text. */
    const linkedCandidates = makeLinkedNotificationCandidates(page, source);

    pages.push(...linkedCandidates.map(candidate => ({
      ...page,
      __candidate: candidate
    })));

    if (page.depth >= MAX_DEPTH) {
      continue;
    }

    const ranked = links
      .filter(link =>
        isUsefulCrawlLink(
          link,
          source,
          page.url
        )
      )
      .map(link => ({
        link,
        score: linkPriority(
          link,
          textOf(page.html).slice(0, 12000)
        )
      }))
      .sort((a, b) => b.score - a.score)
      .slice(0, MAX_LINKS_PER_PAGE);

    for (const entry of ranked) {
      const link = entry.link;

      if (isPdfUrl(link.url)) {
        continue;
      }

      const normalized =
        normalizeUrl(link.url);

      if (!normalized) {
        continue;
      }

      if (visited.has(normalized)) {
        continue;
      }

      if (
        pages.length + queue.length >=
        MAX_PAGES
      ) {
        break;
      }

      visited.add(normalized);

      try {
        const response =
          await fetchWithTimeout(normalized);

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
          Ignore individual child-page errors.
        */
      }
    }
  }

  pages.sort(
    (a, b) =>
      pageScore(b, source) -
      pageScore(a, source)
  );

  const candidates = [];

  for (const page of pages) {
    if (page.__candidate) {
      candidates.push(page.__candidate);
      continue;
    }

    const candidate =
      makeCandidate(
        page,
        source
      );

    if (candidate) {
      candidates.push(candidate);
    }
  }

  return candidates;
}


/* -------------------------------------------------------------------------- */
/* Classification                                                             */
/* -------------------------------------------------------------------------- */

function classify(title, body, links) {
  const titleText = cleanTitle(title);

  const linkText =
    (links || [])
      .map(link => link.text)
      .join(' ');

  const bodyText =
    String(body || '').slice(0, 16000);

  for (const [category, patterns] of Object.entries(CATEGORY_PATTERNS)) {
    if (
      patterns.some(pattern =>
        pattern.test(titleText)
      )
    ) {
      return category;
    }
  }

  for (const [category, patterns] of Object.entries(CATEGORY_PATTERNS)) {
    if (
      patterns.some(pattern =>
        pattern.test(linkText)
      )
    ) {
      return category;
    }
  }

  for (const [category, patterns] of Object.entries(CATEGORY_PATTERNS)) {
    if (
      patterns.some(pattern =>
        pattern.test(bodyText)
      )
    ) {
      return category;
    }
  }

  return null;
}


/* -------------------------------------------------------------------------- */
/* Date extraction                                                            */
/* -------------------------------------------------------------------------- */

function extractDate(text, labels = []) {
  const source = String(text || '');

  if (labels.length) {
    const labelPattern =
      new RegExp(
        '(?:' +
          labels.join('|') +
        ')[^\\n]{0,120}?(\\d{1,2}[\\/.-]\\d{1,2}[\\/.-]20\\d{2}|\\d{1,2}\\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\s+20\\d{2}|(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\\s+\\d{1,2},?\\s+20\\d{2})',
        'i'
      );

    const labelled =
      source.match(labelPattern);

    if (labelled?.[1]) {
      return labelled[1];
    }
  }

  const general =
    source.match(
      /\b\d{1,2}[\/.-]\d{1,2}[\/.-]20\d{2}\b/
    );

  if (general?.[0]) {
    return general[0];
  }

  const month =
    source.match(
      /\b\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+20\d{2}\b/i
    );

  if (month?.[0]) {
    return month[0];
  }

  return null;
}


/* -------------------------------------------------------------------------- */
/* Recruitment evidence                                                       */
/* -------------------------------------------------------------------------- */

function recruitmentEvidence(title, body, links) {
  const titleText =
    compactText(title);

  const bodyText =
    compactText(
      String(body || '').slice(0, 24000)
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

  if (/\brecruitment\b|\brecruit\b/i.test(titleText)) {
    score += 4;
    evidence.push('recruitment-title');
  }

  if (
    /\badvertisement\b|\bemployment\s+notice\b|\bdetailed\s+advertisement\b/i.test(titleText)
  ) {
    score += 4;
    evidence.push('advertisement-title');
  }

  if (
    /\b\d+\s+(?:posts?|vacancies?)\b/i.test(bodyText)
  ) {
    score += 2;
    evidence.push('post-count');
  }

  if (
    /\bonline\s+application\b|\bapply\s+online\b|\bapplication\s+form\b/i.test(bodyText)
  ) {
    score += 2;
    evidence.push('application');
  }

  if (
    /\blast\s+date\b|\bclosing\s+date\b|\bdeadline\b/i.test(bodyText)
  ) {
    score += 2;
    evidence.push('deadline');
  }

  if (
    /\beligib(?:le|ility)\b|\bqualification\b|\beducational\s+qualification\b/i.test(bodyText)
  ) {
    score += 2;
    evidence.push('eligibility');
  }

  if (
    /\bselection\s+process\b|\bselection\s+procedure\b|\bwritten\s+exam\b|\binterview\b/i.test(bodyText)
  ) {
    score += 1;
    evidence.push('selection');
  }

  if (
    /\bapplication\s+fee\b|\bexam\s+fee\b/i.test(bodyText)
  ) {
    score += 1;
    evidence.push('fee');
  }

  if (
    (links || []).some(link =>
      isPdfUrl(link.url)
    )
  ) {
    score += 2;
    evidence.push('pdf-link');
  }

  if (
    (links || []).some(link =>
      !isPdfUrl(link.url) &&
      STRONG_APPLY_PATTERN.test(
        `${link.text} ${link.url}`
      )
    )
  ) {
    score += 3;
    evidence.push('apply-link');
  }

  return {
    score,
    strongRecruitment: score >= 8,
    evidence
  };
}


/* -------------------------------------------------------------------------- */
/* Category evidence                                                          */
/* -------------------------------------------------------------------------- */

function categoryEvidence(category, title, body, links) {
  const combined =
    compactText(
      `${title} ${String(body || '').slice(0, 12000)} ${(links || [])
        .map(link => link.text)
        .join(' ')}`
    );

  const patterns =
    CATEGORY_PATTERNS[category] || [];

  let score = 0;

  for (const pattern of patterns) {
    if (pattern.test(combined)) {
      score++;
    }
  }

  return {
    score,
    strong: score >= 2
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
    (links || []).filter(link => {
      if (!isPdfUrl(link.url)) {
        return false;
      }

      if (urlHasOldYear(link.url)) {
        return false;
      }

      if (isBlockedPath(link.url)) {
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

  if (!officialLinks.length) {
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

  if (explicit.length) {
    return explicit[0].url;
  }

  if (
    /\brecruitment\b|\bvacanc(?:y|ies)\b|\badvertisement\b|\bnotification\b|\bemployment\s+notice\b|\bappointment\b/i.test(
      pageContext
    )
  ) {
    const ranked =
      officialLinks
        .map(link => ({
          link,
          score: linkPriority(
            link,
            pageContext
          )
        }))
        .sort(
          (a, b) =>
            b.score - a.score
        );

    if (ranked[0]) {
      return ranked[0].link.url;
    }
  }

  const urlSignal =
    officialLinks.find(link =>
      /\b(?:adv|advt|advertisement|notification|notice|recruitment|vacancy|employment|appointment|detailed)\b/i.test(
        link.url
      )
    );

  return urlSignal?.url || null;
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
    (links || []).filter(link => {
      if (!isHttp(link.url)) {
        return false;
      }

      if (isPdfUrl(link.url)) {
        return false;
      }

      if (sameUrl(link.url, sourceUrl)) {
        return false;
      }

      if (
        notificationUrl &&
        sameUrl(link.url, notificationUrl)
      ) {
        return false;
      }

      if (urlHasOldYear(link.url)) {
        return false;
      }

      if (isBlockedPath(link.url)) {
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
        STRONG_APPLY_PATTERN.test(
          `${link.text} ${link.url}`
        )
      )
      .sort(
        (a, b) =>
          linkPriority(b) -
          linkPriority(a)
      );

  if (explicit.length) {
    return explicit[0].url;
  }

  const endpoint =
    candidates
      .filter(link =>
        /\/(?:apply|application|registration|register|online-?apply|candidate)\b/i.test(
          new URL(link.url).pathname
        )
      )
      .sort(
        (a, b) =>
          linkPriority(b) -
          linkPriority(a)
      );

  if (endpoint.length) {
    return endpoint[0].url;
  }

  return null;
}


/* -------------------------------------------------------------------------- */
/* Title extraction                                                           */
/* -------------------------------------------------------------------------- */

function extractBestTitle(html, fallback) {
  const headings = [];

  const headingRegex =
    /<h[1-3]\b[^>]*>([\s\S]*?)<\/h[1-3]>/gi;

  let match;

  while (
    (match = headingRegex.exec(html)) &&
    headings.length < 20
  ) {
    const title =
      cleanTitle(
        textOf(match[1])
      );

    if (title) {
      headings.push(title);
    }
  }

  const goodHeading =
    headings.find(title =>
      hasSpecificTitle(title)
    );

  if (goodHeading) {
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

  if (hasSpecificTitle(pageTitle)) {
    return pageTitle;
  }

  return cleanTitle(fallback);
}


/* -------------------------------------------------------------------------- */
/* Field extraction                                                           */
/* -------------------------------------------------------------------------- */

function extractLabeledValue(body, labels) {
  const label = labels.join('|');

  const regex =
    new RegExp(
      `(?:${label})\\s*(?:[:\\-]|is)?\\s*([^|]{2,180})`,
      'i'
    );

  const match =
    String(body || '').match(regex);

  if (!match?.[1]) {
    return null;
  }

  const value =
    match[1]
      .replace(/\s+/g, ' ')
      .trim();

  if (!value || value.length > 180) {
    return null;
  }

  return value;
}


function extractCandidateFields(
  body,
  source
) {
  const text =
    String(body || '').slice(0, 30000);

  return {
    application_start:
      extractDate(
        text,
        [
          'application\\s+start',
          'starting\\s+date',
          'start\\s+date',
          'online\\s+application\\s+from',
          'apply\\s+from'
        ]
      ),

    last_date:
      extractDate(
        text,
        [
          'last\\s+date',
          'closing\\s+date',
          'last\\s+date\\s+for',
          'application\\s+last\\s+date',
          'deadline'
        ]
      ),

    exam_date:
      extractDate(
        text,
        [
          'exam\\s+date',
          'date\\s+of\\s+exam',
          'written\\s+exam',
          'examination\\s+date'
        ]
      ),

    vacancies:
      extractLabeledValue(
        text,
        [
          'vacancies?',
          'no\\.\\s*of\\s*vacancies?',
          'number\\s+of\\s+posts?',
          'total\\s+posts?'
        ]
      ),

    qualification:
      extractLabeledValue(
        text,
        [
          'educational\\s+qualification',
          'qualification',
          'essential\\s+qualification',
          'minimum\\s+qualification'
        ]
      ),

    age_limit:
      extractLabeledValue(
        text,
        [
          'age\\s+limit',
          'maximum\\s+age',
          'minimum\\s+age'
        ]
      ),

    fee:
      extractLabeledValue(
        text,
        [
          'application\\s+fee',
          'exam\\s+fee',
          'registration\\s+fee'
        ]
      ),

    selection_process:
      extractLabeledValue(
        text,
        [
          'selection\\s+process',
          'selection\\s+procedure',
          'mode\\s+of\\s+selection'
        ]
      ),

    salary:
      extractLabeledValue(
        text,
        [
          'salary',
          'pay\\s+scale',
          'pay\\s+level',
          'remuneration',
          'stipend'
        ]
      ),

    how_to_apply:
      /\bhow\s+to\s+apply\b/i.test(text)
        ? 'Apply through the official application link.'
        : null,

    organization:
      source?.name || null
  };
}


/* -------------------------------------------------------------------------- */
/* Candidate creation                                                         */
/* -------------------------------------------------------------------------- */

function makeCandidate(page, source) {
  const pageUrl = page.url;
  const html = page.html;
  const links = page.links || [];

  const title =
    extractBestTitle(
      html,
      page.fallbackTitle || ''
    );

  const body = textOf(html);

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

  if (urlHasOldYear(pageUrl)) {
    return null;
  }

  const category =
    classify(
      title,
      body,
      links
    );

  if (!category) {
    return null;
  }

  const recruitment =
    recruitmentEvidence(
      title,
      body,
      links
    );

  if (
    category === 'job' &&
    !recruitment.strongRecruitment
  ) {
    return null;
  }

  const fields =
    extractCandidateFields(
      body,
      source
    );

  const pageContext =
    compactText(
      `${title} ${body.slice(0, 22000)}`
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

  /*
    A recruitment candidate without direct
    PDF/apply URL is retained only when evidence
    is very strong so monitor.js can send it
    through secondary verification.
  */
  if (
    category === 'job' &&
    (
      !notificationUrl ||
      !applyUrl
    ) &&
    recruitment.score < 10
  ) {
    return null;
  }

  if (category !== 'job') {
    const evidence =
      categoryEvidence(
        category,
        title,
        body,
        links
      );

    if (!evidence.strong) {
      return null;
    }
  }

  const canonicalUrl =
    normalizeUrl(pageUrl);

  const notificationKeyBase =
    notificationUrl ||
    canonicalUrl ||
    pageUrl;

  const notificationKey =
    `${source.id}|${normalizeUrl(notificationKeyBase)}`;

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
      body.slice(0, 3000).trim() || null,

    eligibility:
      fields.qualification || null,

    qualification:
      fields.qualification || null,

    vacancies:
      fields.vacancies || null,

    age_limit:
      fields.age_limit || null,

    age_relaxation:
      null,

    fee:
      fields.fee || null,

    selection_process:
      fields.selection_process || null,

    salary:
      fields.salary || null,

    application_start:
      fields.application_start || null,

    last_date:
      fields.last_date || null,

    exam_date:
      fields.exam_date || null,

    how_to_apply:
      fields.how_to_apply || null,

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
/* Page ranking                                                               */
/* -------------------------------------------------------------------------- */

function pageScore(page) {
  const title =
    compactText(
      page.fallbackTitle || ''
    );

  const url =
    compactText(page.url);

  const body =
    compactText(
      page.html?.slice(0, 14000) || ''
    );

  let score = 0;

  if (
    /\brecruitment|vacancy|advertisement|notification\b/i.test(title)
  ) {
    score += 15;
  }

  if (
    /\brecruitment|vacancy|advertisement|notification\b/i.test(url)
  ) {
    score += 12;
  }

  if (/\b20\d{2}\b/.test(title)) {
    score += 5;
  }

  if (
    /\bapply\s+online\b|\bonline\s+application\b/i.test(body)
  ) {
    score += 5;
  }

  if (
    /\blast\s+date\b|\bdeadline\b/i.test(body)
  ) {
    score += 5;
  }

  if (
    page.links?.some(link =>
      isPdfUrl(link.url)
    )
  ) {
    score += 5;
  }

  if (
    page.links?.some(link =>
      STRONG_APPLY_PATTERN.test(
        `${link.text} ${link.url}`
      )
    )
  ) {
    score += 7;
  }

  if (page.depth === 0) {
    score -= 2;
  }

  return score;
}


/* -------------------------------------------------------------------------- */
/* Candidate deduplication                                                    */
/* -------------------------------------------------------------------------- */

function deduplicateCandidates(
  candidates
) {
  const seen = new Set();
  const output = [];

  for (const candidate of candidates || []) {
    const identity =
      normalizeUrl(
        candidate.notification_url ||
        candidate.canonical_url ||
        candidate.source_url
      );

    if (!identity) {
      continue;
    }

    if (seen.has(identity)) {
      continue;
    }

    seen.add(identity);
    output.push(candidate);
  }

  output.sort(
    (a, b) =>
      Number(b._evidence_score || 0) -
      Number(a._evidence_score || 0)
  );

  return output.slice(0, MAX_LINKS);
}


/* -------------------------------------------------------------------------- */
/* Main official discovery                                                   */
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

  const homepage =
    normalizeUrl(
      source.base_url
    );

  if (!homepage) {
    throw new Error(
      `Invalid source URL: ${source.base_url}`
    );
  }

  /*
    SSC gets an additional official-only
    discovery path because its current website
    uses a Notice Board / candidate structure.
  */
  if (
    String(source.adapter || '').toLowerCase() === 'ssc'
  ) {
    return discoverSSC(source);
  }

  const first =
    await fetchWithTimeout(
      homepage
    );

  if (!first.ok) {
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

  const firstPage = {
    url:
      first.finalUrl ||
      homepage,

    html:
      first.body,

    depth:
      0,

    fallbackTitle:
      source.name
  };

  const candidates =
    await crawlPagesFromSeed(
      firstPage,
      source
    );

  return deduplicateCandidates(
    candidates
  );
}


/* -------------------------------------------------------------------------- */
/* Portal discovery                                                           */
/* -------------------------------------------------------------------------- */

export async function discoverPortal(
  source
) {
  return discoverFromSource(
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
