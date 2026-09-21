import {
  isPdfUrl,
  normalizeUrl,
  sameHostOrAllowed
} from './verification.js';

/*
  North Bharat Jobs
  Official-source discovery engine

  STRICT DISCOVERY RULES
  ----------------------
  1. Never invent URLs.
  2. Official domain alone is NOT evidence.
  3. Generic pages are never public records.
  4. Administrative/static documents are blocked.
  5. Old-year material is blocked.
  6. Every category has its own evidence gate.
  7. Recruitment requires:
       - strong recruitment evidence
       - real notification PDF
       - real current application URL
       - three distinct URLs
       - official-domain validation
  8. Admit/Result/Answer Key/Syllabus/Admission/Scholarship
     require category-specific evidence.
  9. Stable identity is the official detail page.
 10. Never invent or guess missing URLs.
*/

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const MAX_LINKS = 220;
const MAX_PAGES = 22;
const MAX_LINKS_PER_PAGE = 150;
const FETCH_TIMEOUT_MS = 12000;

const CURRENT_YEAR = new Date().getUTCFullYear();
const MIN_ACCEPTABLE_YEAR = CURRENT_YEAR - 1;

/* -------------------------------------------------------------------------- */
/* Category words                                                             */
/* -------------------------------------------------------------------------- */

const WORDS = {
  job:
    /\b(recruitment|recruit|vacanc(?:y|ies)|appointment|advertisement|employment\s+notice|job\s+notification|post(?:s)?\s+of|hiring|engagement|selection\s+process|application\s+form|staff\s+selection)\b/i,

  admit:
    /\b(admit\s*card|admission\s*card|hall\s*ticket|call\s*letter|e[-\s]?admit|download\s+admit|download\s+hall\s*ticket)\b/i,

  result:
    /\b(result|merit\s*list|selection\s*list|short\s*list|shortlist|final\s*result|provisional\s*result|qualified\s*candidates|selected\s*candidates|marks\s*list|score\s*card)\b/i,

  answer:
    /\b(answer\s*key|response\s*sheet|answer\s*sheet|provisional\s*answer|final\s*answer\s*key|objection\s*tracker|question\s*paper\s*with\s*answer)\b/i,

  syllabus:
    /\b(syllabus|scheme\s*(?:and|&)\s*syllabus|exam\s*scheme|scheme\s*of\s*examination|course\s*syllabus)\b/i,

  admission:
    /\b(admission|entrance\s*(?:exam|test)|entrance\s*examination|counselling|counseling|seat\s*allotment|admission\s*notice|admission\s*schedule)\b/i,

  scholarship:
    /\bscholarship\b/i
};

/* -------------------------------------------------------------------------- */
/* Application signals                                                        */
/* -------------------------------------------------------------------------- */

const APPLY =
  /\b(apply\s*(?:online|now|here)|online\s*application|application\s*(?:form|portal|link)|registration\s*(?:link|portal|form)?|register\s*(?:online|now)|apply\s*link|online\s*registration|candidate\s*registration|application\s*portal)\b/i;

/* -------------------------------------------------------------------------- */
/* Recruitment notification signals                                           */
/* -------------------------------------------------------------------------- */

const NOTIFICATION_SIGNAL =
  /\b(notification|advertisement|recruitment|recruitment\s*notice|employment\s*notice|vacanc(?:y|ies)|selection\s*notice|appointment|corrigendum|extension|job\s*notice|employment|engagement\s*notice)\b/i;

/* -------------------------------------------------------------------------- */
/* Strong administrative/static negative signals                               */
/* -------------------------------------------------------------------------- */

const ADMIN_DOCUMENT =
  /\b(rti|right\s*to\s*information|policy|policies|affidavit|certificate|proforma|form(?:s)?\s+for|annual\s*report|annual\s*reports|tender|procurement|minutes|meeting|budget|press\s*release|calendar|rules|manual|guidelines|terms\s+and\s+conditions|privacy|disclaimer|citizen\s*charter|office\s*order|office\s*memorandum|memorandum|circular\s+for\s+administration)\b/i;

/* -------------------------------------------------------------------------- */
/* Generic/static page signals                                                */
/* -------------------------------------------------------------------------- */

const GENERIC_TITLE =
  /^(home|homepage|welcome|index|about|contact|feedback|login|sign\s*in|careers?|career|results?|result|syllabus|admit\s*card|answer\s*key|scholarship|admission|recruitment|advertisement|notifications?|notices?|latest\s*news|important\s*links)$/i;

const GENERIC_ORG_TITLE =
  /^(home\s*[\|\-:]|welcome\s*[\|\-:]|about\s*[\|\-:]|careers?\s*[\|\-:]|results?\s*[\|\-:]|syllabus\s*[\|\-:]|notifications?\s*[\|\-:])/i;

/* -------------------------------------------------------------------------- */
/* Blocked file/path signals                                                  */
/* -------------------------------------------------------------------------- */

const BLOCKED_FILE =
  /\b(rti|right[_-]?to[_-]?information|policy|policies|affidavit|certificate|proforma|annual[_-]?report|tender|procurement|minutes|meeting|budget|press[_-]?release|calendar|rules|manual|guidelines|office[_-]?order|memorandum|privacy|disclaimer)\b/i;

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
      .replace(/<option[\s\S]*?<\/option>/gi, ' ')
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

function compactText(value = '') {
  return normalizedText(value)
    .replace(/[|:;,()[\]{}]+/g, ' ')
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

function hasCurrentOrRecentYear(value = '') {
  const years =
    String(value).match(/\b(19|20)\d{2}\b/g) || [];

  if (!years.length) {
    return false;
  }

  return years.some(year => {
    const y = Number(year);
    return y >= MIN_ACCEPTABLE_YEAR;
  });
}

function isBlockedPath(url = '', text = '') {
  const value =
    normalizedText(`${url} ${text}`);

  return BLOCKED_FILE.test(value);
}

/* -------------------------------------------------------------------------- */
/* Generic page detection                                                     */
/* -------------------------------------------------------------------------- */

function isGenericPage(url = '', text = '') {
  const title = cleanTitle(text);
  const value = normalizedText(`${url} ${text}`);

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

  if (GENERIC_TITLE.test(title)) {
    return true;
  }

  if (GENERIC_ORG_TITLE.test(title)) {
    return true;
  }

  /*
    A page whose URL itself is a generic section landing page
    must not become an item.
  */
  try {
    const parsed = new URL(url);
    const path = parsed.pathname.toLowerCase();

    if (
      /\/(about|contact|feedback|privacy|terms|disclaimer|rti|careers?|login|signin)(\/|$)/i.test(
        path
      )
    ) {
      return true;
    }
  } catch {
    /* Ignore */
  }

  /*
    Do not reject specific pages simply because their body contains
    words such as "career", "result", "syllabus", etc.
  */
  if (
    /\b(login|sign[\s-]?in)\b/.test(value) &&
    !/\b(application|registration|candidate|apply)\b/.test(value)
  ) {
    return true;
  }

  return false;
}

function looksLikeGenericCareerPage(url = '', text = '') {
  const value =
    normalizedText(`${url} ${text}`);

  return (
    /\bcareers?\b/.test(value) &&
    !/\bapply\b/.test(value) &&
    !/\bapplication\b/.test(value) &&
    !/\bregistration\b/.test(value) &&
    !/\brecruitment\b/.test(value) &&
    !/\bvacanc(?:y|ies)\b/.test(value)
  );
}

function looksLikeLoginOnly(url = '', text = '') {
  const value =
    normalizedText(`${url} ${text}`);

  return (
    /\blogin\b|\bsign[\s-]?in\b/.test(value) &&
    !/\bapplication\b/.test(value) &&
    !/\bregistration\b/.test(value) &&
    !/\bapply\b/.test(value)
  );
}

/* -------------------------------------------------------------------------- */
/* Specific-title detection                                                   */
/* -------------------------------------------------------------------------- */

function hasSpecificTitle(title = '', organization = '') {
  const clean = compactText(title);
  const org = compactText(organization);

  if (!clean || clean.length < 8) {
    return false;
  }

  if (GENERIC_TITLE.test(clean)) {
    return false;
  }

  if (
    /\b(home|homepage|about|contact|careers?|rti|policy|privacy|terms)\b/.test(
      clean
    ) &&
    clean.length < 35
  ) {
    return false;
  }

  if (
    org &&
    clean === org
  ) {
    return false;
  }

  /*
    A title must contain some useful identifying information.
  */
  const identifying =
    /\b(20\d{2}|post|posts|exam|examination|recruitment|vacanc(?:y|ies)|admit|hall|result|merit|selection|answer|response|syllabus|admission|entrance|scholarship|candidate|grade|group|class|officer|assistant|teacher|engineer|clerk|constable|inspector|technician|staff|department|course|programme|program)\b/i;

  return identifying.test(clean);
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

  while (
    (match = re.exec(html)) &&
    out.length < MAX_LINKS
  ) {
    try {
      const rawHref =
        match[1]?.trim();

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
          new URL(
            rawHref,
            base
          ).toString()
        );

      if (!url) continue;

      const text =
        textOf(match[2])
          .slice(0, 500);

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
  const controller =
    new AbortController();

  const timer =
    setTimeout(
      () => controller.abort(),
      FETCH_TIMEOUT_MS
    );

  try {
    const response =
      await fetch(url, {
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
      response.headers.get(
        'content-type'
      ) || '';

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
        normalizeUrl(
          response.url || url
        ) || url,
      retryAfter:
        response.headers.get(
          'retry-after'
        ),
      isPdf:
        /application\/pdf/i.test(
          contentType
        ) ||
        isPdfUrl(
          response.url || url
        )
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
      error:
        String(
          error?.message || error
        )
    };
  } finally {
    clearTimeout(timer);
  }
}

/* -------------------------------------------------------------------------- */
/* Category classification                                                    */
/* -------------------------------------------------------------------------- */

/*
  Classification is intentionally title/link focused.

  We do NOT classify only because some random word appears deep
  inside a long page body.
*/

function classify(title, body, links = []) {
  const titleText =
    compactText(title);

  const linkText =
    compactText(
      links
        .slice(0, 80)
        .map(link =>
          `${link.text} ${link.url}`
        )
        .join(' ')
    );

  const combined =
    `${titleText} ${linkText}`;

  /*
    Specific categories first.
  */

  if (WORDS.admit.test(titleText)) {
    return 'admit_card';
  }

  if (WORDS.answer.test(titleText)) {
    return 'answer_key';
  }

  if (WORDS.result.test(titleText)) {
    return 'result';
  }

  if (WORDS.syllabus.test(titleText)) {
    return 'syllabus';
  }

  if (WORDS.admission.test(titleText)) {
    return 'admission';
  }

  if (WORDS.scholarship.test(titleText)) {
    return 'scholarship';
  }

  if (WORDS.job.test(titleText)) {
    return 'job';
  }

  /*
    Then strong link-level evidence.
  */

  if (WORDS.admit.test(linkText)) {
    return 'admit_card';
  }

  if (WORDS.answer.test(linkText)) {
    return 'answer_key';
  }

  if (WORDS.result.test(linkText)) {
    return 'result';
  }

  if (WORDS.syllabus.test(linkText)) {
    return 'syllabus';
  }

  if (WORDS.admission.test(linkText)) {
    return 'admission';
  }

  if (WORDS.scholarship.test(linkText)) {
    return 'scholarship';
  }

  if (WORDS.job.test(linkText)) {
    return 'job';
  }

  /*
    Body is used only as a final signal and requires
    multiple category-specific terms.
  */

  const bodyText =
    normalizedText(
      body.slice(0, 14000)
    );

  if (
    WORDS.admit.test(bodyText) &&
    /\b(download|candidate|hall|ticket|roll\s*number|exam\s*centre)\b/i.test(
      bodyText
    )
  ) {
    return 'admit_card';
  }

  if (
    WORDS.answer.test(bodyText) &&
    /\b(download|objection|question|paper|response|candidate)\b/i.test(
      bodyText
    )
  ) {
    return 'answer_key';
  }

  if (
    WORDS.result.test(bodyText) &&
    /\b(download|qualified|selected|merit|marks|roll\s*number|candidate)\b/i.test(
      bodyText
    )
  ) {
    return 'result';
  }

  if (
    WORDS.syllabus.test(bodyText) &&
    /\b(exam|subject|paper|course|unit|chapter|scheme)\b/i.test(
      bodyText
    )
  ) {
    return 'syllabus';
  }

  if (
    WORDS.admission.test(bodyText) &&
    /\b(course|entrance|candidate|college|university|seat|registration)\b/i.test(
      bodyText
    )
  ) {
    return 'admission';
  }

  if (
    WORDS.scholarship.test(bodyText) &&
    /\b(student|scheme|application|eligib|amount|academic|year)\b/i.test(
      bodyText
    )
  ) {
    return 'scholarship';
  }

  if (
    WORDS.job.test(bodyText) &&
    /\b(vacanc(?:y|ies)|post|posts|application|eligib|qualification|selection)\b/i.test(
      bodyText
    )
  ) {
    return 'job';
  }

  return null;
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
    const match =
      text.match(pattern);

    if (match?.[1]) {
      return match[1].trim();
    }
  }

  return null;
}

/* -------------------------------------------------------------------------- */
/* Recruitment evidence                                                      */
/* -------------------------------------------------------------------------- */

function recruitmentEvidence(
  title,
  body,
  links
) {
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
    evidence.push(
      'recruitment-title'
    );
  }

  if (
    /\badvertisement\b|\bemployment\s+notice\b|\bjob\s+notification\b/.test(
      titleText
    )
  ) {
    score += 3;
    evidence.push(
      'recruitment-advertisement-title'
    );
  }

  if (
    /\bnumber of posts\b|\bno\.?\s*of posts\b|\btotal posts\b|\bvacanc(?:y|ies)\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push(
      'vacancy-or-post-count'
    );
  }

  if (
    /\bonline application\b|\bapplication form\b|\bregistration\b|\bapply online\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push(
      'application-signal'
    );
  }

  if (
    /\blast date\b|\bclosing date\b|\bapply by\b|\bdeadline\b|\bclosing\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push(
      'last-date'
    );
  }

  if (
    /\beligib(?:ility|le)\b|\bqualification\b|\beducational qualification\b|\bessential qualification\b/.test(
      bodyText
    )
  ) {
    score += 2;
    evidence.push(
      'eligibility'
    );
  }

  if (
    /\bselection process\b|\bselection procedure\b|\bwritten examination\b|\binterview\b|\bskill test\b/.test(
      bodyText
    )
  ) {
    score += 1;
    evidence.push(
      'selection-process'
    );
  }

  if (
    /\bapplication fee\b|\bexam fee\b|\bprocessing fee\b/.test(
      bodyText
    )
  ) {
    score += 1;
    evidence.push(
      'fee'
    );
  }

  const hasNotification =
    links.some(link => {
      if (!isPdfUrl(link.url)) {
        return false;
      }

      if (urlHasOldYear(link.url)) {
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

      return NOTIFICATION_SIGNAL.test(
        `${link.text} ${link.url}`
      );
    });

  if (hasNotification) {
    score += 3;
    evidence.push(
      'recruitment-notification-pdf'
    );
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
    evidence.push(
      'current-apply-link'
    );
  }

  return {
    score,
    evidence
  };
}

/* -------------------------------------------------------------------------- */
/* Category evidence helpers                                                  */
/* -------------------------------------------------------------------------- */

function categoryEvidence(
  type,
  title,
  body,
  links,
  sourceUrl
) {
  const titleText =
    normalizedText(title);

  const bodyText =
    normalizedText(
      body.slice(0, 16000)
    );

  const linkText =
    normalizedText(
      links
        .slice(0, 100)
        .map(link =>
          `${link.text} ${link.url}`
        )
        .join(' ')
    );

  const evidence = [];
  let score = 0;

  /*
    Never allow administrative documents to become
    category records.
  */
  const adminInDocument =
    ADMIN_DOCUMENT.test(
      `${sourceUrl} ${title}`
    );

  if (adminInDocument) {
    return {
      ok: false,
      score: 0,
      evidence: [
        'administrative-document-blocked'
      ]
    };
  }

  /*
    ------------------------------------------------------------------------
    ADMIT CARD
    ------------------------------------------------------------------------
  */

  if (type === 'admit_card') {
    const strongTitle =
      /\badmit\s*card\b|\bhall\s*ticket\b|\bcall\s*letter\b|\be[-\s]?admit\b/i.test(
        titleText
      );

    const strongLink =
      /\badmit\s*card\b|\bhall\s*ticket\b|\bcall\s*letter\b|\be[-\s]?admit\b/i.test(
        linkText
      );

    const operational =
      /\bdownload\b|\broll\s*(?:no|number)\b|\bexam\s*(?:date|centre|center)\b|\bcandidate\b|\bregistration\s*(?:no|number)\b/i.test(
        `${titleText} ${bodyText}`
      );

    if (strongTitle) {
      score += 7;
      evidence.push(
        'admit-title'
      );
    } else if (strongLink) {
      score += 6;
      evidence.push(
        'admit-link'
      );
    }

    if (operational) {
      score += 3;
      evidence.push(
        'admit-operational-context'
      );
    }

    const admitFile =
      links.some(link =>
        isPdfUrl(link.url) &&
        !urlHasOldYear(link.url) &&
        /\b(admit|hall[-_\s]?ticket|call[-_\s]?letter|e[-_\s]?admit)\b/i.test(
          `${link.text} ${link.url}`
        )
      );

    if (admitFile) {
      score += 3;
      evidence.push(
        'admit-document'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle || strongLink) &&
        operational,
      score,
      evidence
    };
  }

  /*
    ------------------------------------------------------------------------
    RESULT
    ------------------------------------------------------------------------
  */

  if (type === 'result') {
    const strongTitle =
      /\b(result|merit\s*list|selection\s*list|short\s*list|shortlist|final\s*result|provisional\s*result|selected\s*candidates|qualified\s*candidates|marks\s*list|score\s*card)\b/i.test(
        titleText
      );

    const strongLink =
      /\b(result|merit|selection[-_\s]?list|short[-_\s]?list|score[-_\s]?card|marks[-_\s]?list)\b/i.test(
        linkText
      );

    const operational =
      /\b(download|qualified|selected|merit|marks|score|candidate|roll\s*(?:no|number)|cut[\s-]?off|provisional|final)\b/i.test(
        `${titleText} ${bodyText}`
      );

    if (strongTitle) {
      score += 7;
      evidence.push(
        'result-title'
      );
    } else if (strongLink) {
      score += 6;
      evidence.push(
        'result-link'
      );
    }

    if (operational) {
      score += 3;
      evidence.push(
        'result-operational-context'
      );
    }

    const resultFile =
      links.some(link =>
        !urlHasOldYear(link.url) &&
        (
          isPdfUrl(link.url) ||
          /\b(result|merit|selection|score|marks)\b/i.test(
            `${link.text} ${link.url}`
          )
        )
      );

    if (resultFile) {
      score += 2;
      evidence.push(
        'result-document-or-link'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle || strongLink) &&
        operational,
      score,
      evidence
    };
  }

  /*
    ------------------------------------------------------------------------
    ANSWER KEY
    ------------------------------------------------------------------------
  */

  if (type === 'answer_key') {
    const strongTitle =
      /\b(answer\s*key|response\s*sheet|provisional\s*answer|final\s*answer\s*key|answer\s*sheet)\b/i.test(
        titleText
      );

    const strongLink =
      /\b(answer[-_\s]?key|response[-_\s]?sheet|answer[-_\s]?sheet|objection)\b/i.test(
        linkText
      );

    const operational =
      /\b(download|objection|question|response|candidate|paper|provisional|final)\b/i.test(
        `${titleText} ${bodyText}`
      );

    if (strongTitle) {
      score += 7;
      evidence.push(
        'answer-key-title'
      );
    } else if (strongLink) {
      score += 6;
      evidence.push(
        'answer-key-link'
      );
    }

    if (operational) {
      score += 3;
      evidence.push(
        'answer-key-operational-context'
      );
    }

    const answerFile =
      links.some(link =>
        isPdfUrl(link.url) &&
        !urlHasOldYear(link.url) &&
        /\b(answer|response|objection)\b/i.test(
          `${link.text} ${link.url}`
        )
      );

    if (answerFile) {
      score += 3;
      evidence.push(
        'answer-key-document'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle || strongLink) &&
        operational,
      score,
      evidence
    };
  }

  /*
    ------------------------------------------------------------------------
    SYLLABUS
    ------------------------------------------------------------------------
  */

  if (type === 'syllabus') {
    const strongTitle =
      /\bsyllabus\b|\bscheme\s*(?:and|&)\s*syllabus\b|\bexam\s*scheme\b|\bscheme\s*of\s*examination\b/i.test(
        titleText
      );

    const strongLink =
      /\bsyllabus\b|\bexam[-_\s]?scheme\b/i.test(
        linkText
      );

    const specificSubject =
      /\b(exam|examination|post|subject|paper|course|group|class|grade|recruitment|technical|non[-\s]?technical|teacher|officer|assistant|engineer|clerk|constable|department)\b/i.test(
        `${titleText} ${bodyText.slice(0, 9000)}`
      );

    const syllabusFile =
      links.some(link =>
        isPdfUrl(link.url) &&
        !urlHasOldYear(link.url) &&
        /\b(syllabus|scheme)\b/i.test(
          `${link.text} ${link.url}`
        ) &&
        !ADMIN_DOCUMENT.test(
          `${link.text} ${link.url}`
        )
      );

    if (strongTitle) {
      score += 7;
      evidence.push(
        'syllabus-title'
      );
    } else if (strongLink) {
      score += 6;
      evidence.push(
        'syllabus-link'
      );
    }

    if (specificSubject) {
      score += 3;
      evidence.push(
        'syllabus-specific-exam-or-post'
      );
    }

    if (syllabusFile) {
      score += 3;
      evidence.push(
        'syllabus-document'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle || strongLink) &&
        specificSubject,
      score,
      evidence
    };
  }

  /*
    ------------------------------------------------------------------------
    ADMISSION
    ------------------------------------------------------------------------
  */

  if (type === 'admission') {
    const strongTitle =
      /\badmission\b|\bentrance\s*(?:exam|test|examination)\b|\bcounselling\b|\bcounseling\b|\bseat\s*allotment\b/i.test(
        titleText
      );

    const strongLink =
      /\badmission\b|\bentrance\b|\bcounselling\b|\bcounseling\b|\bseat[-_\s]?allotment\b/i.test(
        linkText
      );

    const operational =
      /\b(course|programme|program|college|university|candidate|registration|entrance|seat|counselling|counseling|application|eligib)\b/i.test(
        `${titleText} ${bodyText}`
      );

    if (strongTitle) {
      score += 7;
      evidence.push(
        'admission-title'
      );
    } else if (strongLink) {
      score += 6;
      evidence.push(
        'admission-link'
      );
    }

    if (operational) {
      score += 3;
      evidence.push(
        'admission-operational-context'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle || strongLink) &&
        operational,
      score,
      evidence
    };
  }

  /*
    ------------------------------------------------------------------------
    SCHOLARSHIP
    ------------------------------------------------------------------------
  */

  if (type === 'scholarship') {
    const strongTitle =
      /\bscholarship\b/i.test(
        titleText
      );

    const strongLink =
      /\bscholarship\b/i.test(
        linkText
      );

    const operational =
      /\b(student|scheme|application|eligib|amount|academic|class|course|year|income|merit)\b/i.test(
        `${titleText} ${bodyText}`
      );

    if (strongTitle) {
      score += 7;
      evidence.push(
        'scholarship-title'
      );
    } else if (strongLink) {
      score += 6;
      evidence.push(
        'scholarship-link'
      );
    }

    if (operational) {
      score += 3;
      evidence.push(
        'scholarship-operational-context'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle || strongLink) &&
        operational,
      score,
      evidence
    };
  }

  return {
    ok: false,
    score: 0,
    evidence: []
  };
}

/* -------------------------------------------------------------------------- */
/* Notification selection                                                     */
/* -------------------------------------------------------------------------- */

function findNotificationLink(
  links,
  source
) {
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

    if (!isPdfUrl(link.url)) {
      continue;
    }

    if (urlHasOldYear(link.url)) {
      continue;
    }

    if (
      isBlockedPath(
        link.url,
        link.text
      )
    ) {
      continue;
    }

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

    if (
      sameUrl(
        link.url,
        sourceUrl
      )
    ) {
      continue;
    }

    if (
      notificationUrl &&
      sameUrl(
        link.url,
        notificationUrl
      )
    ) {
      continue;
    }

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

    if (
      /\b(home|about|contact|rti|syllabus|policy|tender|privacy|terms)\b/i.test(
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

function makeCandidate(
  page,
  source
) {
  const titleMatch =
    page.body.match(
      /<title[^>]*>([\s\S]*?)<\/title>/i
    );

  const title =
    cleanTitle(
      titleMatch?.[1] ||
      textOf(
        page.body
      ).slice(0, 220)
    );

  const body =
    textOf(
      page.body
    ).slice(
      0,
      18000
    );

  const sourceUrl =
    normalizeUrl(
      page.finalUrl ||
      page.url
    );

  if (
    !sourceUrl ||
    !title
  ) {
    return null;
  }

  /*
    Generic pages never become candidates.
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
    Static/admin paths never become candidates.
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
    Old pages never become current records.
  */
  if (
    urlHasOldYear(
      sourceUrl
    )
  ) {
    return null;
  }

  const links =
    linksOf(
      page.body,
      page.finalUrl ||
      page.url
    ).slice(
      0,
      MAX_LINKS_PER_PAGE
    );

  /*
    Category classification now happens AFTER links are known.
  */
  const type =
    classify(
      title,
      body,
      links
    );

  if (!type) {
    return null;
  }

  /*
    Only supported public categories.
  */
  const allowedTypes = new Set([
    'job',
    'admit_card',
    'result',
    'answer_key',
    'syllabus',
    'admission',
    'scholarship'
  ]);

  if (!allowedTypes.has(type)) {
    return null;
  }

  /*
    Specific title requirement.
  */
  if (
    !hasSpecificTitle(
      title,
      source.name
    )
  ) {
    return null;
  }

  /*
    Job notification and application links.
  */
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

  /*
    Recruitment evidence.
  */
  const recruitment =
    recruitmentEvidence(
      title,
      body,
      links
    );

  /*
    Category-specific evidence.
  */
  const category =
    categoryEvidence(
      type,
      title,
      body,
      links,
      sourceUrl
    );

  /*
    ------------------------------------------------------------------------
    JOB / RECRUITMENT GATE
    ------------------------------------------------------------------------
  */

  if (type === 'job') {
    if (
      recruitment.score < 8
    ) {
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

    /*
      The notification itself must also belong to the
      official allowed domain for official sources.
    */
    if (
      source.role === 'official' &&
      !sameHostOrAllowed(
        notification.url,
        source.allowed_domains
      )
    ) {
      return null;
    }

    /*
      Apply URL must also be within allowed official domains
      for an official source.
    */
    if (
      source.role === 'official' &&
      !sameHostOrAllowed(
        apply.url,
        source.allowed_domains
      )
    ) {
      return null;
    }
  }

  /*
    ------------------------------------------------------------------------
    NON-JOB CATEGORY GATE
    ------------------------------------------------------------------------
  */

  if (
    type !== 'job' &&
    !category.ok
  ) {
    return null;
  }

  /*
    Public official URL.
  */
  const officialUrl =
    source.role === 'official'
      ? sourceUrl
      : null;

  /*
    For non-job categories, the actual relevant document
    is used when available.

    This is NOT forced to exist because some official
    result/admit pages may provide a dynamic link instead
    of a PDF.
  */
  let categoryDocument = null;

  if (type === 'admit_card') {
    categoryDocument =
      links.find(link =>
        !urlHasOldYear(link.url) &&
        /\b(admit|hall[-_\s]?ticket|call[-_\s]?letter|e[-_\s]?admit)\b/i.test(
          `${link.text} ${link.url}`
        ) &&
        (
          isPdfUrl(link.url) ||
          /\b(download|view|print)\b/i.test(
            link.text
          )
        )
      ) || null;
  }

  if (type === 'result') {
    categoryDocument =
      links.find(link =>
        !urlHasOldYear(link.url) &&
        /\b(result|merit|selection[-_\s]?list|score[-_\s]?card|marks[-_\s]?list)\b/i.test(
          `${link.text} ${link.url}`
        )
      ) || null;
  }

  if (type === 'answer_key') {
    categoryDocument =
      links.find(link =>
        !urlHasOldYear(link.url) &&
        /\b(answer[-_\s]?key|response[-_\s]?sheet|answer[-_\s]?sheet|objection)\b/i.test(
          `${link.text} ${link.url}`
        )
      ) || null;
  }

  if (type === 'syllabus') {
    categoryDocument =
      links.find(link =>
        !urlHasOldYear(link.url) &&
        /\b(syllabus|scheme)\b/i.test(
          `${link.text} ${link.url}`
        ) &&
        !ADMIN_DOCUMENT.test(
          `${link.text} ${link.url}`
        )
      ) || null;
  }

  /*
    Admission can legitimately have an application link.
  */
  let categoryApply = null;

  if (type === 'admission') {
    categoryApply =
      findApplyLink(
        links,
        sourceUrl,
        null
      );
  }

  /*
    Use category document as notification_url only for
    non-job records where it is genuinely the relevant
    document. Never use an unrelated PDF.
  */
  let notificationUrl =
    notification?.url || null;

  if (
    type !== 'job' &&
    categoryDocument?.url
  ) {
    notificationUrl =
      categoryDocument.url;
  }

  /*
    For non-job categories, apply_url is only set when
    a real application/registration link exists.
  */
  let applyUrl =
    apply?.url || null;

  if (
    type === 'admission' &&
    categoryApply?.url
  ) {
    applyUrl =
      categoryApply.url;
  }

  /*
    Stable identity:
      official source + canonical official detail page.

    PDF revisions do not create another item.
  */
  const canonicalPage =
    sourceUrl;

  /*
    Evidence score must be high enough for verification.js.
    We deliberately cap invalid candidates by returning null
    before this point.
  */
  const finalEvidenceScore =
    Math.max(
      category.score || 0,
      type === 'job'
        ? recruitment.score
        : category.score
    );

  const finalEvidence =
    [
      ...(type === 'job'
        ? recruitment.evidence
        : []),
      ...(category.evidence || [])
    ];

  return {
    type,

    title,

    organization:
      source.name,

    category:
      type,

    description:
      body.slice(
        0,
        5000
      ),

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

    how_to_apply:
      null,

    important_dates:
      null,

    official_url:
      officialUrl,

    apply_url:
      applyUrl,

    notification_url:
      notificationUrl,

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
      finalEvidenceScore,

    _evidence:
      [...new Set(finalEvidence)],

    _links:
      links.slice(
        0,
        25
      )
  };
}

/* -------------------------------------------------------------------------- */
/* Source discovery                                                          */
/* -------------------------------------------------------------------------- */

export async function discoverFromSource(
  source
) {
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
      home.body.slice(
        0,
        5000
      )
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
    Select links using category signals.

    Generic/static pages are removed BEFORE fetching.
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
    Homepage itself is NEVER a candidate.
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
        response.body.slice(
          0,
          3000
        )
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

export async function discoverPortal(
  source
) {
  return discoverFromSource(
    source
  );
}
