import {
  isPdfUrl,
  normalizeUrl,
  sameHostOrAllowed
} from './verification.js';

/*
  North Bharat Jobs
  Official-source discovery engine

  IMPORTANT
  ---------
  - Never invent URLs.
  - Only official-domain URLs are accepted for official sources.
  - Homepage / generic pages are never published.
  - Administrative/static pages are blocked.
  - Old-year material is blocked.
  - Recruitment requires:
      official detail page
      notification PDF
      real application URL
      three distinct URLs
  - Category-specific evidence is mandatory.
  - Discovery uses multi-level crawling so that
    official listing/index pages can lead to actual notices.
*/

/* -------------------------------------------------------------------------- */
/* Configuration                                                              */
/* -------------------------------------------------------------------------- */

const MAX_LINKS = 300;
const MAX_PAGES = 30;
const MAX_DEPTH = 2;
const MAX_LINKS_PER_PAGE = 180;
const FETCH_TIMEOUT_MS = 12000;

const CURRENT_YEAR =
  new Date().getUTCFullYear();

const MIN_ACCEPTABLE_YEAR =
  CURRENT_YEAR - 1;

/* -------------------------------------------------------------------------- */
/* Category words                                                             */
/* -------------------------------------------------------------------------- */

const WORDS = {
  job:
    /\b(recruitment|recruit|vacanc(?:y|ies)|appointment|advertisement|employment\s+notice|job\s+notification|post(?:s)?\s+of|hiring|engagement|selection\s+process|application\s+form|staff\s+selection|notice\s+of\s+recruitment)\b/i,

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
/* Administrative/static negative signals                                     */
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
/* Blocked path/file signals                                                  */
/* -------------------------------------------------------------------------- */

const BLOCKED_FILE =
  /\b(rti|right[_-]?to[_-]?information|policy|policies|affidavit|certificate|proforma|annual[_-]?report|tender|procurement|minutes|meeting|budget|press[_-]?release|calendar|rules|manual|guidelines|office[_-]?order|memorandum|privacy|disclaimer|citizen[_-]?charter)\b/i;

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
    .slice(0, 240);
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
  return Boolean(
    normalizeUrl(value)
  );
}

function sameUrl(a, b) {
  const x =
    normalizeUrl(a);

  const y =
    normalizeUrl(b);

  if (!x || !y) {
    return false;
  }

  return x === y;
}

function urlHasOldYear(url = '') {
  const matches =
    String(url).match(
      /\b(19|20)\d{2}\b/g
    );

  if (!matches?.length) {
    return false;
  }

  return matches.some(year => {
    const y =
      Number(year);

    return (
      y < MIN_ACCEPTABLE_YEAR
    );
  });
}

function hasCurrentOrRecentYear(value = '') {
  const years =
    String(value).match(
      /\b(19|20)\d{2}\b/g
    ) || [];

  if (!years.length) {
    return false;
  }

  return years.some(year => {
    const y =
      Number(year);

    return (
      y >= MIN_ACCEPTABLE_YEAR
    );
  });
}

function isBlockedPath(
  url = '',
  text = ''
) {
  const value =
    normalizedText(
      `${url} ${text}`
    );

  return BLOCKED_FILE.test(
    value
  );
}

/* -------------------------------------------------------------------------- */
/* Generic page detection                                                     */
/* -------------------------------------------------------------------------- */

function isGenericPage(
  url = '',
  text = ''
) {
  const title =
    cleanTitle(text);

  try {
    const parsed =
      new URL(url);

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
    /* ignore */
  }

  if (
    GENERIC_TITLE.test(title)
  ) {
    return true;
  }

  if (
    GENERIC_ORG_TITLE.test(title)
  ) {
    return true;
  }

  try {
    const parsed =
      new URL(url);

    const path =
      parsed.pathname.toLowerCase();

    if (
      /\/(about|contact|feedback|privacy|terms|disclaimer|rti|login|signin)(\/|$)/i.test(
        path
      )
    ) {
      return true;
    }
  } catch {
    /* ignore */
  }

  return false;
}

function looksLikeGenericCareerPage(
  url = '',
  text = ''
) {
  const value =
    normalizedText(
      `${url} ${text}`
    );

  return (
    /\bcareers?\b/.test(value) &&
    !/\bapply\b/.test(value) &&
    !/\bapplication\b/.test(value) &&
    !/\bregistration\b/.test(value) &&
    !/\brecruitment\b/.test(value) &&
    !/\bvacanc(?:y|ies)\b/.test(value)
  );
}

function looksLikeLoginOnly(
  url = '',
  text = ''
) {
  const value =
    normalizedText(
      `${url} ${text}`
    );

  return (
    /\blogin\b|\bsign[\s-]?in\b/.test(value) &&
    !/\bapplication\b/.test(value) &&
    !/\bregistration\b/.test(value) &&
    !/\bapply\b/.test(value)
  );
}

/* -------------------------------------------------------------------------- */
/* Specific title detection                                                   */
/* -------------------------------------------------------------------------- */

function hasSpecificTitle(
  title = '',
  organization = ''
) {
  const clean =
    compactText(title);

  const org =
    compactText(organization);

  if (
    !clean ||
    clean.length < 8
  ) {
    return false;
  }

  if (
    GENERIC_TITLE.test(clean)
  ) {
    return false;
  }

  if (
    org &&
    clean === org
  ) {
    return false;
  }

  const identifying =
    /\b(20\d{2}|post|posts|exam|examination|recruitment|vacanc(?:y|ies)|admit|hall|result|merit|selection|answer|response|syllabus|admission|entrance|scholarship|candidate|grade|group|class|officer|assistant|teacher|engineer|clerk|constable|inspector|technician|staff|department|course|programme|program|notice|notification|advertisement|corrigendum)\b/i;

  return identifying.test(
    clean
  );
}

/* -------------------------------------------------------------------------- */
/* Link parser                                                                */
/* -------------------------------------------------------------------------- */

function linksOf(
  html,
  base
) {
  const out = [];

  if (
    !html ||
    !base
  ) {
    return out;
  }

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

      if (!rawHref) {
        continue;
      }

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

      if (!url) {
        continue;
      }

      const text =
        textOf(
          match[2]
        ).slice(
          0,
          500
        );

      out.push({
        url,
        text
      });
    } catch {
      /* ignore malformed link */
    }
  }

  return out;
}

/* -------------------------------------------------------------------------- */
/* Link priority                                                              */
/* -------------------------------------------------------------------------- */

function linkPriority(link) {
  const value =
    normalizedText(
      `${link.text} ${link.url}`
    );

  let score = 0;

  if (
    WORDS.job.test(value)
  ) {
    score += 50;
  }

  if (
    WORDS.admit.test(value)
  ) {
    score += 45;
  }

  if (
    WORDS.result.test(value)
  ) {
    score += 45;
  }

  if (
    WORDS.answer.test(value)
  ) {
    score += 45;
  }

  if (
    WORDS.syllabus.test(value)
  ) {
    score += 40;
  }

  if (
    WORDS.admission.test(value)
  ) {
    score += 40;
  }

  if (
    WORDS.scholarship.test(value)
  ) {
    score += 35;
  }

  if (
    NOTIFICATION_SIGNAL.test(value)
  ) {
    score += 25;
  }

  if (
    APPLY.test(value)
  ) {
    score += 20;
  }

  if (
    isPdfUrl(link.url)
  ) {
    score += 10;
  }

  return score;
}

function isUsefulCrawlLink(
  link,
  source
) {
  if (
    !link?.url
  ) {
    return false;
  }

  if (
    !isHttp(link.url)
  ) {
    return false;
  }

  if (
    source?.role === 'official' &&
    !sameHostOrAllowed(
      link.url,
      source.allowed_domains
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

  if (
    isGenericPage(
      link.url,
      link.text
    )
  ) {
    return false;
  }

  return true;
}

/* -------------------------------------------------------------------------- */
/* Fetch helper                                                               */
/* -------------------------------------------------------------------------- */

async function fetchWithTimeout(
  url
) {
  const controller =
    new AbortController();

  const timer =
    setTimeout(
      () =>
        controller.abort(),
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
          signal:
            controller.signal,

          headers: {
            'User-Agent':
              'NorthBharatJobs/1.0 (+official-source-monitor)',

            Accept:
              'text/html,application/xhtml+xml,application/pdf;q=0.9,*/*;q=0.5',

            'Accept-Language':
              'en-IN,en;q=0.9'
          }
        }
      );

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
      ok:
        response.ok,

      status:
        response.status,

      body,

      contentType,

      finalUrl:
        normalizeUrl(
          response.url ||
          url
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
          response.url ||
          url
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
          error?.message ||
          error
        )
    };
  } finally {
    clearTimeout(
      timer
    );
  }
}

/* -------------------------------------------------------------------------- */
/* Category classification                                                    */
/* -------------------------------------------------------------------------- */

function classify(
  title,
  body,
  links = []
) {
  const titleText =
    compactText(title);

  const linkText =
    compactText(
      links
        .slice(
          0,
          100
        )
        .map(
          link =>
            `${link.text} ${link.url}`
        )
        .join(' ')
    );

  /*
    Title gets priority.
  */

  if (
    WORDS.admit.test(
      titleText
    )
  ) {
    return 'admit_card';
  }

  if (
    WORDS.answer.test(
      titleText
    )
  ) {
    return 'answer_key';
  }

  if (
    WORDS.result.test(
      titleText
    )
  ) {
    return 'result';
  }

  if (
    WORDS.syllabus.test(
      titleText
    )
  ) {
    return 'syllabus';
  }

  if (
    WORDS.admission.test(
      titleText
    )
  ) {
    return 'admission';
  }

  if (
    WORDS.scholarship.test(
      titleText
    )
  ) {
    return 'scholarship';
  }

  if (
    WORDS.job.test(
      titleText
    )
  ) {
    return 'job';
  }

  /*
    Then link evidence.
  */

  if (
    WORDS.admit.test(
      linkText
    )
  ) {
    return 'admit_card';
  }

  if (
    WORDS.answer.test(
      linkText
    )
  ) {
    return 'answer_key';
  }

  if (
    WORDS.result.test(
      linkText
    )
  ) {
    return 'result';
  }

  if (
    WORDS.syllabus.test(
      linkText
    )
  ) {
    return 'syllabus';
  }

  if (
    WORDS.admission.test(
      linkText
    )
  ) {
    return 'admission';
  }

  if (
    WORDS.scholarship.test(
      linkText
    )
  ) {
    return 'scholarship';
  }

  if (
    WORDS.job.test(
      linkText
    )
  ) {
    return 'job';
  }

  /*
    Finally use body evidence.
  */

  const bodyText =
    normalizedText(
      body.slice(
        0,
        16000
      )
    );

  if (
    WORDS.admit.test(bodyText) &&
    /\b(download|candidate|hall|ticket|roll\s*number|exam\s*centre|exam\s*center)\b/i.test(
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

function extractDate(
  text,
  labels
) {
  const month =
    '(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)';

  const patterns = [
    new RegExp(
      `(?:${labels})[^\\d]{0,100}(\\d{1,2}[\\/-]\\d{1,2}[\\/-]\\d{2,4})`,
      'i'
    ),

    new RegExp(
      `(?:${labels})[^\\d]{0,100}(\\d{1,2}\\s+${month}\\s+\\d{4})`,
      'i'
    ),

    new RegExp(
      `(?:${labels})[^\\d]{0,100}(${month}\\s+\\d{1,2},?\\s+\\d{4})`,
      'i'
    )
  ];

  for (
    const pattern of patterns
  ) {
    const match =
      text.match(pattern);

    if (
      match?.[1]
    ) {
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
    links.some(
      link => {
        if (
          !isPdfUrl(
            link.url
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
      }
    );

  if (
    hasNotification
  ) {
    score += 3;
    evidence.push(
      'recruitment-notification-pdf'
    );
  }

  const hasApply =
    links.some(
      link => {
        if (
          isPdfUrl(
            link.url
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

        return APPLY.test(
          `${link.text} ${link.url}`
        );
      }
    );

  if (
    hasApply
  ) {
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
/* Category evidence                                                          */
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
      body.slice(
        0,
        16000
      )
    );

  const linkText =
    normalizedText(
      links
        .slice(
          0,
          120
        )
        .map(
          link =>
            `${link.text} ${link.url}`
        )
        .join(' ')
    );

  const evidence = [];

  let score = 0;

  if (
    ADMIN_DOCUMENT.test(
      `${sourceUrl} ${title}`
    )
  ) {
    return {
      ok: false,
      score: 0,
      evidence: [
        'administrative-document-blocked'
      ]
    };
  }

  if (
    type === 'admit_card'
  ) {
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

    if (
      strongTitle
    ) {
      score += 7;
      evidence.push(
        'admit-title'
      );
    } else if (
      strongLink
    ) {
      score += 6;
      evidence.push(
        'admit-link'
      );
    }

    if (
      operational
    ) {
      score += 3;
      evidence.push(
        'admit-operational-context'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle ||
          strongLink) &&
        operational,

      score,

      evidence
    };
  }

  if (
    type === 'result'
  ) {
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

    if (
      strongTitle
    ) {
      score += 7;
      evidence.push(
        'result-title'
      );
    } else if (
      strongLink
    ) {
      score += 6;
      evidence.push(
        'result-link'
      );
    }

    if (
      operational
    ) {
      score += 3;
      evidence.push(
        'result-operational-context'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle ||
          strongLink) &&
        operational,

      score,

      evidence
    };
  }

  if (
    type === 'answer_key'
  ) {
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

    if (
      strongTitle
    ) {
      score += 7;
      evidence.push(
        'answer-key-title'
      );
    } else if (
      strongLink
    ) {
      score += 6;
      evidence.push(
        'answer-key-link'
      );
    }

    if (
      operational
    ) {
      score += 3;
      evidence.push(
        'answer-key-operational-context'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle ||
          strongLink) &&
        operational,

      score,

      evidence
    };
  }

  if (
    type === 'syllabus'
  ) {
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
        `${titleText} ${bodyText.slice(
          0,
          9000
        )}`
      );

    if (
      strongTitle
    ) {
      score += 7;
      evidence.push(
        'syllabus-title'
      );
    } else if (
      strongLink
    ) {
      score += 6;
      evidence.push(
        'syllabus-link'
      );
    }

    if (
      specificSubject
    ) {
      score += 3;
      evidence.push(
        'syllabus-specific-exam-or-post'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle ||
          strongLink) &&
        specificSubject,

      score,

      evidence
    };
  }

  if (
    type === 'admission'
  ) {
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

    if (
      strongTitle
    ) {
      score += 7;
      evidence.push(
        'admission-title'
      );
    } else if (
      strongLink
    ) {
      score += 6;
      evidence.push(
        'admission-link'
      );
    }

    if (
      operational
    ) {
      score += 3;
      evidence.push(
        'admission-operational-context'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle ||
          strongLink) &&
        operational,

      score,

      evidence
    };
  }

  if (
    type === 'scholarship'
  ) {
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

    if (
      strongTitle
    ) {
      score += 7;
      evidence.push(
        'scholarship-title'
      );
    } else if (
      strongLink
    ) {
      score += 6;
      evidence.push(
        'scholarship-link'
      );
    }

    if (
      operational
    ) {
      score += 3;
      evidence.push(
        'scholarship-operational-context'
      );
    }

    return {
      ok:
        score >= 8 &&
        (strongTitle ||
          strongLink) &&
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
  for (
    const link of links
  ) {
    if (
      !isHttp(link.url)
    ) {
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

    if (
      !isPdfUrl(link.url)
    ) {
      continue;
    }

    if (
      urlHasOldYear(link.url)
    ) {
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
  for (
    const link of links
  ) {
    if (
      !isHttp(link.url)
    ) {
      continue;
    }

    if (
      isPdfUrl(link.url)
    ) {
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

    if (
      urlHasOldYear(link.url)
    ) {
      continue;
    }

    const label =
      `${link.text} ${link.url}`;

    if (
      !APPLY.test(label)
    ) {
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

  /*
    Prefer an H1/H2 heading when available.
    Many government sites have generic <title>
    values but specific H1/H2 notice headings.
  */
  const headingMatch =
    page.body.match(
      /<h[12][^>]*>([\s\S]*?)<\/h[12]>/i
    );

  const title =
    cleanTitle(
      headingMatch?.[1] ||
      titleMatch?.[1] ||
      textOf(
        page.body
      ).slice(
        0,
        240
      )
    );

  const body =
    textOf(
      page.body
    ).slice(
      0,
      20000
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

  if (
    isGenericPage(
      sourceUrl,
      title
    )
  ) {
    return null;
  }

  if (
    isBlockedPath(
      sourceUrl,
      title
    )
  ) {
    return null;
  }

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

  const type =
    classify(
      title,
      body,
      links
    );

  if (!type) {
    return null;
  }

  if (
    !hasSpecificTitle(
      title,
      source.name
    )
  ) {
    return null;
  }

  const notification =
    findNotificationLink(
      links,
      source
    );

  const apply =
    findApplyLink(
      links,
      sourceUrl,
      notification?.url ||
        null
    );

  const recruitment =
    recruitmentEvidence(
      title,
      body,
      links
    );

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
    RECRUITMENT GATE
    ------------------------------------------------------------------------
  */

  if (
    type === 'job'
  ) {
    if (
      recruitment.score < 8
    ) {
      return null;
    }

    if (
      !notification?.url
    ) {
      return null;
    }

    if (
      !apply?.url
    ) {
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

    if (
      source.role === 'official' &&
      !sameHostOrAllowed(
        notification.url,
        source.allowed_domains
      )
    ) {
      return null;
    }

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

  const officialUrl =
    source.role === 'official'
      ? sourceUrl
      : null;

  let categoryDocument =
    null;

  if (
    type === 'admit_card'
  ) {
    categoryDocument =
      links.find(
        link =>
          !urlHasOldYear(
            link.url
          ) &&
          /\b(admit|hall[-_\s]?ticket|call[-_\s]?letter|e[-_\s]?admit)\b/i.test(
            `${link.text} ${link.url}`
          ) &&
          (
            isPdfUrl(
              link.url
            ) ||
            /\b(download|view|print)\b/i.test(
              link.text
            )
          )
      ) || null;
  }

  if (
    type === 'result'
  ) {
    categoryDocument =
      links.find(
        link =>
          !urlHasOldYear(
            link.url
          ) &&
          /\b(result|merit|selection[-_\s]?list|score[-_\s]?card|marks[-_\s]?list)\b/i.test(
            `${link.text} ${link.url}`
          )
      ) || null;
  }

  if (
    type === 'answer_key'
  ) {
    categoryDocument =
      links.find(
        link =>
          !urlHasOldYear(
            link.url
          ) &&
          /\b(answer[-_\s]?key|response[-_\s]?sheet|answer[-_\s]?sheet|objection)\b/i.test(
            `${link.text} ${link.url}`
          )
      ) || null;
  }

  if (
    type === 'syllabus'
  ) {
    categoryDocument =
      links.find(
        link =>
          !urlHasOldYear(
            link.url
          ) &&
          /\b(syllabus|scheme)\b/i.test(
            `${link.text} ${link.url}`
          ) &&
          !ADMIN_DOCUMENT.test(
            `${link.text} ${link.url}`
          )
      ) || null;
  }

  let categoryApply =
    null;

  if (
    type === 'admission'
  ) {
    categoryApply =
      findApplyLink(
        links,
        sourceUrl,
        null
      );
  }

  let notificationUrl =
    notification?.url ||
    null;

  if (
    type !== 'job' &&
    categoryDocument?.url
  ) {
    notificationUrl =
      categoryDocument.url;
  }

  let applyUrl =
    apply?.url ||
    null;

  if (
    type === 'admission' &&
    categoryApply?.url
  ) {
    applyUrl =
      categoryApply.url;
  }

  const finalEvidenceScore =
    Math.max(
      category.score || 0,
      type === 'job'
        ? recruitment.score
        : category.score
    );

  const finalEvidence = [
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
        6000
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
      sourceUrl,

    notification_key:
      `${source.id}|${sourceUrl}`,

    _source_role:
      source.role,

    _official:
      source.role === 'official',

    _evidence_score:
      finalEvidenceScore,

    _evidence:
      [
        ...new Set(
          finalEvidence
        )
      ],

    _links:
      links.slice(
        0,
        30
      )
  };
}

/* -------------------------------------------------------------------------- */
/* Crawl seed scoring                                                        */
/* -------------------------------------------------------------------------- */

function scoreCrawlLink(
  link
) {
  const value =
    `${link.text} ${link.url}`;

  let score =
    linkPriority(link);

  /*
    Listing/notice pages are important even when
    they do not themselves look like a final job.
  */

  if (
    /\b(notice|notices|notification|notifications|advertisement|recruitment|results?|answer|admit|syllabus|career|vacancy|vacancies|current|latest|what'?s\s+new)\b/i.test(
      value
    )
  ) {
    score += 20;
  }

  return score;
}

/* -------------------------------------------------------------------------- */
/* Source discovery                                                          */
/* -------------------------------------------------------------------------- */

export async function discoverFromSource(
  source
) {
  if (
    !source?.base_url
  ) {
    throw new Error(
      'Source base URL missing'
    );
  }

  const home =
    await fetchWithTimeout(
      source.base_url
    );

  if (
    !home.ok
  ) {
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

  if (
    !homeIsHtml
  ) {
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

  /*
    ------------------------------------------------------------------------
    MULTI-LEVEL CRAWLER
    ------------------------------------------------------------------------

    Old version:
      homepage -> relevant links -> final candidate

    New version:
      homepage
        -> section/listing pages
          -> notice/detail pages
            -> candidate

    This is the important fix for sources such as SSC.
  */

  const queue = [];
  const queued = new Set();
  const fetched = new Set();

  const homeUrl =
    normalizeUrl(
      home.finalUrl ||
      source.base_url
    );

  if (
    homeUrl
  ) {
    queued.add(
      homeUrl
    );

    queue.push({
      url:
        homeUrl,

      depth: 0,

      text:
        'homepage',

      score: 0
    });
  }

  function addLinks(
    html,
    baseUrl,
    depth
  ) {
    if (
      depth >= MAX_DEPTH
    ) {
      return;
    }

    const links =
      linksOf(
        html,
        baseUrl
      );

    const candidates =
      links
        .filter(
          link =>
            isUsefulCrawlLink(
              link,
              source
            )
        )
        .map(
          link => ({
            ...link,

            score:
              scoreCrawlLink(
                link
              ),

            depth:
              depth + 1
          })
        )
        .sort(
          (a, b) =>
            b.score -
            a.score
        );

    for (
      const link of candidates
    ) {
      if (
        queue.length >=
        MAX_LINKS
      ) {
        break;
      }

      if (
        queued.has(
          link.url
        )
      ) {
        continue;
      }

      queued.add(
        link.url
      );

      queue.push({
        url:
          link.url,

        depth:
          link.depth,

        text:
          link.text,

        score:
          link.score
      });
    }
  }

  /*
    Add homepage links first.
  */
  addLinks(
    home.body,
    home.finalUrl ||
      source.base_url,
    0
  );

  const pages = [];

  /*
    Process queue in priority order.
    Re-sort after adding second-level links.
  */

  while (
    queue.length &&
    fetched.size < MAX_PAGES
  ) {
    queue.sort(
      (a, b) =>
        b.score -
        a.score
    );

    const next =
      queue.shift();

    if (
      !next?.url
    ) {
      continue;
    }

    if (
      fetched.has(
        next.url
      )
    ) {
      continue;
    }

    fetched.add(
      next.url
    );

    /*
      Homepage was already fetched.
    */
    let response;

    if (
      sameUrl(
        next.url,
        homeUrl
      )
    ) {
      response =
        home;
    } else {
      response =
        await fetchWithTimeout(
          next.url
        );
    }

    if (
      !response.ok
    ) {
      continue;
    }

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
      !isHtml ||
      !response.body
    ) {
      continue;
    }

    const finalUrl =
      normalizeUrl(
        response.finalUrl ||
        next.url
      ) ||
      next.url;

    pages.push({
      url:
        next.url,

      finalUrl,

      body:
        response.body,

      depth:
        next.depth,

      linkText:
        next.text,

      score:
        next.score
    });

    /*
      Continue crawling listing/section pages.
    */
    if (
      next.depth <
      MAX_DEPTH
    ) {
      addLinks(
        response.body,
        finalUrl,
        next.depth
      );
    }
  }

  /* ---------------------------------------------------------------------- */
  /* Candidate generation                                                   */
  /* ---------------------------------------------------------------------- */

  const seen =
    new Set();

  const candidates =
    [];

  /*
    Candidate pages are processed before generic
    listing pages whenever possible.
  */

  pages.sort(
    (a, b) =>
      b.score -
      a.score
  );

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

    seen.add(
      pageKey
    );

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
