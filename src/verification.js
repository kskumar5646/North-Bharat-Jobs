const JOB_TYPES = new Set(['job','recruitment']);
const PDF_RE = /\.pdf(?:[?#]|$)/i;

export function isHttpUrl(value) {
  try { const u = new URL(value); return u.protocol === 'https:' || u.protocol === 'http:'; } catch { return false; }
}

export function sameHostOrAllowed(url, allowedDomains = '') {
  try {
    const host = new URL(url).hostname.toLowerCase();
    return allowedDomains.split(';').map(x => x.trim().toLowerCase()).filter(Boolean).some(d => host === d || host.endsWith('.' + d));
  } catch { return false; }
}

export function isPdfUrl(url) { return PDF_RE.test(url || ''); }

export function normalizeUrl(value) {
  if (!value || !isHttpUrl(value)) return null;
  try {
    const u = new URL(value);
    u.hash = '';
    u.hostname = u.hostname.toLowerCase();
    return u.toString();
  } catch { return null; }
}

export function distinctUrls(values = []) {
  return [...new Set(values.map(normalizeUrl).filter(Boolean))];
}

export function slugify(value) {
  return String(value || '').toLowerCase().normalize('NFKD').replace(/[^\p{Letter}\p{Number}]+/gu, '-').replace(/^-+|-+$/g, '').slice(0, 110) || `item-${Date.now()}`;
}

export async function sha256Hex(value) {
  const bytes = new TextEncoder().encode(String(value));
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export function canonicalNotificationKey(candidate) {
  return candidate.notification_key || normalizeUrl(candidate.notification_url) || normalizeUrl(candidate.canonical_url) || normalizeUrl(candidate.source_url) || `${candidate.organization || ''}|${candidate.title || ''}|${candidate.last_date || ''}`;
}

export function validateCandidate(candidate, source) {
  const errors = [];
  const warnings = [];
  const type = candidate.type || 'update';
  const official = normalizeUrl(candidate.official_url);
  const notification = normalizeUrl(candidate.notification_url);
  const apply = normalizeUrl(candidate.apply_url);

  if (!candidate.title?.trim()) errors.push('Missing title');
  if (!normalizeUrl(candidate.source_url)) errors.push('Missing valid source URL');
  if (source?.role === 'official' && !sameHostOrAllowed(candidate.source_url, source.allowed_domains)) errors.push('Source URL outside allowed official domain');

  if (JOB_TYPES.has(type)) {
    if (!official) errors.push('Recruitment item missing official URL');
    if (!notification || !isPdfUrl(notification)) errors.push('Recruitment item missing verified notification PDF URL');
    if (!apply || isPdfUrl(apply)) errors.push('Recruitment item missing distinct apply URL');
    if (official && notification && official === notification) errors.push('Official URL and notification URL must differ');
    if (official && apply && official === apply) errors.push('Official URL and apply URL must differ');
    if (notification && apply && notification === apply) errors.push('Notification URL and apply URL must differ');
    if (source?.role === 'official') {
      for (const [label, url] of [['official', official], ['notification', notification], ['apply', apply]]) {
        if (url && !sameHostOrAllowed(url, source.allowed_domains)) warnings.push(`${label} URL is outside official domain; admin verification required`);
      }
    }
  }

  return { ok: errors.length === 0, errors, warnings };
}

export async function verifyCandidate(candidate, source) {
  const validation = validateCandidate(candidate, source);
  const fingerprint = await sha256Hex(JSON.stringify({
    title: candidate.title, organization: candidate.organization, type: candidate.type,
    notification_key: canonicalNotificationKey(candidate), last_date: candidate.last_date,
    source_url: normalizeUrl(candidate.source_url), notification_url: normalizeUrl(candidate.notification_url),
    apply_url: normalizeUrl(candidate.apply_url)
  }));
  let confidence = source?.role === 'official' ? 85 : 45;
  if (candidate.notification_url) confidence += 5;
  if (candidate.apply_url) confidence += 5;
  if (candidate.qualification || candidate.eligibility) confidence += 2;
  if (candidate.last_date) confidence += 2;
  if (candidate.vacancies) confidence += 1;
  confidence = Math.min(100, confidence);
  return { ...validation, fingerprint, confidence };
}
