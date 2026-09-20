import { runMonitor } from './monitor.js';
import { sha256Hex } from './verification.js';

const COOKIE = 'nbj_admin_session';
const SESSION_DAYS = 7;

const PUBLIC_TYPES = [
  'job',
  'recruitment',
  'admit_card',
  'result',
  'answer_key',
  'syllabus',
  'admission',
  'scholarship',
  'update'
];

const htmlHeaders = {
  'content-type': 'text/html; charset=UTF-8',
  'cache-control': 'public, max-age=300'
};

const jsonHeaders = {
  'content-type': 'application/json; charset=UTF-8',
  'cache-control': 'no-store'
};

function json(data, status = 200) {
  return new Response(
    JSON.stringify(data),
    {
      status,
      headers: jsonHeaders
    }
  );
}

function nowIso() {
  return new Date().toISOString();
}

function siteOrigin(request) {
  return new URL(request.url).origin;
}

function safeJson(request) {
  return request.json().catch(() => ({}));
}

function esc(value = '') {
  return String(value).replace(
    /[&<>'"]/g,
    char => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;'
    }[char])
  );
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();

  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: enc.encode(salt),
      iterations: 120000,
      hash: 'SHA-256'
    },
    key,
    256
  );

  return `${salt}$${[
    ...new Uint8Array(bits)
  ]
    .map(
      b =>
        b.toString(16).padStart(2, '0')
    )
    .join('')}`;
}

async function verifyPassword(
  password,
  stored
) {
  if (!stored?.includes('$')) {
    return false;
  }

  const separator = stored.indexOf('$');

  const salt =
    stored.slice(0, separator);

  const expected =
    stored.slice(separator + 1);

  const actual =
    await hashPassword(
      password,
      salt
    );

  return actual.slice(
    actual.indexOf('$') + 1
  ) === expected;
}

function randomToken() {
  const bytes =
    new Uint8Array(32);

  crypto.getRandomValues(bytes);

  return [
    ...bytes
  ]
    .map(
      b =>
        b.toString(16).padStart(2, '0')
    )
    .join('');
}

function cookieToken(request) {
  const cookie =
    request.headers.get('cookie') || '';

  const match =
    cookie.match(
      new RegExp(
        `${COOKIE}=([^;]+)`
      )
    );

  return match?.[1] || null;
}

function cookieHeader(
  token,
  maxAge
) {
  return [
    `${COOKIE}=${token}`,
    `Max-Age=${maxAge}`,
    'Path=/',
    'HttpOnly',
    'Secure',
    'SameSite=Lax'
  ].join('; ');
}

/*
  Admin authentication
*/
async function adminFromRequest(
  env,
  request
) {
  const token =
    cookieToken(request);

  if (!token) {
    return null;
  }

  const hash =
    await sha256Hex(token);

  const row =
    await env.DB
      .prepare(`
        SELECT
          a.*
        FROM sessions s
        JOIN admins a
          ON a.id=s.admin_id
        WHERE
          s.token_hash=?
          AND s.expires_at>?
      `)
      .bind(
        hash,
        nowIso()
      )
      .first();

  return row || null;
}

async function requireAdmin(
  env,
  request
) {
  return adminFromRequest(
    env,
    request
  );
}

async function audit(
  env,
  adminId,
  action,
  type = null,
  id = null,
  meta = null
) {
  await env.DB
    .prepare(`
      INSERT INTO audit_logs(
        admin_id,
        action,
        target_type,
        target_id,
        metadata_json
      )
      VALUES(?,?,?,?,?)
    `)
    .bind(
      adminId,
      action,
      type,
      id,
      meta
        ? JSON.stringify(meta)
        : null
    )
    .run();
}

/*
  Creates the first admin only when
  the database has no admin account.
*/
async function ensureAdmin(env) {
  const count =
    await env.DB
      .prepare(
        `SELECT COUNT(*) c FROM admins`
      )
      .first();

  if (
    Number(count?.c || 0) > 0
  ) {
    return;
  }

  if (
    !env.ADMIN_EMAIL ||
    !env.ADMIN_PASSWORD
  ) {
    return;
  }

  const email =
    String(
      env.ADMIN_EMAIL
    )
      .trim()
      .toLowerCase();

  const password =
    String(env.ADMIN_PASSWORD);

  if (
    !/^\S+@\S+\.\S+$/.test(email) ||
    password.length < 10
  ) {
    return;
  }

  const salt =
    randomToken().slice(0, 32);

  const passwordHash =
    await hashPassword(
      password,
      salt
    );

  await env.DB
    .prepare(`
      INSERT OR IGNORE INTO admins(
        email,
        password_hash
      )
      VALUES(?,?)
    `)
    .bind(
      email,
      passwordHash
    )
    .run();
}

/*
  Public jobs list
*/
async function publicList(
  env,
  url
) {
  const type =
    url.searchParams.get('type');

  const q =
    (
      url.searchParams.get('q') ||
      ''
    ).trim();

  const requestedPage =
    Number(
      url.searchParams.get('page') ||
      1
    );

  const requestedLimit =
    Number(
      url.searchParams.get('limit') ||
      15
    );

  const page =
    Number.isFinite(requestedPage)
      ? Math.max(
          1,
          Math.floor(requestedPage)
        )
      : 1;

  const limit =
    Number.isFinite(requestedLimit)
      ? Math.min(
          30,
          Math.max(
            1,
            Math.floor(requestedLimit)
          )
        )
      : 15;

  const offset =
    (page - 1) * limit;

  const where = [
    `status='published'`,
    `(
      published_at IS NULL
      OR published_at >= datetime('now','-365 day')
    )`
  ];

  const args = [];

  if (
    type &&
    PUBLIC_TYPES.includes(type)
  ) {
    where.push('type=?');
    args.push(type);
  }

  if (q) {
    const search =
      `%${q}%`;

    where.push(`
      (
        title LIKE ?
        OR organization LIKE ?
        OR qualification LIKE ?
        OR category LIKE ?
      )
    `);

    args.push(
      search,
      search,
      search,
      search
    );
  }

  const sql = `
    SELECT
      id,
      slug,
      type,
      title,
      organization,
      category,
      location,
      qualification,
      vacancies,
      age_limit,
      fee,
      application_start,
      last_date,
      exam_date,
      official_url,
      apply_url,
      notification_url,
      published_at
    FROM items
    WHERE ${where.join(' AND ')}
    ORDER BY
      COALESCE(
        published_at,
        created_at
      ) DESC,
      id DESC
    LIMIT ?
    OFFSET ?
  `;

  const rows =
    (
      await env.DB
        .prepare(sql)
        .bind(
          ...args,
          limit,
          offset
        )
        .all()
    ).results || [];

  return json({
    ok: true,
    page,
    limit,
    items: rows
  });
}

/*
  Public item
*/
async function publicItem(
  env,
  slug
) {
  const item =
    await env.DB
      .prepare(`
        SELECT *
        FROM items
        WHERE
          slug=?
          AND status='published'
          AND (
            published_at IS NULL
            OR published_at >= datetime('now','-365 day')
          )
      `)
      .bind(slug)
      .first();

  if (!item) {
    return json(
      {
        ok: false,
        error: 'Not found'
      },
      404
    );
  }

  return json({
    ok: true,
    item
  });
}

/*
  Admin dashboard
*/
async function adminDashboard(env) {
  const queries =
    await Promise.all([
      env.DB
        .prepare(`
          SELECT COUNT(*) c
          FROM items
          WHERE status='published'
        `)
        .first(),

      env.DB
        .prepare(`
          SELECT COUNT(*) c
          FROM items
          WHERE status='verification_required'
        `)
        .first(),

      env.DB
        .prepare(`
          SELECT COUNT(*) c
          FROM sources
          WHERE
            enabled=1
            AND last_error IS NOT NULL
        `)
        .first(),

      env.DB
        .prepare(`
          SELECT COUNT(*) c
          FROM notifications
          WHERE read_at IS NULL
        `)
        .first()
    ]);

  return json({
    ok: true,
    stats: {
      published:
        Number(
          queries[0]?.c || 0
        ),

      verification_required:
        Number(
          queries[1]?.c || 0
        ),

      source_errors:
        Number(
          queries[2]?.c || 0
        ),

      unread_notifications:
        Number(
          queries[3]?.c || 0
        )
    }
  });
}

/*
  Admin API
*/
async function adminApi(
  env,
  request,
  url,
  admin
) {
  const path =
    url.pathname;

  if (
    path ===
    '/api/admin/me'
  ) {
    return json({
      ok: true,
      admin: {
        id: admin.id,
        email: admin.email
      }
    });
  }

  if (
    path ===
    '/api/admin/dashboard'
  ) {
    return adminDashboard(env);
  }

  if (
    path ===
    '/api/admin/sources'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM sources
            ORDER BY
              role,
              priority,
              id
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      sources: rows
    });
  }

  if (
    path ===
    '/api/admin/items'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM items
            WHERE status IN (
              'verification_required',
              'published'
            )
            ORDER BY
              updated_at DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      items: rows
    });
  }

  if (
    path ===
    '/api/admin/notifications'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM notifications
            ORDER BY
              created_at DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      notifications: rows
    });
  }

  if (
    path ===
    '/api/admin/runs'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM monitor_runs
            ORDER BY
              id DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      runs: rows
    });
  }

  if (
    path ===
    '/api/admin/audit'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM audit_logs
            ORDER BY
              id DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      logs: rows
    });
  }

  if (
    path ===
    '/api/admin/verification-logs'
  ) {
    const rows =
      (
        await env.DB
          .prepare(`
            SELECT *
            FROM verification_events
            ORDER BY
              id DESC
            LIMIT 100
          `)
          .all()
      ).results || [];

    return json({
      ok: true,
      logs: rows
    });
  }

  /*
    Manual source discovery
  */
  if (
    path ===
      '/api/admin/discover' &&
    request.method === 'POST'
  ) {
    const name =
      url.searchParams.get(
        'source'
      );

    if (!name) {
      return json(
        {
          ok: false,
          error:
            'Missing source'
        },
        400
      );
    }

    const result =
      await runMonitor(
        env,
        name
      );

    await audit(
      env,
      admin.id,
      'manual_discover',
      'source',
      name
    );

    return json({
      ok: true,
      ...result
    });
  }

  /*
    Manual item verification
  */
  if (
    path ===
      '/api/admin/item/verify' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error: 'Invalid id'
        },
        400
      );
    }

    const result =
      await env.DB
        .prepare(`
          UPDATE items
          SET
            status='published',
            verification_status='admin_verified',
            last_verified_at=?,
            published_at=
              COALESCE(
                published_at,
                ?
              ),
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(
          nowIso(),
          nowIso(),
          id
        )
        .run();

    if (
      Number(
        result.meta?.changes || 0
      ) === 0
    ) {
      return json(
        {
          ok: false,
          error:
            'Item not found'
        },
        404
      );
    }

    await audit(
      env,
      admin.id,
      'verify_publish',
      'item',
      id
    );

    return json({
      ok: true
    });
  }

  /*
    Reject item
  */
  if (
    path ===
      '/api/admin/item/reject' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error: 'Invalid id'
        },
        400
      );
    }

    const result =
      await env.DB
        .prepare(`
          UPDATE items
          SET
            status='rejected',
            verification_status='rejected',
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(id)
        .run();

    if (
      Number(
        result.meta?.changes || 0
      ) === 0
    ) {
      return json(
        {
          ok: false,
          error:
            'Item not found'
        },
        404
      );
    }

    await audit(
      env,
      admin.id,
      'reject',
      'item',
      id
    );

    return json({
      ok: true
    });
  }

  /*
    Save source
  */
  if (
    path ===
      '/api/admin/source/save' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error: 'Invalid id'
        },
        400
      );
    }

    const existing =
      await env.DB
        .prepare(`
          SELECT *
          FROM sources
          WHERE id=?
        `)
        .bind(id)
        .first();

    if (!existing) {
      return json(
        {
          ok: false,
          error:
            'Source not found'
        },
        404
      );
    }

    const name =
      String(
        body.name || ''
      ).trim();

    const baseUrl =
      String(
        body.base_url || ''
      ).trim();

    const domains =
      String(
        body.allowed_domains || ''
      ).trim();

    const adapter =
      String(
        body.adapter ||
        'generic'
      ).trim();

    const fallbackKey =
      String(
        body.fallback_key ||
        '*'
      ).trim();

    const priority =
      Number(
        body.priority ?? 50
      );

    const enabled =
      body.enabled
        ? 1
        : 0;

    if (
      !name ||
      !baseUrl ||
      !domains
    ) {
      return json(
        {
          ok: false,
          error:
            'Name, base URL and allowed domains are required'
        },
        400
      );
    }

    if (
      !Number.isFinite(priority)
    ) {
      return json(
        {
          ok: false,
          error:
            'Invalid priority'
        },
        400
      );
    }

    /*
      Admin cannot change an official
      source into a portal or vice versa
      from this endpoint.
    */
    const result =
      await env.DB
        .prepare(`
          UPDATE sources
          SET
            name=?,
            base_url=?,
            allowed_domains=?,
            adapter=?,
            fallback_key=?,
            priority=?,
            enabled=?,
            updated_at=CURRENT_TIMESTAMP
          WHERE id=?
        `)
        .bind(
          name,
          baseUrl,
          domains,
          adapter,
          fallbackKey,
          priority,
          enabled,
          id
        )
        .run();

    await audit(
      env,
      admin.id,
      'update_source',
      'source',
      id,
      {
        name,
        base_url: baseUrl,
        allowed_domains: domains,
        adapter,
        fallback_key: fallbackKey,
        priority,
        enabled
      }
    );

    return json({
      ok: true,
      changes:
        Number(
          result.meta?.changes || 0
        )
    });
  }

  /*
    Change password
  */
  if (
    path ===
      '/api/admin/password' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    if (
      !body.current ||
      !body.next ||
      String(body.next).length < 10
    ) {
      return json(
        {
          ok: false,
          error:
            'Password must be at least 10 characters'
        },
        400
      );
    }

    if (
      !(await verifyPassword(
        String(body.current),
        admin.password_hash
      ))
    ) {
      return json(
        {
          ok: false,
          error:
            'Current password is incorrect'
        },
        403
      );
    }

    const salt =
      randomToken().slice(0, 32);

    const passwordHash =
      await hashPassword(
        String(body.next),
        salt
      );

    await env.DB
      .prepare(`
        UPDATE admins
        SET password_hash=?
        WHERE id=?
      `)
      .bind(
        passwordHash,
        admin.id
      )
      .run();

    /*
      Invalidate all existing sessions
      after a password change.
    */
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE admin_id=?
      `)
      .bind(admin.id)
      .run();

    await audit(
      env,
      admin.id,
      'change_password',
      'admin',
      admin.id
    );

    return json({
      ok: true
    });
  }

  /*
    Change email
  */
  if (
    path ===
      '/api/admin/email' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const email =
      String(
        body.email || ''
      )
        .trim()
        .toLowerCase();

    if (
      !/^\S+@\S+\.\S+$/.test(email)
    ) {
      return json(
        {
          ok: false,
          error:
            'Invalid email'
        },
        400
      );
    }

    try {
      await env.DB
        .prepare(`
          UPDATE admins
          SET email=?
          WHERE id=?
        `)
        .bind(
          email,
          admin.id
        )
        .run();
    } catch {
      return json(
        {
          ok: false,
          error:
            'Email is already in use'
        },
        409
      );
    }

    await audit(
      env,
      admin.id,
      'change_email',
      'admin',
      admin.id
    );

    return json({
      ok: true
    });
  }

  /*
    Mark notification read
  */
  if (
    path ===
      '/api/admin/notification/read' &&
    request.method === 'POST'
  ) {
    const body =
      await safeJson(request);

    const id =
      Number(body.id);

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return json(
        {
          ok: false,
          error:
            'Invalid id'
        },
        400
      );
    }

    await env.DB
      .prepare(`
        UPDATE notifications
        SET read_at=?
        WHERE id=?
      `)
      .bind(
        nowIso(),
        id
      )
      .run();

    return json({
      ok: true
    });
  }

  return json(
    {
      ok: false,
      error: 'Not found'
    },
    404
  );
}

/*
  Login page
*/
function loginPage() {
  return new Response(
    `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin Login — North Bharat Jobs</title>
<style>
body{
  font-family:system-ui;
  background:#eef3f9;
  display:grid;
  place-items:center;
  min-height:100vh;
  margin:0
}
.box{
  background:white;
  padding:28px;
  border-radius:16px;
  box-shadow:0 10px 35px #0001;
  width:min(380px,90%)
}
input,button{
  width:100%;
  padding:12px;
  margin:7px 0;
  border-radius:9px;
  border:1px solid #ccd5e2;
  box-sizing:border-box
}
button{
  background:#155eef;
  color:white;
  border:0;
  font-weight:700
}
</style>
</head>
<body>
<form class="box"
      method="post"
      action="/api/admin/login">
<h1>North Bharat Jobs</h1>
<p>Admin Portal</p>
<input
  name="email"
  type="email"
  placeholder="Admin email"
  required>
<input
  name="password"
  type="password"
  placeholder="Password"
  required>
<button type="submit">
Login
</button>
</form>
</body>
</html>`,
    {
      headers: htmlHeaders
    }
  );
}

/*
  Admin login
*/
async function handleLogin(
  env,
  request
) {
  const contentType =
    request.headers.get(
      'content-type'
    ) || '';

  let email = '';
  let password = '';

  if (
    contentType.includes(
      'application/json'
    )
  ) {
    const body =
      await safeJson(request);

    email =
      String(
        body.email || ''
      );

    password =
      String(
        body.password || ''
      );
  } else {
    const form =
      await request.formData();

    email =
      String(
        form.get('email') || ''
      );

    password =
      String(
        form.get('password') || ''
      );
  }

  email =
    email
      .trim()
      .toLowerCase();

  /*
    First admin can be seeded from
    ADMIN_EMAIL / ADMIN_PASSWORD secrets.
  */
  await ensureAdmin(env);

  const admin =
    await env.DB
      .prepare(`
        SELECT *
        FROM admins
        WHERE email=?
      `)
      .bind(email)
      .first();

  if (
    !admin ||
    !(await verifyPassword(
      password,
      admin.password_hash
    ))
  ) {
    return new Response(
      'Invalid credentials',
      {
        status: 401,
        headers: {
          'content-type':
            'text/plain; charset=UTF-8'
        }
      }
    );
  }

  const token =
    randomToken();

  const tokenHash =
    await sha256Hex(token);

  const expires =
    new Date(
      Date.now() +
      SESSION_DAYS *
      86_400_000
    ).toISOString();

  await env.DB
    .prepare(`
      INSERT INTO sessions(
        token_hash,
        admin_id,
        expires_at
      )
      VALUES(?,?,?)
    `)
    .bind(
      tokenHash,
      admin.id,
      expires
    )
    .run();

  await env.DB
    .prepare(`
      UPDATE admins
      SET last_login_at=?
      WHERE id=?
    `)
    .bind(
      nowIso(),
      admin.id
    )
    .run();

  const headers = {
    ...jsonHeaders,
    'set-cookie':
      cookieHeader(
        token,
        SESSION_DAYS *
          86_400
      )
  };

  if (
    contentType.includes(
      'application/json'
    )
  ) {
    return new Response(
      JSON.stringify({
        ok: true
      }),
      {
        headers
      }
    );
  }

  return Response.redirect(
    new URL(
      '/admin/',
      request.url
    ),
    303
  );
}

/*
  Logout
*/
async function logout(
  env,
  request
) {
  const token =
    cookieToken(request);

  if (token) {
    await env.DB
      .prepare(`
        DELETE FROM sessions
        WHERE token_hash=?
      `)
      .bind(
        await sha256Hex(token)
      )
      .run();
  }

  return new Response(
    '',
    {
      status: 204,
      headers: {
        'set-cookie':
          cookieHeader('', 0)
      }
    }
  );
}

/*
  Public item HTML
*/
async function publicItemPage(
  env,
  request,
  slug
) {
  const item =
    await env.DB
      .prepare(`
        SELECT *
        FROM items
        WHERE
          slug=?
          AND status='published'
          AND (
            published_at IS NULL
            OR published_at >= datetime('now','-365 day')
          )
      `)
      .bind(slug)
      .first();

  if (!item) {
    return env.ASSETS.fetch(
      new Request(
        new URL(
          '/index.html',
          request.url
        ),
        request
      )
    );
  }

  const facts = [
    ['Post', item.title],
    ['Organization', item.organization],
    ['Category', item.category],
    ['Location', item.location],
    ['Vacancies', item.vacancies],
    ['Qualification', item.qualification],
    ['Eligibility', item.eligibility],
    ['Age Limit', item.age_limit],
    ['Age Relaxation', item.age_relaxation],
    ['Fee', item.fee],
    ['Salary', item.salary],
    ['Selection Process', item.selection_process],
    ['Application Start', item.application_start],
    ['Last Date', item.last_date],
    ['Exam Date', item.exam_date],
    ['How to Apply', item.how_to_apply],
    ['Important Dates', item.important_dates]
  ];

  const factsHtml =
    facts
      .filter(
        fact =>
          fact[1] !== null &&
          fact[1] !== undefined &&
          String(fact[1]).trim() !== ''
      )
      .map(
        fact =>
          `<div><b>${esc(fact[0])}</b><span>${esc(fact[1])}</span></div>`
      )
      .join('');

  const actions = [];

  if (item.official_url) {
    actions.push(
      `<a href="${esc(item.official_url)}" target="_blank" rel="noopener noreferrer">Official Website</a>`
    );
  }

  if (item.notification_url) {
    actions.push(
      `<a href="${esc(item.notification_url)}" target="_blank" rel="noopener noreferrer">Notification PDF</a>`
    );
  }

  if (item.apply_url) {
    actions.push(
      `<a href="${esc(item.apply_url)}" target="_blank" rel="noopener noreferrer">Apply Online</a>`
    );
  }

  return new Response(
    `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport"
      content="width=device-width,initial-scale=1">
<title>${esc(item.title)} | North Bharat Jobs</title>
<meta
  name="description"
  content="${esc(
    (item.description || '').slice(0, 155)
  )}">
<link rel="stylesheet"
      href="/style.css">
</head>

<body>

<header class="top">
<a href="/" class="brand">
North Bharat Jobs
</a>
<a href="/">
Home
</a>
</header>

<main class="detail">

<div class="badge">
${esc(item.type)}
</div>

<h1>
${esc(item.title)}
</h1>

<p class="muted">
${esc(item.organization || '')}
${item.location
  ? ` • ${esc(item.location)}`
  : ''}
</p>

<section class="facts">
${factsHtml}
</section>

<article>
<h2>Description</h2>
<p>
${esc(
  item.description ||
  'Verified details are shown from the available source evidence.'
)}
</p>
</article>

${
  actions.length
    ? `<div class="actions">${actions.join('')}</div>`
    : ''
}

</main>
</body>
</html>`,
    {
      headers: htmlHeaders
    }
  );
}

/*
  Main Worker
*/
export default {
  async fetch(
    request,
    env,
    ctx
  ) {
    const url =
      new URL(request.url);

    /*
      Login/logout do not require
      an existing session.
    */
    if (
      url.pathname ===
        '/api/admin/login' &&
      request.method === 'POST'
    ) {
      return handleLogin(
        env,
        request
      );
    }

    if (
      url.pathname ===
        '/api/admin/logout' &&
      request.method === 'POST'
    ) {
      return logout(
        env,
        request
      );
    }

    /*
      Seed first admin if configured.
    */
    await ensureAdmin(env);

    /*
      Admin pages
    */
    if (
      url.pathname === '/admin/' ||
      url.pathname === '/admin'
    ) {
      const admin =
        await adminFromRequest(
          env,
          request
        );

      if (!admin) {
        return loginPage();
      }

      return env.ASSETS.fetch(
        new Request(
          new URL(
            '/admin.html',
            request.url
          ),
          request
        )
      );
    }

    if (
      url.pathname ===
      '/admin.html'
    ) {
      const admin =
        await adminFromRequest(
          env,
          request
        );

      if (!admin) {
        return new Response(
          'Unauthorized',
          {
            status: 401
          }
        );
      }

      return env.ASSETS.fetch(
        request
      );
    }

    /*
      All admin APIs require a valid
      session.
    */
    if (
      url.pathname.startsWith(
        '/api/admin/'
      )
    ) {
      const admin =
        await requireAdmin(
          env,
          request
        );

      if (!admin) {
        return json(
          {
            ok: false,
            error:
              'Unauthorized'
          },
          401
        );
      }

      return adminApi(
        env,
        request,
        url,
        admin
      );
    }

    /*
      Public API
    */
    if (
      url.pathname ===
      '/api/jobs'
    ) {
      return publicList(
        env,
        url
      );
    }

    if (
      url.pathname.startsWith(
        '/api/jobs/'
      )
    ) {
      return publicItem(
        env,
        decodeURIComponent(
          url.pathname.slice(
            '/api/jobs/'.length
          )
        )
      );
    }

    /*
      Health endpoint
    */
    if (
      url.pathname ===
      '/api/health'
    ) {
      return json({
        ok: true,
        service:
          'north-bharat-jobs',
        time: nowIso()
      });
    }

    /*
      Sitemap
    */
    if (
      url.pathname ===
      '/sitemap.xml'
    ) {
      const rows =
        (
          await env.DB
            .prepare(`
              SELECT
                slug,
                updated_at
              FROM items
              WHERE
                status='published'
                AND (
                  published_at IS NULL
                  OR published_at >= datetime('now','-365 day')
                )
              ORDER BY
                updated_at DESC
              LIMIT 5000
            `)
            .all()
        ).results || [];

      const origin =
        siteOrigin(request);

      const staticUrls = [
        `${origin}/`,
        `${origin}/about.html`,
        `${origin}/contact.html`,
        `${origin}/privacy.html`
      ];

      const staticXml =
        staticUrls
          .map(
            value =>
              `<url><loc>${esc(value)}</loc></url>`
          )
          .join('');

      const itemXml =
        rows
          .map(
            row =>
              `<url><loc>${esc(
                `${origin}/item/${encodeURIComponent(row.slug)}`
              )}</loc><lastmod>${new Date(
                row.updated_at
              ).toISOString()}</lastmod></url>`
          )
          .join('');

      const body =
        `<?xml version="1.0" encoding="UTF-8"?>` +
        `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` +
        staticXml +
        itemXml +
        `</urlset>`;

      return new Response(
        body,
        {
          headers: {
            'content-type':
              'application/xml; charset=UTF-8',
            'cache-control':
              'public,max-age=900'
          }
        }
      );
    }

    /*
      Robots
    */
    if (
      url.pathname ===
      '/robots.txt'
    ) {
      return new Response(
        `User-agent: *
Allow: /
Disallow: /admin
Disallow: /api/admin
Sitemap: ${siteOrigin(request)}/sitemap.xml
`,
        {
          headers: {
            'content-type':
              'text/plain; charset=UTF-8'
          }
        }
      );
    }

    /*
      Public SEO item page
    */
    if (
      url.pathname.startsWith(
        '/item/'
      )
    ) {
      return publicItemPage(
        env,
        request,
        decodeURIComponent(
          url.pathname.slice(
            '/item/'.length
          )
        )
      );
    }

    /*
      IMPORTANT:
      /api/cron is intentionally NOT
      exposed anymore.

      Monitoring is performed only
      through the Cloudflare scheduled()
      handler or authenticated admin
      discovery endpoint.
    */

    if (
      request.method === 'GET'
    ) {
      return env.ASSETS.fetch(
        request
      );
    }

    return json(
      {
        ok: false,
        error: 'Not found'
      },
      404
    );
  },

  /*
    Cloudflare Cron Trigger
  */
  async scheduled(
    event,
    env,
    ctx
  ) {
    ctx.waitUntil(
      runMonitor(env)
    );
  }
};
