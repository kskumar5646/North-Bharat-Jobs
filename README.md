# North Bharat Jobs — Fresh Architecture

A clean Cloudflare Workers + D1 government-jobs information portal. This repository is intentionally independent of the previous North Bharat Jobs codebase.

## Architecture

- Official source first and primary authority.
- Official-source retry budget: maximum 20 attempts per source per UTC day, with a minimum 5-minute interval and controlled handling of 404/401/403/429/5xx/security challenges.
- After the official retry budget is exhausted, two configured secondary portals can be used for discovery/cross-checking.
- Secondary-source matches never auto-publish; they enter Admin verification.
- Conflicting portal data enters Admin verification without choosing a value automatically.
- Recruitment records require distinct official, notification-PDF and apply URLs before automatic publication.
- Notification identity and canonical URLs are used to update revisions in place instead of cloning extensions/corrections.
- Revision history is stored in `item_revisions`.
- Public records are retained for 365 days and then archived automatically.
- Admin portal supports verification, source configuration, runs, logs, notifications, audit history, password and email changes.
- No admin password is hardcoded in source. Initial bootstrap uses Cloudflare Worker Secrets `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
- No advertising, Search Console verification, previous Worker URL, previous D1 ID, or previous project files are included.

## First deployment

1. Create a brand-new D1 database.
2. Replace `REPLACE_WITH_NEW_D1_DATABASE_ID` in `wrangler.jsonc` with the new UUID.
3. Run `schema.sql` against the new database, then `seed.sql`.
4. Set Worker secrets `ADMIN_EMAIL` and `ADMIN_PASSWORD`.
5. Connect the new GitHub repository to a new Cloudflare Worker.
6. Deploy with `npx wrangler deploy`.
7. Configure Portal 1 and Portal 2 from Admin > Sources only after selecting lawful public sources you are permitted to fetch.

Cloudflare Workers builds use the repository's Wrangler configuration as the deployment source of truth.
