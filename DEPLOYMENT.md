# Fresh deployment checklist

## GitHub
- Create a new repository.
- Upload the contents of this folder, not the parent folder itself.
- Keep `wrangler.jsonc` at repository root.
- Keep `src/index.js` at exactly `src/index.js`.
- Keep `public/index.html` at exactly `public/index.html`.
- There is intentionally no old Search Console verification HTML or AdSense code in this project.

## D1
Create a new D1 database and put its UUID in `wrangler.jsonc`.

Dashboard path: Cloudflare → D1 SQL → Create database.

Then run `schema.sql` and `seed.sql` against the new database.

## Secrets
Set these as Worker secrets, not GitHub files:

- `ADMIN_EMAIL`
- `ADMIN_PASSWORD`

The first successful admin login creates the initial admin record. After that, password changes are managed from the Admin Portal.

## Workers Builds
Connect the new repository. Production branch: `main`. Build command can remain blank. Deploy command: `npx wrangler deploy`. Root directory: `/`.

## Portal fallback
The repository creates two disabled placeholder portal slots. Admin must replace their URL/domain and enable them. Do not use a source unless its public access and applicable terms permit automated GET requests.
