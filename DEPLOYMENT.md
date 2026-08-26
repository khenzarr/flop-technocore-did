# Deployment

## Dashboard on Vercel

1. Import the GitHub repository.
2. Set **Root Directory** to `dashboard`.
3. Keep the detected Next.js build settings: `npm run build`, Node `>=22.13.0`.
4. Optional: define Vercel **Project Settings → Environment Variables** `TECHNOCORE_INDEXER_URL` for Production/Preview as an exact HTTPS origin/root URL, for example `https://indexer.example.com`. Do not include credentials, query, fragment, or path. HTTP is accepted only for explicit loopback/local development.
5. After deployment, verify the home page, public room refresh, one room feed, fallback labeling, security headers, desktop layout, and a 390 px mobile viewport.

The dashboard is stateless and reads bounded upstream windows. It is not a persistent index and does not host signing. If the variable is absent or invalid, the indexer status is **not configured** and search remains empty. Transport, timeout, redirect, MIME, JSON, and response-size failures are shown as **unreachable**. A reachable structured HTTP 503 health response with `worker_fresh: false` remains reachable and is shown as **stale**.

## Optional indexer

Run `indexer/` on a long-running service with a durable volume mounted at `/data`. Set `TECHNOCORE_INDEX_DB=/data/technocore-index.sqlite3`, put the read API behind external HTTPS (required for non-loopback dashboard configuration), rate limiting, and access policy, monitor `/health`, and define backups, retention, disk quota, and alerting.

Do not place the indexer on ephemeral serverless storage. Pin the container base by digest in an operator deployment lock before production.

## Rollback

Redeploy the previous immutable Vercel build for the dashboard. For the indexer, stop the new worker, preserve the volume, and restore a tested SQLite backup only under the operator's recovery procedure.
