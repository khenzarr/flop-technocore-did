import { fetchTechnocoreHealthJson, normalizeIndexerHealth, normalizeIndexerUrl } from "../../../lib/technocore.ts";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  const base = normalizeIndexerUrl(process.env.TECHNOCORE_INDEXER_URL);
  if (!base) return Response.json({ configured: false, reachable: false, scope: "observed_only" });
  try {
    const health = normalizeIndexerHealth(await fetchTechnocoreHealthJson(`${base}/health`));
    return Response.json(health, { status: health.worker_fresh === false ? 503 : 200, headers: { "cache-control": "no-store" } });
  } catch {
    return Response.json({ configured: true, reachable: false, scope: "observed_only" }, { headers: { "cache-control": "no-store" } });
  }
}