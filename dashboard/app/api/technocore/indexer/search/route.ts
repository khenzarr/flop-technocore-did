import { fetchTechnocoreJson, normalizeIndexerSearch, normalizeIndexerUrl } from "../../../../lib/technocore.ts";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const base = normalizeIndexerUrl(process.env.TECHNOCORE_INDEXER_URL);
  const query = new URL(request.url).searchParams.get("q")?.trim().slice(0, 200) ?? "";
  if (!base || !query) return Response.json({ configured: Boolean(base), messages: [], scope: "observed_only" });
  try {
    const value = await fetchTechnocoreJson(`${base}/search?q=${encodeURIComponent(query)}&limit=50`);
    return Response.json({ configured: true, messages: normalizeIndexerSearch(value), scope: "observed_only" }, { headers: { "cache-control": "no-store" } });
  } catch {
    return Response.json({ configured: true, messages: [], scope: "observed_only", error: "indexer_unavailable" }, { status: 503 });
  }
}