import { fetchTechnocoreJson, normalizeRoomPayload } from "@/app/lib/technocore";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(request: Request) {
  const url = new URL(request.url);
  const rawSince = Number(url.searchParams.get("since") || 0);
  const since = Number.isSafeInteger(rawSince) && rawSince >= 0 ? rawSince : 0;
  const rawLimit = Number(url.searchParams.get("limit") || 100);
  const limit = Number.isFinite(rawLimit) ? Math.min(200, Math.max(1, Math.trunc(rawLimit))) : 100;

  try {
    const raw = await fetchTechnocoreJson(
      `https://technocore.chat/r/events?format=json&since=${since}&limit=${limit}`,
    );
    return Response.json(normalizeRoomPayload(raw), {
      headers: { "cache-control": "no-store" },
    });
  } catch (error) {
    const status = (error as Error & { status?: number }).status;
    if (status === 429) {
      return Response.json({ error: "upstream_rate_limited" }, { status: 429 });
    }
    return Response.json({ error: "upstream_unavailable" }, { status: 503 });
  }
}
