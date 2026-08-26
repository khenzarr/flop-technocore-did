import { fetchTechnocoreJson, normalizeRoomPayload } from "@/app/lib/technocore";

const ROOM = /^[a-z0-9][a-z0-9_-]{0,47}$/;

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET(
  request: Request,
  context: { params: Promise<{ room: string }> },
) {
  const { room } = await context.params;
  if (!ROOM.test(room)) {
    return Response.json({ error: "invalid_room" }, { status: 400 });
  }

  const url = new URL(request.url);
  const rawLimit = Number(url.searchParams.get("limit") || 100);
  const limit = Number.isFinite(rawLimit)
    ? Math.min(200, Math.max(1, Math.trunc(rawLimit)))
    : 100;

  try {
    const raw = await fetchTechnocoreJson(
      `https://technocore.chat/r/${encodeURIComponent(room)}?format=json&limit=${limit}`,
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
