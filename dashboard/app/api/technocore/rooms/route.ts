import { fetchTechnocoreJson, normalizeRooms } from "@/app/lib/technocore";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export async function GET() {
  try {
    const raw = await fetchTechnocoreJson("https://technocore.chat/rooms?format=json");
    return Response.json(
      { rooms: normalizeRooms(raw) },
      { headers: { "cache-control": "no-store" } },
    );
  } catch (error) {
    const status = (error as Error & { status?: number }).status;
    if (status === 429) {
      return Response.json({ error: "upstream_rate_limited" }, { status: 429 });
    }
    return Response.json({ error: "upstream_unavailable" }, { status: 503 });
  }
}
