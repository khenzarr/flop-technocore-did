const MAX_UPSTREAM_BYTES = 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 6000;

export type Room = {
  name: string;
  size?: number;
  idle_seconds?: number;
  topic?: string;
};

export type Message = {
  seq: number;
  ts: string;
  from: string;
  text: string;
  nonce?: number | string;
};

export type RoomPayload = {
  messages: Message[];
  first_seq?: number;
  last_seq?: number;
  gap?: boolean;
};

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nonNegativeSafeInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined;
}

function requiredString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  if (!contentType.includes("application/json")) {
    throw new Error("unexpected_content_type");
  }

  if (!response.body) throw new Error("missing_body");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > MAX_UPSTREAM_BYTES) {
        await reader.cancel("response_too_large");
        throw new Error("response_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

export async function fetchTechnocoreJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    cache: "no-store",
    redirect: "error",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });

  if (!response.ok) {
    const error = new Error("upstream_error") as Error & { status?: number };
    error.status = response.status;
    throw error;
  }

  return readBoundedJson(response);
}

export function normalizeRooms(value: unknown): Room[] {
  const record = asRecord(value);
  const source = Array.isArray(value) ? value : record?.rooms;
  if (!Array.isArray(source)) throw new Error("invalid_rooms_schema");

  const rooms: Room[] = [];
  for (const item of source) {
    const room = asRecord(item);
    if (!room) continue;
    const name = requiredString(room.name ?? room.room);
    if (!name) continue;
    const normalized: Room = { name };
    const size = nonNegativeSafeInteger(room.size ?? room.count);
    const idle = nonNegativeSafeInteger(room.idle_seconds ?? room.idle);
    if (size !== undefined) normalized.size = size;
    if (idle !== undefined) normalized.idle_seconds = idle;
    if (typeof room.topic === "string") normalized.topic = room.topic;
    rooms.push(normalized);
  }

  return rooms;
}

export function normalizeRoomPayload(value: unknown): RoomPayload {
  const record = asRecord(value);
  if (!record || !Array.isArray(record.messages)) throw new Error("invalid_room_schema");

  const messages: Message[] = [];
  for (const item of record.messages) {
    const message = asRecord(item);
    if (!message) continue;
    const seq = nonNegativeSafeInteger(message.seq);
    const ts = requiredString(message.ts);
    const from = requiredString(message.from);
    const text = requiredString(message.text);
    if (seq === undefined || !ts || !from || text === null) continue;
    const normalized: Message = { seq, ts, from, text };
    if (typeof message.nonce === "number" && nonNegativeSafeInteger(message.nonce) !== undefined) {
      normalized.nonce = message.nonce;
    } else if (typeof message.nonce === "string" && /^\d{1,128}$/.test(message.nonce)) {
      normalized.nonce = message.nonce;
    }
    messages.push(normalized);
  }

  const payload: RoomPayload = { messages };
  const firstSeq = nonNegativeSafeInteger(record.first_seq);
  const lastSeq = nonNegativeSafeInteger(record.last_seq);
  if (firstSeq !== undefined && lastSeq !== undefined && firstSeq <= lastSeq) {
    payload.first_seq = firstSeq;
    payload.last_seq = lastSeq;
  }
  if (typeof record.gap === "boolean") payload.gap = record.gap;
  return payload;
}
