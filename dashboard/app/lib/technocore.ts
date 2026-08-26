const MAX_UPSTREAM_BYTES = 1024 * 1024;
const UPSTREAM_TIMEOUT_MS = 6000;
const INDEXER_MAX_RESULTS = 50;
const ROOM_PATTERN = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const MAX_TIMESTAMP = 64;
const MAX_WRITER = 512;
const MAX_TEXT = 16384;
const MAX_NONCE = 128;

export type TrustMode = "observer" | "browser-did" | "trusted-local-signer";
export type IndexerHealth = {
  configured: boolean;
  reachable: boolean;
  worker_fresh?: boolean;
  messages?: number;
  scope: "observed_only";
};
export type IndexerSearchResult = {
  room: string;
  seq: number;
  ts: string;
  writer: string;
  text: string;
  nonce?: string | null;
};

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

export function normalizeTrustMode(value: unknown): TrustMode {
  return value === "browser-did" || value === "trusted-local-signer" ? value : "observer";
}

export function normalizeIndexerUrl(value: unknown): string | undefined {
  if (typeof value !== "string" || value.length > 2048 || !value.trim()) return undefined;
  try {
    const url = new URL(value.trim());
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash || url.search) return undefined;
    if (url.pathname !== "" && url.pathname !== "/") return undefined;
    const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "::1";
    if (url.protocol !== "https:" && !loopback) return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
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

export async function fetchTechnocoreHealthJson(url: string): Promise<unknown> {
  const response = await fetch(url, {
    cache: "no-store",
    redirect: "error",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  if (!response.ok && response.status !== 503) {
    const error = new Error("upstream_error") as Error & { status?: number };
    error.status = response.status;
    throw error;
  }
  const value = await readBoundedJson(response);
  const record = asRecord(value);
  if (response.status === 503 && record?.ok === true) throw new Error("invalid_indexer_health");
  if (response.status !== 503 && record?.ok === false) throw new Error("invalid_indexer_health");
  return value;
}

export function normalizeIndexerHealth(value: unknown, configured = true): IndexerHealth {
  const record = asRecord(value);
  if (
    !record ||
    typeof record.ok !== "boolean" ||
    record.database !== "ok" ||
    typeof record.worker_fresh !== "boolean" ||
    record.ok !== record.worker_fresh
  ) {
    throw new Error("invalid_indexer_health");
  }
  const result: IndexerHealth = {
    configured,
    reachable: true,
    worker_fresh: record.worker_fresh,
    scope: "observed_only",
  };
  const messages = nonNegativeSafeInteger(record.messages);
  if (messages !== undefined) result.messages = messages;
  return result;
}

export function normalizeIndexerSearch(value: unknown): IndexerSearchResult[] {
  const record = asRecord(value);
  if (!record || !Array.isArray(record.messages)) throw new Error("invalid_indexer_search");
  const results: IndexerSearchResult[] = [];
  for (const item of record.messages) {
    if (results.length >= INDEXER_MAX_RESULTS) break;
    const row = asRecord(item);
    const room = requiredString(row?.room);
    const seq = nonNegativeSafeInteger(row?.seq);
    const ts = requiredString(row?.ts);
    const writer = requiredString(row?.writer);
    const text = requiredString(row?.text);
    const nonce = row?.nonce;
    if (!room || !ROOM_PATTERN.test(room) || seq === undefined || ts === null || ts.length > MAX_TIMESTAMP || writer === null || writer.length > MAX_WRITER || text === null || text.length > MAX_TEXT) continue;
    if (nonce !== null && nonce !== undefined && (typeof nonce !== "string" || nonce.length > MAX_NONCE)) continue;
    results.push({ room, seq, ts, writer, text, nonce: typeof nonce === "string" ? nonce : null });
  }
  return results;
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
