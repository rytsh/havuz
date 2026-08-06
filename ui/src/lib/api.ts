import type {
  Family,
  GroupSnapshot,
  LiveSession,
  PinReport,
  Pool,
  PoolIdentities,
  Summary,
  TraceDetail,
  TraceResponse,
  User,
} from "./types";

/**
 * Bearer token for a remote admin listener.
 *
 * Kept in sessionStorage rather than localStorage: it disappears when the tab
 * closes, which is the right lifetime for an operator console.
 */
const TOKEN_KEY = "havuz.token";

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  if (init.body) headers.set("content-type", "application/json");

  const response = await fetch(path, { ...init, headers });

  if (!response.ok) {
    let code = "unknown";
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      code = body?.error?.code ?? code;
      message = body?.error?.message ?? message;
    } catch {
      // A non-JSON error body is still worth surfacing verbatim.
    }
    throw new ApiError(response.status, code, message);
  }

  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export const api = {
  summary: () => request<Summary>("/api/v1/summary"),
  families: () => request<{ families: Family[] }>("/api/v1/families").then((r) => r.families),
  pools: () => request<{ pools: Pool[]; warnings: Summary["warnings"] }>("/api/v1/pools"),
  users: () => request<{ users: User[] }>("/api/v1/users").then((r) => r.users),
  pins: () => request<PinReport>("/api/v1/pins"),
  traces: (params: URLSearchParams) => request<TraceResponse>(`/api/v1/traces?${params}`),
  trace: (id: number) => request<TraceDetail>(`/api/v1/traces/${id}`),
  /**
   * Ask the database to stop a query that is running right now.
   *
   * The session stays connected — this is the operator's `Ctrl-C`, not a
   * disconnect. Postgres never confirms a cancellation, so a resolved promise
   * means the request was delivered, not that the query has stopped.
   */
  cancelTrace: (id: number) => request<{ trace: number; delivered: boolean }>(`/api/v1/traces/${id}/cancel`, { method: "POST" }),
  clearTraces: () => request<{ deleted: number }>("/api/v1/traces", { method: "DELETE" }),
  poolTargets: (name: string) => request<GroupSnapshot>(`/api/v1/pools/${encodeURIComponent(name)}/targets`),
  poolIdentities: (name: string) =>
    request<PoolIdentities>(`/api/v1/pools/${encodeURIComponent(name)}/identities`),
  resetPins: () => request<unknown>("/api/v1/pins", { method: "DELETE" }),

  createPool: (body: unknown) => request<Pool>("/api/v1/pools", { method: "POST", body: JSON.stringify(body) }),
  updatePool: (name: string, body: unknown) =>
    request<Pool>(`/api/v1/pools/${encodeURIComponent(name)}`, { method: "PATCH", body: JSON.stringify(body) }),
  deletePool: (name: string) => request<unknown>(`/api/v1/pools/${encodeURIComponent(name)}`, { method: "DELETE" }),
  pausePool: (name: string) => request<unknown>(`/api/v1/pools/${encodeURIComponent(name)}/pause`, { method: "POST" }),
  resumePool: (name: string) =>
    request<unknown>(`/api/v1/pools/${encodeURIComponent(name)}/resume`, { method: "POST" }),
  probePool: (name: string) =>
    request<{ ok: boolean; probe?: { version: string; latency_ms: number; read_only: boolean }; error?: string }>(
      `/api/v1/pools/${encodeURIComponent(name)}/probe`,
      { method: "POST" },
    ),
  /**
   * End every live session on a pool without closing it.
   *
   * A session reads its policy — read-only above all — once, at connect time.
   * This is how an operator who has just frozen writes stops waiting for the
   * clients already inside to reconnect on their own.
   */
  kickPool: (name: string) =>
    request<{ pool: string; kicked: number }>(`/api/v1/pools/${encodeURIComponent(name)}/kick`, { method: "POST" }),

  createUser: (body: unknown) => request<{ name: string }>("/api/v1/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (name: string, body: unknown) =>
    request<{ updated: string; kicked: number }>(`/api/v1/users/${encodeURIComponent(name)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteUser: (name: string) => request<unknown>(`/api/v1/users/${encodeURIComponent(name)}`, { method: "DELETE" }),
  kickUser: (name: string) =>
    request<{ user: string; kicked: number }>(`/api/v1/users/${encodeURIComponent(name)}/kick`, { method: "POST" }),
  sessions: () => request<{ sessions: LiveSession[] }>("/api/v1/sessions").then((r) => r.sessions),
  kickSession: (id: number) =>
    request<{ session: number; kicked: boolean }>(`/api/v1/sessions/${id}/kick`, { method: "POST" }),
};

/**
 * Split an operator's alias list into names.
 *
 * Commas and whitespace both separate, because a list typed by hand arrives
 * either way, and duplicates are dropped here rather than being sent to the
 * server only to come back as a validation error about something the operator
 * did not mean to say twice.
 */
export function parseAliases(value: string): string[] {
  return [...new Set(value.split(/[,\s]+/).filter(Boolean))];
}

/** Human-readable fan-in, e.g. `33.3x`. */
export function formatFanIn(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${value.toFixed(1)}x`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
  return `${Math.floor(seconds / 86400)}d`;
}

export function formatMicros(micros: number): string {
  if (micros < 1000) return `${micros}µs`;
  if (micros < 1_000_000) return `${(micros / 1000).toFixed(1)}ms`;
  return `${(micros / 1_000_000).toFixed(2)}s`;
}
