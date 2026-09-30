export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  if (init?.body && !(init.body instanceof FormData))
    headers.set("Content-Type", "application/json");
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    headers,
    credentials: "same-origin",
    cache: "no-store",
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail =
      typeof body?.detail === "string" ? body.detail : "The request could not be completed.";
    throw new Error(
      response.status === 401 ? "Your session has ended. Reload to sign in." : detail,
    );
  }
  return response.json();
}

export function date(value?: string, compact = false) {
  if (!value) return "—";
  const parsed = new Date(
    value.endsWith("Z") || /[+-]\d\d:\d\d$/.test(value) ? value : `${value}Z`,
  );
  return Number.isNaN(parsed.valueOf())
    ? "—"
    : new Intl.DateTimeFormat(
        undefined,
        compact
          ? { month: "short", day: "numeric" }
          : { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" },
      ).format(parsed);
}
export function humanize(value: string) {
  return value.replaceAll("_", " ");
}
export function exportUrl(id: string, format: string) {
  return `/api/v1/scans/${encodeURIComponent(id)}/export?format=${encodeURIComponent(format)}`;
}
