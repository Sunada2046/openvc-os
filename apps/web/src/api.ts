export interface Principal {
  accountId: string;
  organizationId: string;
  email: string;
  name: string;
  roles: Array<{ code: string; name: string }>;
  permissions: string[];
}

export interface AuthState {
  authenticated: true;
  account: Principal;
  csrfToken: string;
  expiresAt: string;
}

export interface CoreObject {
  id: string;
  objectType: string;
  name: string;
  status: string;
  data: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

let csrfToken = "";

export function setCsrfToken(value: string) {
  csrfToken = value;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = init.method || "GET";
  const headers = new Headers(init.headers);
  if (init.body) headers.set("Content-Type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers.set("X-CSRF-Token", csrfToken);
  }
  const response = await fetch(path, {
    ...init,
    headers,
    credentials: "include",
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `Request failed with status ${response.status}.`);
  }
  return payload as T;
}
