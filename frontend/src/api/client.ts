import * as SecureStore from 'expo-secure-store';
import { Platform } from 'react-native';

const BASE = process.env.EXPO_PUBLIC_BACKEND_URL || '';
const TOKEN_KEY = 'skyhawk_auth_token';
const REFRESH_TOKEN_KEY = 'skyhawk_refresh_token';

/**
 * Module-level callback fired when any authenticated request receives a 401.
 * AuthProvider sets this to clear the session and show a "session expired" message.
 */
let _onUnauthorized: (() => void) | null = null;
export function setUnauthorizedHandler(cb: () => void) {
  _onUnauthorized = cb;
}

async function getStoredToken(): Promise<string | null> {
  if (Platform.OS === 'web') {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  }
  return await SecureStore.getItemAsync(TOKEN_KEY);
}

async function getStoredRefreshToken(): Promise<string | null> {
  if (Platform.OS === 'web') {
    try { return localStorage.getItem(REFRESH_TOKEN_KEY); } catch { return null; }
  }
  return await SecureStore.getItemAsync(REFRESH_TOKEN_KEY);
}

export async function setToken(token: string | null) {
  if (Platform.OS === 'web') {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
    return;
  }
  if (token) await SecureStore.setItemAsync(TOKEN_KEY, token);
  else await SecureStore.deleteItemAsync(TOKEN_KEY);
}

export async function setSession(accessToken: string | null, refreshToken: string | null) {
  await setToken(accessToken);
  if (Platform.OS === 'web') {
    if (refreshToken) localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
    else localStorage.removeItem(REFRESH_TOKEN_KEY);
  } else if (refreshToken) {
    await SecureStore.setItemAsync(REFRESH_TOKEN_KEY, refreshToken);
  } else {
    await SecureStore.deleteItemAsync(REFRESH_TOKEN_KEY);
  }
}

let refreshPromise: Promise<boolean> | null = null;
async function refreshAccessToken(): Promise<boolean> {
  if (refreshPromise) return refreshPromise;
  refreshPromise = (async () => {
    const refreshToken = await getStoredRefreshToken();
    if (!refreshToken) return false;
    try {
      const response = await fetch(`${BASE}/api/auth/refresh`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
      if (!response.ok) {
        await setSession(null, null);
        return false;
      }
      const data = await response.json();
      await setSession(data.access_token, data.refresh_token);
      return true;
    } catch {
      return false;
    }
  })();
  try { return await refreshPromise; } finally { refreshPromise = null; }
}

export async function revokeSession() {
  const refreshToken = await getStoredRefreshToken();
  if (refreshToken) {
    try {
      await fetch(`${BASE}/api/auth/logout-native`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });
    } catch { /* Local sign-out must still succeed while offline. */ }
  }
  await setSession(null, null);
}

export async function getToken() {
  return await getStoredToken();
}

/** Exchange a protected file path for a five-minute, file-scoped download URL. */
export async function getProtectedFileUrl(path: string): Promise<string> {
  let normalized = path.replace(/^\/api/, '');
  normalized = normalized.replace(/^\/uploads\//, '/files/');
  const result = await api<{ url: string }>(`${normalized}/access`);
  return `${BASE}${result.url}`;
}

/**
 * Upload a file via multipart/form-data (e.g. to POST /uploads).
 * `file` is a React Native picker asset shape: { uri, name?, type? }.
 */
export async function apiUpload<T = any>(
  path: string,
  file: { uri: string; name?: string; type?: string }
): Promise<T> {
  const form = new FormData();
  form.append('file', {
    uri: file.uri,
    name: file.name || 'upload.jpg',
    type: file.type || 'image/jpeg',
  } as any);

  const send = async () => {
    const token = await getStoredToken();
    return fetch(`${BASE}/api${path}`, {
      method: 'POST', headers: token ? { Authorization: `Bearer ${token}` } : undefined, body: form,
    });
  };
  let res = await send();
  if (res.status === 401 && await refreshAccessToken()) res = await send();

  const text = await res.text();
  let data: any = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = text;
  }
  if (!res.ok) {
    const msg = (data && (data.detail || data.message)) || `Upload failed (${res.status})`;
    throw new Error(msg);
  }
  return data as T;
}

/** Status codes worth retrying on (GET only, to avoid duplicate side-effects). */
const RETRYABLE_STATUS = new Set([408, 502, 503, 504]);
const MAX_RETRIES = 3;

function sleep(ms: number) {
  return new Promise<void>((resolve) => setTimeout(resolve, ms));
}

export async function api<T = any>(
  path: string,
  opts: { method?: string; body?: any; auth?: boolean; skipUnauthorizedHandler?: boolean } = {}
): Promise<T> {
  const { method = 'GET', body, auth = true, skipUnauthorizedHandler = false } = opts;

  let refreshed = false;
  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (auth) {
      const token = await getStoredToken();
      if (token) headers.Authorization = `Bearer ${token}`;
    }

    let res: Response;
    try {
      res = await fetch(`${BASE}/api${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      });
    } catch {
      // Network-level failure (offline, DNS, timeout)
      const isLastAttempt = attempt >= MAX_RETRIES - 1;
      if (isLastAttempt) {
        throw new Error('Network error — check your connection and try again.');
      }
      await sleep(Math.min(500 * 2 ** attempt, 4000));
      continue;
    }

    // 401 on an authenticated call: session expired — clear it and stop retrying.
    if (res.status === 401 && auth) {
      if (!refreshed && await refreshAccessToken()) {
        refreshed = true;
        attempt -= 1;
        continue;
      }
      if (!skipUnauthorizedHandler) _onUnauthorized?.();
      throw new Error('SESSION_EXPIRED');
    }

    // Retry transient server errors on safe (read-only) requests only.
    if (RETRYABLE_STATUS.has(res.status) && method === 'GET' && attempt < MAX_RETRIES - 1) {
      await sleep(Math.min(500 * 2 ** attempt, 4000));
      continue;
    }

    const text = await res.text();
    let data: any = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch {
      data = text;
    }

    if (!res.ok) {
      const msg = (data && (data.detail || data.message)) || `Request failed (${res.status})`;
      throw new Error(msg);
    }

    return data as T;
  }

  throw new Error('Request failed after retries');
}
