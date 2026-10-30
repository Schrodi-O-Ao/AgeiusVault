import axios from 'axios';

export const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL ?? 'http://127.0.0.1:8000/api/v1',
  withCredentials: true,
});

let getAccessToken = () => '';
let getVaultKey = () => '';
let getRefreshToken = () => '';
let onTokenRefreshed: (token: string) => void = () => {};

export const injectStores = (
  accessFn: () => string,
  vaultFn: () => string,
  refreshFn: () => string,
  onRefresh: (token: string) => void,
) => {
  getAccessToken = accessFn;
  getVaultKey = vaultFn;
  getRefreshToken = refreshFn;
  onTokenRefreshed = onRefresh;
};

// Attach tokens to every request
api.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  const vaultKey = getVaultKey();
  const needsVaultKey =
    config.url?.startsWith('/requests') ||
    config.url?.startsWith('/delegations') ||
    config.url?.startsWith('/users/me/key-regenerate');
  if (vaultKey && needsVaultKey) {
    config.headers['X-Vault-Key'] = vaultKey;
  }
  return config;
});

// Refresh token interceptor: retry once on 401
let isRefreshing = false;
let failedQueue: Array<{ resolve: (val: unknown) => void; reject: (reason?: unknown) => void }> = [];

const processQueue = (error: unknown, token: string | null = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers.Authorization = `Bearer ${token}`;
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      const refreshToken = getRefreshToken();
      if (!refreshToken) {
        isRefreshing = false;
        return Promise.reject(error);
      }

      try {
        const res = await axios.post(
          `${api.defaults.baseURL}/auth/refresh`,
          { refresh_token: refreshToken },
        );
        const newToken = res.data.access_token;
        onTokenRefreshed(newToken);
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        processQueue(null, newToken);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  },
);

type ApiValidationDetail = { loc?: Array<string | number>; msg?: string };
type ApiErrorPayload = { detail?: string | ApiValidationDetail[]; message?: string };

export const extractErrorMessage = (err: unknown): string => {
  if (!err || typeof err !== 'object') return "An unexpected error occurred";

  const response = 'response' in err && err.response && typeof err.response === 'object'
    ? err.response
    : undefined;
  const responseData = response && 'data' in response
    ? response.data as ApiErrorPayload
    : undefined;
  if (responseData) {
    if (typeof responseData.detail === 'string') {
      return responseData.detail;
    }
    if (Array.isArray(responseData.detail)) {
      return responseData.detail
        .map((e) => {
          const locStr = e.loc ? e.loc.filter((l) => l !== 'body').join('.') : '';
          return `${locStr ? locStr + ': ' : ''}${e.msg}`;
        })
        .join(', ');
    }
    if (responseData.message) {
      return responseData.message;
    }
  }
  
  if (err instanceof Error) return err.message;
  return "An unexpected error occurred";
};
