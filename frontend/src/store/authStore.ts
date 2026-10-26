import { create } from 'zustand';
import { injectStores } from '@/lib/api';
import type { UserProfile } from '@/types';

interface AuthState {
  user: UserProfile | null;
  accessToken: string | null;
  refreshToken: string | null;
  vaultKey: string | null;
  pendingMasterPassword: string | null;
  autoLockTimer: ReturnType<typeof setTimeout> | null;
  setAuth: (user: UserProfile, accessToken: string, vaultKey: string, refreshToken?: string) => void;
  setAccessToken: (token: string) => void;
  setVaultKey: (key: string) => void;
  setPendingMasterPassword: (password: string) => void;
  consumePendingMasterPassword: () => string | null;
  clearAuth: () => void;
  resetTimer: () => void;
}

export const useAuthStore = create<AuthState>((set, get) => ({
  user: null,
  accessToken: null,
  refreshToken: null,
  vaultKey: null,
  pendingMasterPassword: null,
  autoLockTimer: null,

  setAuth: (user, accessToken, vaultKey, refreshToken) => {
    set({ user, accessToken, vaultKey, refreshToken: refreshToken ?? get().refreshToken });
    get().resetTimer();
  },

  setAccessToken: (token) => {
    set({ accessToken: token });
  },

  setVaultKey: (key) => {
    set({ vaultKey: key });
    get().resetTimer();
  },

  setPendingMasterPassword: (password) => {
    set({ pendingMasterPassword: password });
  },

  consumePendingMasterPassword: () => {
    const { pendingMasterPassword } = get();
    set({ pendingMasterPassword: null });
    return pendingMasterPassword;
  },

  clearAuth: () => {
    const { autoLockTimer } = get();
    if (autoLockTimer) clearTimeout(autoLockTimer);
    set({ user: null, accessToken: null, refreshToken: null, vaultKey: null, pendingMasterPassword: null, autoLockTimer: null });
  },

  resetTimer: () => {
    const { autoLockTimer } = get();
    if (autoLockTimer) clearTimeout(autoLockTimer);
    const newTimer = setTimeout(() => {
      set({ vaultKey: null });
    }, 600000);
    set({ autoLockTimer: newTimer });
  },
}));

injectStores(
  () => useAuthStore.getState().accessToken || '',
  () => useAuthStore.getState().vaultKey || '',
  () => useAuthStore.getState().refreshToken || '',
  (token: string) => useAuthStore.getState().setAccessToken(token),
);
