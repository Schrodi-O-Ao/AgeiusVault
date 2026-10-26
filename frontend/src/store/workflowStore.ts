import { create } from 'zustand';
import { api } from '@/lib/api';
import type { AegisVaultRequest, DashboardStats, RequestTypeInfo } from '@/types';

interface WorkflowState {
  requestTypes: RequestTypeInfo[];
  inbox: AegisVaultRequest[];
  outbox: AegisVaultRequest[];
  stats: DashboardStats | null;
  isLoading: boolean;
  fetchTypes: () => Promise<void>;
  fetchStats: () => Promise<void>;
  fetchList: (view: 'inbox' | 'outbox') => Promise<void>;
}

export const useWorkflowStore = create<WorkflowState>((set) => ({
  requestTypes: [],
  inbox: [],
  outbox: [],
  stats: null,
  isLoading: false,

  fetchTypes: async () => {
    const res = await api.get('/requests/types');
    set({ requestTypes: res.data.data });
  },

  fetchStats: async () => {
    const res = await api.get('/requests/stats');
    set({ stats: res.data.data });
  },

  fetchList: async (view) => {
    set({ isLoading: true });
    try {
      const res = await api.get(`/requests/${view}`);
      if (view === 'inbox') set({ inbox: res.data.data });
      if (view === 'outbox') set({ outbox: res.data.data });
    } finally {
      set({ isLoading: false });
    }
  },
}));
