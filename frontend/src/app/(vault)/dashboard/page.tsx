"use client";
import { useEffect, useState } from 'react';
import { CheckCircle2, Clock3, Inbox, Send } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import { useWorkflowStore } from '@/store/workflowStore';
import type { AuditChainEntry, AegisVaultRequest } from '@/types';

function StatCard({ label, value, icon: Icon }: { label: string; value: number; icon: React.ElementType }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-400/10 text-emerald-300"><Icon className="h-5 w-5" /></div>
        <div><p className="text-2xl font-semibold">{value}</p><p className="text-xs text-zinc-500">{label}</p></div>
      </div>
    </div>
  );
}

function RequestCard({ request }: { request: AegisVaultRequest }) {
  const statusColor: Record<string, string> = { PENDING: 'text-yellow-300 border-yellow-500/30 bg-yellow-500/10', APPROVED: 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10', REJECTED: 'text-red-300 border-red-500/30 bg-red-500/10' };
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="flex items-center justify-between">
        <p className="text-sm font-semibold">{request.type.replace(/_/g, ' ')}</p>
        <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${statusColor[request.status] || 'text-zinc-400'}`}>{request.status}</span>
      </div>
      <p className="mt-2 text-xs text-zinc-500">Submitted {new Date(request.submitted_at).toLocaleDateString()}</p>
    </div>
  );
}

export default function Dashboard() {
  const user = useAuthStore((s) => s.user);
  const { stats, inbox, fetchStats, fetchList } = useWorkflowStore();
  const [logs, setLogs] = useState<AuditChainEntry[]>([]);
  const [error, setError] = useState('');

  useEffect(() => {
    async function load() {
      try {
        await Promise.all([fetchStats(), fetchList('inbox')]);
        const logsRes = await api.get('/audit/logs');
        setLogs(logsRes.data.data.slice(0, 6));
      } catch { setError('Dashboard data is unavailable.'); }
    }
    load();
  }, [fetchList, fetchStats]);

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-2">
        <p className="text-sm font-medium text-emerald-300">Welcome back, {user?.full_name}</p>
        <h1 className="text-3xl font-semibold">AegisVault Dashboard</h1>
      </header>
      {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
      <section className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Pending My Approval" value={stats?.pending_approvals ?? 0} icon={Inbox} />
        <StatCard label="My Requests" value={stats?.my_requests ?? 0} icon={Send} />
        <StatCard label="Approved" value={stats?.approved ?? 0} icon={CheckCircle2} />
        <StatCard label="Security Score" value={stats?.security_score ?? 0} icon={Clock3} />
      </section>
      <section className="space-y-3">
        <div className="flex items-center gap-2"><Clock3 className="h-5 w-5 text-zinc-500" /><h2 className="font-semibold">Next Approvals</h2></div>
        {inbox.length === 0 ? (
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-8 text-center text-sm text-zinc-500">No pending approvals.</div>
        ) : (
          <div className="grid gap-3 lg:grid-cols-2">{inbox.slice(0, 4).map((r) => <RequestCard key={r.id} request={r} />)}</div>
        )}
      </section>
      {logs.length > 0 && (
        <section className="space-y-3">
          <h2 className="font-semibold">Recent Activity</h2>
          <div className="space-y-2">
            {logs.map((log) => (
              <div key={log.id} className="flex items-center justify-between rounded-lg border border-zinc-800 bg-zinc-900 px-4 py-3 text-sm">
                <span className="font-medium">{log.action}</span>
                <span className="text-xs text-zinc-500">{new Date(log.recorded_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
