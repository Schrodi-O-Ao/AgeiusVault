import { Activity } from 'lucide-react';
import type { AuditChainEntry } from '@/types';

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

export function ActivityFeed({ logs }: { logs: AuditChainEntry[] }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900">
      <div className="flex items-center justify-between border-b border-zinc-800 px-5 py-4">
        <h2 className="font-semibold">Recent Activity</h2>
        <Activity className="h-5 w-5 text-zinc-500" />
      </div>
      <div className="divide-y divide-zinc-800">
        {logs.length === 0 ? (
          <p className="px-5 py-8 text-sm text-zinc-500">No audit events yet.</p>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="grid gap-1 px-5 py-3 sm:grid-cols-[1fr_auto] sm:items-center">
              <p className="text-sm font-medium">{log.action.replaceAll('_', ' ')}</p>
              <p className="text-xs text-zinc-500">{formatDate(log.recorded_at)}</p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

