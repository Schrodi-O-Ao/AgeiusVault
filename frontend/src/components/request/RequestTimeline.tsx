import { CheckCircle2, Circle, ShieldCheck } from 'lucide-react';
import type { ApprovalEntry } from '@/types';

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

export function RequestTimeline({ approvals }: { approvals: ApprovalEntry[] }) {
  if (approvals.length === 0) {
    return <p className="rounded-lg border border-zinc-800 bg-zinc-900 p-4 text-sm text-zinc-500">No approval events yet.</p>;
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900">
      <div className="border-b border-zinc-800 px-4 py-3"><h2 className="font-semibold">Approval Timeline</h2></div>
      <div className="divide-y divide-zinc-800">
        {approvals.map((a) => (
          <div key={a.id} className="grid gap-3 p-4 sm:grid-cols-[auto_1fr_auto] sm:items-start">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-zinc-700 text-zinc-300">
              {a.action === 'APPROVED' ? <CheckCircle2 className="h-4 w-4 text-emerald-300" /> : <Circle className="h-4 w-4 text-red-300" />}
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium">{a.action}</p>
              <p className="mt-1 text-xs text-zinc-500">Approver {a.approver_id.slice(0, 8)}…</p>
              <code className="mt-2 block truncate text-xs text-zinc-600">nonce: {a.step_nonce}</code>
            </div>
            <p className="text-xs text-zinc-500">{formatDate(a.acted_at)}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
