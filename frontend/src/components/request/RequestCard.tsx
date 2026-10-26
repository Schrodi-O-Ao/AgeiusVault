import Link from 'next/link';
import { Clock, FileCheck2, ShieldCheck } from 'lucide-react';
import type { AegisVaultRequest } from '@/types';

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

function statusClass(status: string) {
  if (status === 'APPROVED') return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200';
  if (status === 'REJECTED') return 'border-red-500/30 bg-red-500/10 text-red-200';
  if (status === 'CANCELLED') return 'border-zinc-600/30 bg-zinc-600/10 text-zinc-300';
  return 'border-sky-500/30 bg-sky-500/10 text-sky-200';
}

export function RequestCard({ request }: { request: AegisVaultRequest }) {
  return (
    <Link href={`/requests/${request.id}`} className="block rounded-lg border border-zinc-800 bg-zinc-900 p-4 transition hover:border-zinc-600 hover:bg-zinc-900/80">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className={`rounded-md border px-2 py-1 text-xs font-medium ${statusClass(request.status)}`}>
              {request.status}
            </span>
            {request.is_anonymous && (
              <span className="inline-flex items-center gap-1 rounded-md border border-violet-500/30 bg-violet-500/10 px-2 py-1 text-xs text-violet-200">
                <ShieldCheck className="h-3 w-3" />Anonymous
              </span>
            )}
          </div>
          <h3 className="truncate text-base font-semibold text-zinc-100">{request.type.replace(/_/g, ' ')}</h3>
        </div>
        <FileCheck2 className="h-5 w-5 shrink-0 text-zinc-500" />
      </div>
      <div className="mt-4 flex items-center gap-2 text-xs text-zinc-500">
        <Clock className="h-3.5 w-3.5" />
        Submitted {formatDate(request.submitted_at)}
      </div>
    </Link>
  );
}
