"use client";

import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import { AlertTriangle, FileText, ShieldCheck } from 'lucide-react';
import { api } from '@/lib/api';
import { ApprovalPanel } from '@/components/request/ApprovalPanel';
import { ChainVerifier } from '@/components/request/ChainVerifier';
import { RequestTimeline } from '@/components/request/RequestTimeline';
import type { AegisVaultRequest } from '@/types';

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value));
}

function fieldLabel(key: string) {
  return key.replaceAll('_', ' ');
}

export default function RequestDetailPage() {
  const params = useParams<{ id: string }>();
  const [request, setRequest] = useState<AegisVaultRequest | null>(null);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(true);

  const loadRequest = useCallback(async () => {
    if (!params.id) return;
    setIsLoading(true);
    setError('');
    try {
      const res = await api.get(`/requests/${params.id}`);
      setRequest(res.data);
    } catch (err) {
      const detail = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      setError(detail || 'Request is unavailable.');
    } finally {
      setIsLoading(false);
    }
  }, [params.id]);

  useEffect(() => { queueMicrotask(() => { void loadRequest(); }); }, [loadRequest]);

  if (isLoading) return <p className="rounded-lg border border-zinc-800 bg-zinc-900 p-5 text-sm text-zinc-500">Loading request.</p>;
  if (error) return <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>;
  if (!request) return null;

  return (
    <div className="space-y-5">
      <header>
        <div className="mb-2 flex flex-wrap gap-2">
          <span className={`rounded-md border px-2 py-1 text-xs font-medium ${request.status === 'APPROVED' ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' : request.status === 'REJECTED' ? 'border-red-500/30 bg-red-500/10 text-red-200' : 'border-sky-500/30 bg-sky-500/10 text-sky-200'}`}>
            {request.status}
          </span>
          <span className="rounded-md border border-zinc-700 px-2 py-1 text-xs text-zinc-400">{request.type.replace(/_/g, ' ')}</span>
          {request.is_anonymous && <span className="rounded-md border border-violet-500/30 bg-violet-500/10 px-2 py-1 text-xs text-violet-200">Anonymous</span>}
        </div>
        <h1 className="text-3xl font-semibold">{request.type.replace(/_/g, ' ')}</h1>
      </header>

      <section className="grid gap-4 xl:grid-cols-[1fr_360px]">
        <div className="space-y-4">
          {request.payload && (
            <div className="rounded-lg border border-zinc-800 bg-zinc-900">
              <div className="flex items-center gap-2 border-b border-zinc-800 px-4 py-3">
                <FileText className="h-5 w-5 text-zinc-500" /><h2 className="font-semibold">Decrypted Request Content</h2>
              </div>
              <dl className="grid gap-3 p-4 sm:grid-cols-2">
                {Object.entries(request.payload).map(([key, value]) => (
                  <div key={key} className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                    <dt className="text-xs font-medium uppercase text-zinc-500">{fieldLabel(key)}</dt>
                    <dd className="mt-2 break-words text-sm text-zinc-100">{String(value)}</dd>
                  </div>
                ))}
              </dl>
            </div>
          )}
          <RequestTimeline approvals={request.approvals ?? []} />
        </div>

        <aside className="space-y-4">
          <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
            <h2 className="font-semibold">Request Info</h2>
            <div className="mt-4 space-y-3 text-sm">
              <div className="flex items-center justify-between gap-3">
                <span className="text-zinc-400">Submitted</span>
                <span className="text-zinc-200">{formatDate(request.submitted_at)}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-zinc-400">Updated</span>
                <span className="text-zinc-200">{formatDate(request.updated_at)}</span>
              </div>
              {request.nonce && (
                <div className="flex items-center justify-between gap-3">
                  <span className="inline-flex items-center gap-2 text-zinc-400"><ShieldCheck className="h-4 w-4" />Nonce</span>
                  <code className="max-w-[170px] truncate text-xs text-zinc-500">{request.nonce}</code>
                </div>
              )}
            </div>
          </div>

          {request.is_anonymous && (
            <div className="rounded-lg border border-violet-500/30 bg-violet-500/10 p-4 text-sm text-violet-100">
              <div className="flex gap-2"><AlertTriangle className="mt-0.5 h-4 w-4" />Reporter identity is protected.</div>
            </div>
          )}

          <ApprovalPanel request={request} onUpdated={loadRequest} />
          <ChainVerifier requestId={request.id} />
        </aside>
      </section>
    </div>
  );
}
