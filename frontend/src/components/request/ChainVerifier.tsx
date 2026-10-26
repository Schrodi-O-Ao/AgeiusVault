"use client";

import { useState } from 'react';
import { CheckCircle2, ShieldAlert, TriangleAlert } from 'lucide-react';
import { api } from '@/lib/api';
import type { AuditVerification } from '@/types';

export function ChainVerifier({ requestId }: { requestId: string }) {
  const [result, setResult] = useState<AuditVerification | null>(null);
  const [error, setError] = useState('');

  const verify = async () => {
    setError('');
    try {
      const res = await api.post(`/requests/${requestId}/verify`);
      setResult(res.data);
    } catch {
      setError('Chain verification failed.');
    }
  };

  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="flex items-center justify-between gap-3">
        <div><h2 className="font-semibold">Chain Integrity</h2><p className="mt-1 text-sm text-zinc-500">Verify the tamper-evident audit chain.</p></div>
        <button onClick={verify} className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-zinc-700 px-3 text-sm font-semibold text-zinc-100 transition hover:bg-zinc-800">
          <ShieldAlert className="h-4 w-4" />Verify
        </button>
      </div>
      {error && <p className="mt-3 text-sm text-red-300">{error}</p>}
      {result && (
        <div className={`mt-4 flex items-start gap-3 rounded-lg border px-3 py-2 text-sm ${result.is_valid ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-100' : 'border-red-500/30 bg-red-500/10 text-red-100'}`}>
          {result.is_valid ? <CheckCircle2 className="mt-0.5 h-4 w-4" /> : <TriangleAlert className="mt-0.5 h-4 w-4" />}
          <span>{result.is_valid ? `Chain verified (${result.entries_checked} entries).` : `${result.violations.length} violation(s) detected.`}</span>
        </div>
      )}
    </div>
  );
}
