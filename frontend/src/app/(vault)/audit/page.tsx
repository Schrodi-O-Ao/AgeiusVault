"use client";
import { useEffect, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { api } from '@/lib/api';
import type { AuditChainEntry } from '@/types';

function fmt(v: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(v)); }
function sh(h: string) { return h.slice(0,10)+'…'+h.slice(-8); }

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditChainEntry[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const load = async () => {
    setLoading(true); setError('');
    try { const r = await api.get('/audit/logs'); setLogs(r.data.data); }
    catch { setError('Audit logs unavailable.'); }
    finally { setLoading(false); }
  };

  useEffect(() => {
    let active = true;
    api.get('/audit/logs')
      .then((response) => { if (active) setLogs(response.data.data); })
      .catch(() => { if (active) setError('Audit logs unavailable.'); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  return (
    <div className="space-y-5">
      <header className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div><p className="text-sm font-medium text-emerald-300">Tamper-evident records</p><h1 className="mt-1 text-3xl font-semibold">Audit Log</h1></div>
        <button onClick={load} className="inline-flex h-10 items-center justify-center gap-2 rounded-lg border border-zinc-700 px-4 text-sm font-semibold text-zinc-100 transition hover:bg-zinc-900"><RefreshCw className="h-4 w-4"/>Refresh</button>
      </header>
      {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
      <section className="rounded-lg border border-zinc-800 bg-zinc-900">
        <div className="grid grid-cols-[1fr_160px_180px] gap-4 border-b border-zinc-800 px-4 py-3 text-xs font-medium uppercase text-zinc-500 max-md:hidden"><span>Action</span><span>Chain Hash</span><span>Time</span></div>
        {loading ? <p className="p-5 text-sm text-zinc-500">Loading…</p> : logs.length===0 ? <p className="p-10 text-center text-sm text-zinc-500">No audit records.</p> : (
          <div className="divide-y divide-zinc-800">{logs.map(l=>(
            <div key={l.id} className="grid gap-2 p-4 md:grid-cols-[1fr_160px_180px] md:items-center">
              <div><p className="text-sm font-medium">{l.action}</p><p className="mt-1 text-xs text-zinc-500">Request {l.request_id.slice(0,8)}…</p></div>
              <code className="text-xs text-zinc-400">{sh(l.chain_hash)}</code>
              <p className="text-xs text-zinc-500">{fmt(l.recorded_at)}</p>
            </div>
          ))}</div>
        )}
      </section>
    </div>
  );
}
