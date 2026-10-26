"use client";

import { useCallback, useEffect, useState } from 'react';
import { GitBranch, Trash2 } from 'lucide-react';
import { api } from '@/lib/api';
import { DelegationForm } from '@/components/request/DelegationForm';
import { useWorkflowStore } from '@/store/workflowStore';
import type { Delegation, TeamMember } from '@/types';

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' }).format(new Date(value));
}

export default function DelegationsPage() {
  const { requestTypes, fetchTypes } = useWorkflowStore();
  const [team, setTeam] = useState<TeamMember[]>([]);
  const [given, setGiven] = useState<Delegation[]>([]);
  const [received, setReceived] = useState<Delegation[]>([]);
  const [error, setError] = useState('');

  const load = useCallback(async () => {
    setError('');
    try {
      const [delegationsRes, teamRes] = await Promise.all([
        api.get('/delegations'),
        api.get('/users/team'),
        fetchTypes(),
      ]);
      setGiven(delegationsRes.data.data.given);
      setReceived(delegationsRes.data.data.received);
      setTeam(teamRes.data.data);
    } catch {
      setError('Delegation data is unavailable.');
    }
  }, [fetchTypes]);

  useEffect(() => { queueMicrotask(() => { void load(); }); }, [load]);

  const revoke = async (id: string) => {
    await api.post(`/delegations/${id}/revoke`);
    await load();
  };

  const renderList = (items: Delegation[], empty: string, canRevoke: boolean) => (
    <div className="divide-y divide-zinc-800">
      {items.length === 0 ? (
        <p className="p-5 text-sm text-zinc-500">{empty}</p>
      ) : (
        items.map((item) => (
          <div key={item.id} className="grid gap-3 p-4 md:grid-cols-[1fr_auto] md:items-center">
            <div>
              <div className="flex flex-wrap gap-2">
                <span className={`rounded-md border px-2 py-1 text-xs ${item.is_active ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200' : 'border-zinc-700 text-zinc-400'}`}>
                  {item.is_active ? 'active' : 'inactive'}
                </span>
              </div>
              <p className="mt-2 text-sm font-medium">{item.delegator_name || item.delegator_id.slice(0,8)} {'→'} {item.delegatee_name || item.delegatee_id.slice(0,8)}</p>
              <p className="mt-1 text-xs text-zinc-500">{formatDate(item.valid_from)} to {formatDate(item.valid_until)}</p>
            </div>
            {canRevoke && item.is_active && (
              <button onClick={() => revoke(item.id)} className="inline-flex h-9 items-center justify-center gap-2 rounded-lg border border-red-500/30 px-3 text-sm text-red-200 transition hover:bg-red-500/10">
                <Trash2 className="h-4 w-4" />Revoke
              </button>
            )}
          </div>
        ))
      )}
    </div>
  );

  return (
    <div className="space-y-5">
      <header>
        <p className="text-sm font-medium text-emerald-300">Signed approval authority</p>
        <h1 className="mt-1 text-3xl font-semibold">Delegations</h1>
      </header>
      {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
      <section className="grid gap-4 xl:grid-cols-[380px_1fr]">
        <DelegationForm team={team} requestTypes={requestTypes} onCreated={load} />
        <div className="rounded-lg border border-zinc-800 bg-zinc-900">
          <div className="flex items-center gap-2 border-b border-zinc-800 px-5 py-4"><GitBranch className="h-5 w-5 text-zinc-500" /><h2 className="font-semibold">Delegations Given</h2></div>
          {renderList(given, 'No delegations given.', true)}
        </div>
      </section>
      <section className="rounded-lg border border-zinc-800 bg-zinc-900">
        <div className="border-b border-zinc-800 px-5 py-4"><h2 className="font-semibold">Delegations Received</h2></div>
        {renderList(received, 'No delegations received.', false)}
      </section>
    </div>
  );
}
