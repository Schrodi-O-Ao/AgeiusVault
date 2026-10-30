"use client";

import { FormEvent, useState } from 'react';
import { KeyRound, Send } from 'lucide-react';
import { api } from '@/lib/api';
import type { RequestTypeInfo, TeamMember } from '@/types';

export function DelegationForm({ team, onCreated }: { team: TeamMember[]; requestTypes?: RequestTypeInfo[]; onCreated: () => void }) {
  const [delegateeId, setDelegateeId] = useState(team[0]?.id ?? '');
  const [validFrom, setValidFrom] = useState(() => new Date().toISOString().slice(0, 10));
  const [validUntil, setValidUntil] = useState(() => new Date(Date.now() + 7 * 86400000).toISOString().slice(0, 10));
  const [totpCode, setTotpCode] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      const step = await api.post('/auth/step-up', {
        request_id: 'delegation',
        action_type: 'delegation',
        totp_code: totpCode,
      });
      await api.post(
        '/delegations',
        { delegatee_id: delegateeId, valid_from: validFrom, valid_until: validUntil },
        { headers: { 'X-Step-Up-Token': step.data.step_up_token } },
      );
      setTotpCode('');
      onCreated();
    } catch (err) {
      const detail = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      setError(detail || 'Delegation could not be created.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="mb-4 flex items-center gap-2"><KeyRound className="h-5 w-5 text-emerald-300" /><h2 className="font-semibold">Create Delegation</h2></div>
      {error && <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
      <div className="grid gap-3">
        <label>
          <span className="mb-2 block text-sm font-medium text-zinc-300">Delegatee</span>
          <select value={delegateeId} onChange={(e) => setDelegateeId(e.target.value)} required className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none focus:border-emerald-400">
            {team.map((m) => <option key={m.id} value={m.id}>{m.full_name} ({m.role})</option>)}
          </select>
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <label>
            <span className="mb-2 block text-sm font-medium text-zinc-300">Valid From</span>
            <input type="date" value={validFrom} onChange={(e) => setValidFrom(e.target.value)} className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none focus:border-emerald-400" />
          </label>
          <label>
            <span className="mb-2 block text-sm font-medium text-zinc-300">Valid Until</span>
            <input type="date" value={validUntil} onChange={(e) => setValidUntil(e.target.value)} className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none focus:border-emerald-400" />
          </label>
        </div>
        <label>
          <span className="mb-2 block text-sm font-medium text-zinc-300">Authenticator Code</span>
          <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} inputMode="numeric" maxLength={6} required className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-center text-lg outline-none focus:border-emerald-400" />
        </label>
        <button disabled={isLoading || team.length === 0} className="inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50">
          <Send className="h-4 w-4" />{isLoading ? 'Creating…' : 'Create Delegation'}
        </button>
      </div>
    </form>
  );
}
