"use client";
import { FormEvent, useEffect, useState } from 'react';
import Image from 'next/image';
import { Clock, Laptop, QrCode, ShieldCheck, Trash2, UserRound } from 'lucide-react';
import { api } from '@/lib/api';
import { useAuthStore } from '@/store/authStore';
import type { SessionInfo } from '@/types';

function fmt(v?: string|null) { if(!v) return 'Unknown'; return new Intl.DateTimeFormat(undefined,{dateStyle:'medium',timeStyle:'short'}).format(new Date(v)); }

export default function SettingsPage() {
  const user = useAuthStore(s => s.user);
  const setAuth = useAuthStore(s => s.setAuth);
  const accessToken = useAuthStore(s => s.accessToken);
  const vaultKey = useAuthStore(s => s.vaultKey);
  const refreshToken = useAuthStore(s => s.refreshToken);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [totpEnabled, setTotpEnabled] = useState(user?.totp_enabled ?? false);
  const [setup, setSetup] = useState<{secret:string;qr_code_data_url:string}|null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const loadSettings = async () => {
    try {
      const [profileRes, sessionsRes] = await Promise.all([api.get('/users/me'), api.get('/users/me/sessions')]);
      setTotpEnabled(profileRes.data.totp_enabled);
      setSessions(sessionsRes.data.data);
    } catch { setError('Settings are unavailable.'); }
  };

  useEffect(() => { queueMicrotask(() => { void loadSettings(); }); }, []);

  const startTotpSetup = async () => {
    setError('');
    try { const res = await api.post('/auth/setup-totp'); setSetup(res.data); }
    catch { setError('TOTP setup failed.'); }
  };

  const enableTotp = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); setError('');
    try {
      await api.post('/auth/enable-totp', { totp_code: totpCode });
      setTotpEnabled(true); setSetup(null); setTotpCode('');
      setMessage('TOTP enabled successfully.');
      if (user && accessToken && vaultKey) setAuth({...user, totp_enabled: true}, accessToken, vaultKey, refreshToken || undefined);
    } catch { setError('TOTP could not be enabled.'); }
  };

  const revokeSession = async (id: string) => {
    await api.post(`/users/me/sessions/${id}/revoke`);
    await loadSettings();
  };

  return (
    <div className="space-y-5">
      <header><p className="text-sm font-medium text-emerald-300">Account security and workflow keys</p><h1 className="mt-1 text-3xl font-semibold">Settings</h1></header>
      {message && <div className="rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-sm text-emerald-100">{message}</div>}
      {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}

      <section className="grid gap-4 lg:grid-cols-[360px_1fr]">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
          <div className="mb-5 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-zinc-800 text-emerald-200"><UserRound className="h-5 w-5"/></div>
            <div><h2 className="font-semibold">{user?.full_name}</h2><p className="text-sm text-zinc-500">{user?.role} · {user?.department || 'No department'}</p></div>
          </div>
          <div className="space-y-3">
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3"><p className="text-xs font-medium uppercase text-zinc-500">Email</p><p className="mt-1 break-all text-sm text-zinc-300">{user?.email}</p></div>
            <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3"><p className="text-xs font-medium uppercase text-zinc-500">Step-Up TOTP</p><p className="mt-1 text-sm text-zinc-300">{totpEnabled ? 'Enabled' : 'Not enabled'}</p></div>
          </div>
        </div>

        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
          <div className="mb-4 flex items-center justify-between"><div><h2 className="font-semibold">Multi-Factor Authentication</h2><p className="mt-1 text-sm text-zinc-500">Required for approvals and delegations.</p></div><ShieldCheck className="h-5 w-5 text-emerald-300"/></div>
          {!totpEnabled && !setup && (<button onClick={startTotpSetup} className="inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300"><QrCode className="h-4 w-4"/>Set Up TOTP</button>)}
          {setup && (
            <form onSubmit={enableTotp} className="grid gap-4 md:grid-cols-[180px_1fr]">
              <Image src={setup.qr_code_data_url} alt="TOTP QR code" width={160} height={160} unoptimized className="rounded-lg bg-white p-2"/>
              <div className="space-y-3">
                <div className="rounded-lg border border-zinc-800 bg-zinc-950 p-3"><p className="text-xs font-medium uppercase text-zinc-500">Secret</p><code className="mt-1 block break-all text-sm text-zinc-300">{setup.secret}</code></div>
                <input value={totpCode} onChange={e=>setTotpCode(e.target.value)} inputMode="numeric" maxLength={6} placeholder="Authenticator code" className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-center text-lg outline-none focus:border-emerald-400"/>
                <button className="inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300"><ShieldCheck className="h-4 w-4"/>Enable TOTP</button>
              </div>
            </form>
          )}
        </div>
      </section>

      <section className="rounded-lg border border-zinc-800 bg-zinc-900">
        <div className="border-b border-zinc-800 px-5 py-4"><h2 className="font-semibold">Active Sessions</h2></div>
        {sessions.length === 0 ? <p className="p-5 text-sm text-zinc-500">No active sessions found.</p> : (
          <div className="divide-y divide-zinc-800">{sessions.map(s=>(
            <div key={s.id} className="grid gap-3 p-5 md:grid-cols-[1fr_auto] md:items-center">
              <div className="flex gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-zinc-700 text-zinc-300"><Laptop className="h-5 w-5"/></div>
                <div><p className="text-sm font-medium">{s.device_label||'Unknown device'}</p><p className="mt-1 text-xs text-zinc-500">Country {s.ip_country||'XX'}</p></div>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <div className="flex items-center gap-2 text-xs text-zinc-500"><Clock className="h-4 w-4"/>Last active {fmt(s.last_active_at)}</div>
                <button onClick={()=>revokeSession(s.id)} className="inline-flex h-9 items-center justify-center gap-2 rounded-lg border border-red-500/30 px-3 text-sm text-red-200 transition hover:bg-red-500/10"><Trash2 className="h-4 w-4"/>Revoke</button>
              </div>
            </div>
          ))}</div>
        )}
      </section>
    </div>
  );
}
