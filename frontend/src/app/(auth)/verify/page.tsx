"use client";
import { useState, Suspense } from 'react';
import { useForm } from 'react-hook-form';
import { useSearchParams, useRouter } from 'next/navigation';
import { api, extractErrorMessage } from '@/lib/api';
import { deriveVaultKeyHex } from '@/lib/crypto';
import { useAuthStore } from '@/store/authStore';
import { ShieldCheck } from 'lucide-react';

type VerifyFormValues = { code: string };

function VerifyForm() {
  const searchParams = useSearchParams();
  const token = searchParams.get('token');
  const router = useRouter();
  const setAuth = useAuthStore(s => s.setAuth);
  const consumePendingMasterPassword = useAuthStore(s => s.consumePendingMasterPassword);
  const { register, handleSubmit } = useForm<VerifyFormValues>();
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const onSubmit = async (data: VerifyFormValues) => {
    setIsLoading(true);
    setError('');
    try {
      const res = await api.post('/auth/verify-totp', { partial_token: token, totp_code: data.code });
      const password = consumePendingMasterPassword();
      if (!password) { setError('Master password expired from memory. Sign in again.'); return; }
      const vaultKey = await deriveVaultKeyHex(password, res.data.user.key_salt);
      setAuth(res.data.user, res.data.access_token, vaultKey, res.data.refresh_token);
      router.push('/dashboard');
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
      {error && <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
      <div>
        <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="code">Authenticator Code</label>
        <input id="code" {...register('code')} inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-center text-xl text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
      </div>
      <button disabled={isLoading} className="flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 py-2.5 font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50">
        <ShieldCheck className="h-4 w-4" />{isLoading ? "Verifying…" : "Verify"}
      </button>
    </form>
  );
}

export default function Verify() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-4 text-zinc-100">
      <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6 shadow-xl shadow-black/20">
        <h2 className="mb-2 text-2xl font-semibold">Two-Factor Auth</h2>
        <p className="mb-6 text-sm text-zinc-400">Enter the 6-digit code from your authenticator app.</p>
        <Suspense fallback={<div className="text-center text-zinc-400">Loading...</div>}><VerifyForm /></Suspense>
      </div>
    </div>
  );
}
