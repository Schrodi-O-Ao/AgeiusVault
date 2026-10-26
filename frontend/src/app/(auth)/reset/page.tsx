"use client";

import { FormEvent, useState } from 'react';
import Link from 'next/link';
import { ArrowLeft, MailCheck, Send } from 'lucide-react';
import { api } from '@/lib/api';

export default function ResetPage() {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const requestReset = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setIsLoading(true);
    setMessage('');
    setError('');
    try {
      const res = await api.post('/auth/forgot-password', { email });
      setMessage(res.data.message ?? 'If the email exists, a reset code has been sent.');
    } catch {
      setError('Reset request failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-4 text-zinc-100">
      <section className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6 shadow-xl shadow-black/20">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950"><MailCheck className="h-5 w-5" /></div>
          <div><h1 className="text-2xl font-semibold">Reset Password</h1><p className="text-sm text-zinc-400">Request an email reset token</p></div>
        </div>
        {message && <div className="mb-5 rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-3 py-2 text-sm text-emerald-100">{message}</div>}
        {error && <div className="mb-5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
        <form onSubmit={requestReset} className="space-y-4">
          <label className="block">
            <span className="mb-2 block text-sm font-medium text-zinc-300">Email</span>
            <input value={email} onChange={(e) => setEmail(e.target.value)} type="email" autoComplete="email" required className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
          </label>
          <button disabled={isLoading} className="inline-flex h-10 w-full items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50">
            <Send className="h-4 w-4" />{isLoading ? 'Sending…' : 'Send Reset Token'}
          </button>
        </form>
        <Link href="/login" className="mt-5 inline-flex items-center gap-2 text-sm text-zinc-400 transition hover:text-zinc-100"><ArrowLeft className="h-4 w-4" />Back to sign in</Link>
      </section>
    </div>
  );
}
