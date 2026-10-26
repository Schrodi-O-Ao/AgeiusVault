"use client";
import { useState, Suspense } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import { api, extractErrorMessage } from '@/lib/api';
import { useRouter, useSearchParams } from 'next/navigation';
import { ShieldCheck, RefreshCw } from 'lucide-react';
import Link from 'next/link';

const emailVerifySchema = z.object({
  email: z.string().email("Enter a valid email"),
  code: z.string().length(6, "Code must be 6 digits")
});

type EmailVerifyForm = z.infer<typeof emailVerifySchema>;

function EmailVerifyForm() {
  const searchParams = useSearchParams();
  const prefilledEmail = searchParams.get('email') || '';
  const { register, handleSubmit, formState: { errors }, getValues } = useForm<EmailVerifyForm>({
    resolver: zodResolver(emailVerifySchema),
    defaultValues: { email: prefilledEmail, code: '' },
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendMessage, setResendMessage] = useState('');
  const router = useRouter();

  const onSubmit = async (data: EmailVerifyForm) => {
    setIsLoading(true);
    setError('');
    setResendMessage('');
    try {
      await api.post('/auth/email-verify', data);
      setSuccess(true);
      setTimeout(() => router.push('/login'), 2000);
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleResend = async () => {
    const email = getValues('email');
    if (!email) {
      setError('Please enter your email address first.');
      return;
    }
    setResendLoading(true);
    setError('');
    setResendMessage('');
    try {
      const res = await api.post('/auth/resend-otp', { email });
      setResendMessage(res.data.message || 'A new code has been sent. Check the backend terminal.');
    } catch (err) {
      setError(extractErrorMessage(err));
    } finally {
      setResendLoading(false);
    }
  };

  if (success) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-4 text-zinc-100">
        <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6 text-center shadow-xl shadow-black/20">
          <div className="mx-auto mb-5 flex h-12 w-12 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950"><ShieldCheck className="h-6 w-6" /></div>
          <h2 className="text-2xl font-semibold">Email Verified</h2>
          <p className="mt-2 text-sm text-zinc-400">Redirecting to login...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-4 text-zinc-100">
      <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6 shadow-xl shadow-black/20">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950"><ShieldCheck className="h-5 w-5" /></div>
          <div>
            <h2 className="text-2xl font-semibold">Verify Email</h2>
            <p className="text-sm text-zinc-400">Enter the 6-digit code sent to your email</p>
          </div>
        </div>
        {error && <div className="mb-5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
        {resendMessage && <div className="mb-5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200">{resendMessage}</div>}
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="email">Email Address</label>
            <input id="email" {...register('email')} type="email" autoComplete="email" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
            {errors.email && <p className="mt-1 text-xs text-red-300">{errors.email.message}</p>}
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="code">Verification Code</label>
            <input id="code" {...register('code')} inputMode="numeric" autoComplete="one-time-code" maxLength={6} className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-center text-xl text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
            {errors.code && <p className="mt-1 text-xs text-red-300">{errors.code.message}</p>}
          </div>
          <div className="flex gap-2">
            <button disabled={isLoading} type="submit" className="flex flex-1 items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 py-2.5 font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50">
              <ShieldCheck className="h-4 w-4" />
              {isLoading ? "Verifying…" : "Verify Email"}
            </button>
            <button
              type="button"
              disabled={resendLoading}
              onClick={handleResend}
              className="flex items-center justify-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2.5 text-sm font-medium text-zinc-300 transition hover:bg-zinc-700 hover:text-white disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${resendLoading ? 'animate-spin' : ''}`} />
              Resend
            </button>
          </div>
        </form>
        <p className="mt-5 text-center text-sm text-zinc-400">
          Already verified? <Link href="/login" className="font-medium text-emerald-300 hover:text-emerald-200">Sign in</Link>
        </p>
      </div>
    </div>
  );
}

export default function EmailVerify() {
  return (
    <Suspense fallback={<div className="flex min-h-screen items-center justify-center bg-zinc-950 text-zinc-400">Loading...</div>}>
      <EmailVerifyForm />
    </Suspense>
  );
}
