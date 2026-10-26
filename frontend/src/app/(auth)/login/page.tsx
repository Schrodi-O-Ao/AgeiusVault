"use client";
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { loginSchema } from '@/lib/validators';
import { api, extractErrorMessage } from '@/lib/api';
import { deriveVaultKeyHex } from '@/lib/crypto';
import { useAuthStore } from '@/store/authStore';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { LockKeyhole, LogIn, ShieldCheck, Eye, EyeOff } from 'lucide-react';
import { z } from 'zod';

type LoginForm = z.infer<typeof loginSchema>;

export default function Login() {
  const { register, handleSubmit, formState: { errors }, getValues } = useForm<LoginForm>({ resolver: zodResolver(loginSchema) });
  const [error, setError] = useState('');
  const [needsVerification, setNeedsVerification] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const router = useRouter();
  const setAuth = useAuthStore(s => s.setAuth);
  const setPendingMasterPassword = useAuthStore(s => s.setPendingMasterPassword);

  const onSubmit = async (data: LoginForm) => {
    setIsLoading(true);
    setError('');
    setNeedsVerification(false);
    try {
      const res = await api.post('/auth/login', data);
      if (res.data.totp_required) {
        setPendingMasterPassword(data.password);
        router.push(`/verify?token=${res.data.partial_token}`);
      } else {
        const vaultKey = await deriveVaultKeyHex(data.password, res.data.user.key_salt);
        setAuth(res.data.user, res.data.access_token, vaultKey, res.data.refresh_token);
        router.push('/dashboard');
      }
    } catch (err) {
      const msg = extractErrorMessage(err);
      setError(msg);
      // Detect if the error is about email verification
      if (msg.toLowerCase().includes('verify your email')) {
        setNeedsVerification(true);
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 px-4 py-10 text-zinc-100">
      <div className="mx-auto grid min-h-[calc(100vh-5rem)] w-full max-w-5xl items-center gap-8 lg:grid-cols-[1fr_420px]">
        <section className="hidden lg:block">
          <div className="mb-6 flex h-12 w-12 items-center justify-center rounded-lg border border-emerald-400/30 bg-emerald-400/10">
            <img src="/aegisvault-logo.svg" alt="AegisVault" className="h-6 w-6" />
          </div>
          <h1 className="text-4xl font-semibold">AegisVault</h1>
          <p className="mt-2 text-lg font-medium text-emerald-300">Internal Civil Service HR &amp; Leave System</p>
          <p className="mt-4 max-w-xl text-base leading-7 text-zinc-400">
            Sign in to manage leave approvals, expense claims, and linked audit records.
          </p>
        </section>

        <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-6 shadow-xl shadow-black/20">
          <div className="mb-6 flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950">
              <img src="/aegisvault-logo.svg" alt="AegisVault" className="h-5 w-5" />
            </div>
            <div>
              <h2 className="text-2xl font-semibold">Sign In</h2>
              <p className="text-sm text-zinc-400">Access your AegisVault dashboard</p>
            </div>
          </div>

          {error && (
            <div className="mb-5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">
              <p>{error}</p>
              {needsVerification && (
                <Link
                  href={`/email-verify?email=${encodeURIComponent(getValues('email') || '')}`}
                  className="mt-2 inline-block font-medium text-emerald-300 underline hover:text-emerald-200"
                >
                  Go to email verification →
                </Link>
              )}
            </div>
          )}
        
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="email">Email Address</label>
            <input id="email" {...register('email')} type="email" autoComplete="email" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
            {errors.email && <p className="mt-1 text-xs text-red-300">{errors.email.message}</p>}
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="password">Master Password</label>
            <div className="relative">
              <input 
                id="password" 
                {...register('password')} 
                type={showPassword ? "text" : "password"} 
                autoComplete="current-password" 
                className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 pr-10 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" 
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-200"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
            {errors.password && <p className="mt-1 text-xs text-red-300">{errors.password.message}</p>}
          </div>
          
          <button disabled={isLoading} className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 py-2.5 font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50">
            <LogIn className="h-4 w-4" />
            {isLoading ? "Authenticating…" : "Sign In"}
          </button>
          </form>
          <div className="mt-5 flex items-center justify-between text-sm">
            <Link href="/reset" className="text-zinc-400 transition hover:text-zinc-100">Reset password</Link>
            <Link href="/register" className="font-medium text-emerald-300 transition hover:text-emerald-200">Create account</Link>
          </div>
        </section>
      </div>
    </div>
  );
}
