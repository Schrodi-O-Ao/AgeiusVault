"use client";
import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { registerSchema } from '@/lib/validators';
import { api, extractErrorMessage } from '@/lib/api';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { z } from 'zod';
import { CheckCircle2, ShieldPlus, UserPlus, Eye, EyeOff } from 'lucide-react';

type RegisterForm = z.infer<typeof registerSchema>;

export default function Register() {
  const { register, handleSubmit, formState: { errors }, watch, getValues } = useForm<RegisterForm>({ resolver: zodResolver(registerSchema) });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [showPw, setShowPw] = useState(false);
  const [showCpw, setShowCpw] = useState(false);
  const router = useRouter();
  const password = watch('password', '');
  const str = (p: string) => { let s=0; if(p.length>=12)s++; if(/[A-Z]/.test(p))s++; if(/[a-z]/.test(p))s++; if(/[0-9]/.test(p))s++; if(/[^A-Za-z0-9]/.test(p))s++; return s; };
  const strCol = (s:number) => s<=1?'bg-red-500':s<=2?'bg-orange-500':s<=3?'bg-yellow-500':s<=4?'bg-emerald-400':'bg-emerald-500';
  const strTxt = (s:number) => s<=1?'Weak':s<=2?'Fair':s<=3?'Good':s<=4?'Strong':'Very Strong';

  const onSubmit = async (data: RegisterForm) => {
    setIsLoading(true); setError('');
    try { await api.post('/auth/register', data); setSuccess(true); }
    catch (err) { setError(extractErrorMessage(err)); }
    finally { setIsLoading(false); }
  };

  if (success) {
    const registeredEmail = getValues('email');
    return (
      <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-4 text-zinc-100">
        <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6 text-center shadow-xl shadow-black/20">
          <div className="mx-auto mb-5 flex h-12 w-12 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950"><CheckCircle2 className="h-6 w-6" /></div>
          <h2 className="text-2xl font-semibold">Account Created</h2>
          <p className="mt-2 text-sm text-zinc-400">
            A 6-digit verification code has been sent to <span className="font-medium text-zinc-200">{registeredEmail}</span>.
          </p>
          <p className="mt-1 text-xs text-zinc-500">
            Check the backend terminal if SMTP is not configured.
          </p>
          <button
            onClick={() => router.push(`/email-verify?email=${encodeURIComponent(registeredEmail)}`)}
            className="mt-6 block w-full rounded-lg bg-emerald-400 px-4 py-2.5 font-semibold text-zinc-950 transition hover:bg-emerald-300"
          >
            Verify Email
          </button>
          <p className="mt-3 text-sm text-zinc-400">
            Already verified? <Link href="/login" className="font-medium text-emerald-300 hover:text-emerald-200">Sign in</Link>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-4 text-zinc-100">
      <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6 shadow-xl shadow-black/20">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950">
            <ShieldPlus className="h-5 w-5" />
          </div>
          <div><h2 className="text-2xl font-semibold">Create Account</h2><p className="text-sm text-zinc-400">Join AegisVault</p></div>
        </div>
        {error && <div className="mb-5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="full_name">Full Name</label>
            <input id="full_name" {...register('full_name')} autoComplete="name" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
            {errors.full_name && <p className="mt-1 text-xs text-red-300">{errors.full_name.message}</p>}
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="email">Email</label>
            <input id="email" {...register('email')} type="email" autoComplete="email" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
            {errors.email && <p className="mt-1 text-xs text-red-300">{errors.email.message}</p>}
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="password">Master Password</label>
            <div className="relative">
              <input id="password" {...register('password')} type={showPw?"text":"password"} autoComplete="new-password" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 pr-10 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
              <button type="button" onClick={()=>setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-200">{showPw?<EyeOff className="h-4 w-4"/>:<Eye className="h-4 w-4"/>}</button>
            </div>
            {errors.password && <p className="mt-1 text-xs text-red-300">{errors.password.message}</p>}
            {password && (
              <div className="mt-3 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="h-1.5 flex-1 rounded-full bg-zinc-800 mr-3">
                    <div
                      className={`h-full rounded-full transition-all ${strCol(str(password))}`}
                      style={{ width: `${(str(password) / 5) * 100}%` }}
                    />
                  </div>
                  <span className={`text-xs font-semibold px-2 py-0.5 rounded ${
                    str(password) <= 2 ? 'text-red-400 bg-red-500/10' :
                    str(password) <= 3 ? 'text-yellow-400 bg-yellow-500/10' :
                    'text-emerald-400 bg-emerald-500/10'
                  }`}>
                    {strTxt(str(password))}
                  </span>
                </div>
                
                <div className="rounded-lg border border-zinc-800 bg-zinc-950/50 p-3 space-y-1.5 text-xs text-zinc-400">
                  <p className="font-medium text-zinc-300 mb-1">Password Requirements:</p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1">
                    <div className="flex items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 rounded-full ${password.length >= 12 ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                      <span className={password.length >= 12 ? 'text-zinc-200' : 'text-zinc-500'}>Min 12 characters</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 rounded-full ${/[A-Z]/.test(password) ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                      <span className={/[A-Z]/.test(password) ? 'text-zinc-200' : 'text-zinc-500'}>At least 1 uppercase</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 rounded-full ${/[a-z]/.test(password) ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                      <span className={/[a-z]/.test(password) ? 'text-zinc-200' : 'text-zinc-500'}>At least 1 lowercase</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 rounded-full ${/[0-9]/.test(password) ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                      <span className={/[0-9]/.test(password) ? 'text-zinc-200' : 'text-zinc-500'}>At least 1 number</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <span className={`h-1.5 w-1.5 rounded-full ${/[^A-Za-z0-9]/.test(password) ? 'bg-emerald-400' : 'bg-zinc-600'}`} />
                      <span className={/[^A-Za-z0-9]/.test(password) ? 'text-zinc-200' : 'text-zinc-500'}>At least 1 symbol</span>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="confirmPassword">Confirm Password</label>
            <div className="relative">
              <input id="confirmPassword" {...register('confirmPassword')} type={showCpw?"text":"password"} autoComplete="new-password" className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 pr-10 text-white outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
              <button type="button" onClick={()=>setShowCpw(!showCpw)} className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-400 hover:text-zinc-200">{showCpw?<EyeOff className="h-4 w-4"/>:<Eye className="h-4 w-4"/>}</button>
            </div>
            {errors.confirmPassword && <p className="mt-1 text-xs text-red-300">{errors.confirmPassword.message}</p>}
          </div>
          <button disabled={isLoading} className="mt-2 flex w-full items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 py-2.5 font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50"><UserPlus className="h-4 w-4"/>{isLoading?"Creating…":"Create Account"}</button>
        </form>
        <p className="mt-5 text-center text-sm text-zinc-400">Already have an account? <Link href="/login" className="font-medium text-emerald-300 hover:text-emerald-200">Sign in</Link></p>
      </div>
    </div>
  );
}
