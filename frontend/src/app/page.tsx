import Link from 'next/link';
import { ArrowRight, CalendarDays, FileText, LogIn, Shield, ShieldCheck } from 'lucide-react';

export default function Landing() {
  return (
    <main className="min-h-screen bg-zinc-950 px-4 py-10 text-zinc-100">
      <div className="mx-auto grid min-h-[calc(100vh-5rem)] w-full max-w-6xl items-center gap-10 lg:grid-cols-[1fr_420px]">
        <section>
          <div className="mb-6 flex h-12 w-12 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <h1 className="text-5xl font-semibold sm:text-6xl">
            AegisVault
          </h1>
          <p className="mt-3 text-lg font-medium text-emerald-300">
            Internal Civil Service HR & Leave System
          </p>
          <p className="mt-4 max-w-2xl text-base leading-7 text-zinc-400">
            Submit leave requests, expense claims, and IT access permissions with optional browser-side payload encryption for the selected approver, step-up verification, delegation, and linked audit records.
          </p>
          <div className="mt-8 flex flex-col gap-3 sm:flex-row">
            <Link href="/login" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg bg-emerald-400 px-5 font-semibold text-zinc-950 transition hover:bg-emerald-300">
              <LogIn className="h-4 w-4" />
              Sign In
            </Link>
            <Link href="/register" className="inline-flex h-11 items-center justify-center gap-2 rounded-lg border border-zinc-700 px-5 font-semibold text-zinc-100 transition hover:border-zinc-500 hover:bg-zinc-900">
              Create Account
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </section>

        <section className="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
          <div className="border-b border-zinc-800 pb-4">
            <p className="text-sm font-medium text-zinc-400">System Status</p>
            <p className="mt-1 text-2xl font-semibold">Secured</p>
          </div>
          <div className="grid grid-cols-2 gap-3 py-5">
            {[
              ['Annual Leave', 'Submit & track', CalendarDays],
              ['Expense Claims', 'Encrypted payloads', FileText],
              ['IT Access', 'RSA-signed approvals', Shield],
              ['Audit Trail', 'SHA-256 chain', ShieldCheck],
            ].map(([label, value, Icon]) => (
              <div key={label as string} className="rounded-lg border border-zinc-800 bg-zinc-950 p-3">
                <p className="flex items-center gap-2 text-sm font-semibold"><Icon className="h-4 w-4 text-emerald-300" />{label as string}</p>
                <p className="mt-1 text-xs text-zinc-500">{value as string}</p>
              </div>
            ))}
          </div>
          <Link href="/login" className="inline-flex w-full items-center justify-center gap-2 rounded-lg border border-emerald-400/30 bg-emerald-400/10 px-4 py-2.5 text-sm font-semibold text-emerald-200 transition hover:bg-emerald-400/15">
            Open Dashboard
            <ArrowRight className="h-4 w-4" />
          </Link>
        </section>
      </div>
    </main>
  );
}
