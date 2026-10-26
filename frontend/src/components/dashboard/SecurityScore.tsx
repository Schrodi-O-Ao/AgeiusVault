import { ShieldCheck } from 'lucide-react';

export function SecurityScore({ value }: { value: number }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-zinc-400">Security Score</p>
          <p className="mt-2 text-4xl font-semibold text-emerald-200">{value}</p>
        </div>
        <ShieldCheck className="h-9 w-9 text-emerald-300" />
      </div>
      <div className="mt-5 h-2 rounded-lg bg-zinc-800">
        <div className="h-2 rounded-lg bg-emerald-400" style={{ width: `${Math.max(0, Math.min(100, value))}%` }} />
      </div>
    </div>
  );
}
