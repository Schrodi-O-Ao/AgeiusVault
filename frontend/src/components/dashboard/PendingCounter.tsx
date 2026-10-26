import type { LucideIcon } from 'lucide-react';

export function PendingCounter({ label, value, icon: Icon }: { label: string; value: number; icon: LucideIcon }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
      <div className="flex items-center justify-between">
        <p className="text-sm font-medium text-zinc-400">{label}</p>
        <Icon className="h-5 w-5 text-zinc-500" />
      </div>
      <p className="mt-4 text-3xl font-semibold">{value}</p>
    </div>
  );
}
