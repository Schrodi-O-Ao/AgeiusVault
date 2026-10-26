"use client";
import { useEffect, useState } from 'react';
import { useAuthStore } from '@/store/authStore';
import { useRouter, usePathname } from 'next/navigation';
import Link from 'next/link';
import { FilePlus2, GitBranch, Inbox, LayoutDashboard, LogOut, Menu, Send, Settings, ShieldAlert, ShieldCheck } from 'lucide-react';

export default function VaultLayout({ children }: { children: React.ReactNode }) {
  const { user, vaultKey, clearAuth } = useAuthStore();
  const router = useRouter();
  const pathname = usePathname();
  const [isMenuOpen, setIsMenuOpen] = useState(false);

  useEffect(() => { if (!user || !vaultKey) router.replace('/login'); }, [user, vaultKey, router]);
  if (!user || !vaultKey) return null;

  const handleLogout = () => { clearAuth(); router.push('/'); };

  const nav = [
    { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
    { name: 'Inbox', href: '/inbox', icon: Inbox },
    { name: 'My Requests', href: '/outbox', icon: Send },
    { name: 'Submit Request', href: '/requests/new', icon: FilePlus2 },
    { name: 'Delegations', href: '/delegations', icon: GitBranch },
    { name: 'Audit Log', href: '/audit', icon: ShieldAlert },
    { name: 'Settings', href: '/settings', icon: Settings },
  ];

  const sidebar = (
    <aside className="flex h-full w-72 flex-col border-r border-zinc-800 bg-zinc-950">
      <div className="flex h-16 items-center gap-3 border-b border-zinc-800 px-5">
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950">
          <img src="/aegisvault-logo.svg" alt="AegisVault" className="h-5 w-5" />
        </div>
        <span className="text-lg font-semibold">AegisVault</span>
      </div>
      <nav className="flex-1 space-y-1 px-3 py-4">
        {nav.map((item) => {
          const isActive = pathname === item.href || (item.href !== '/dashboard' && pathname.startsWith(item.href));
          return (
            <Link key={item.name} href={item.href} onClick={() => setIsMenuOpen(false)}
              className={`flex h-10 items-center gap-3 rounded-lg px-3 text-sm font-medium transition ${isActive ? 'border border-emerald-400/30 bg-emerald-400/10 text-emerald-200' : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-100'}`}>
              <item.icon className="h-4 w-4" /><span>{item.name}</span>
            </Link>
          );
        })}
      </nav>
      <div className="border-t border-zinc-800 p-3">
        <div className="flex items-center gap-3 rounded-lg border border-zinc-800 bg-zinc-900 p-3">
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-zinc-800 font-semibold text-emerald-200">
            {(user.full_name || 'U').charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <p className="truncate text-sm font-medium">{user.full_name}</p>
            <p className="text-xs text-zinc-500">{user.role || 'STAFF'}</p>
          </div>
          <button onClick={handleLogout} className="flex h-9 w-9 items-center justify-center rounded-lg text-zinc-400 transition hover:bg-zinc-800 hover:text-red-300" aria-label="Sign out" title="Sign out">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
      </div>
    </aside>
  );

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <div className="fixed inset-y-0 left-0 z-30 hidden lg:block">{sidebar}</div>
      {isMenuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <button className="absolute inset-0 bg-black/70" aria-label="Close navigation" onClick={() => setIsMenuOpen(false)} />
          <div className="relative h-full">{sidebar}</div>
        </div>
      )}
      <header className="sticky top-0 z-20 flex h-16 items-center justify-between border-b border-zinc-800 bg-zinc-950/95 px-4 lg:hidden">
        <button onClick={() => setIsMenuOpen(true)} className="flex h-10 w-10 items-center justify-center rounded-lg border border-zinc-800 text-zinc-300" aria-label="Open navigation"><Menu className="h-5 w-5" /></button>
        <div className="flex items-center gap-2 font-semibold">
          <img src="/aegisvault-logo.svg" alt="AegisVault" className="h-5 w-5 text-emerald-300" />
          AegisVault
        </div>
        <button onClick={handleLogout} className="flex h-10 w-10 items-center justify-center rounded-lg border border-zinc-800 text-zinc-300" aria-label="Sign out"><LogOut className="h-5 w-5" /></button>
      </header>
      <main className="min-h-screen px-4 py-6 sm:px-6 lg:ml-72 lg:px-8 lg:py-8">
        <div className="mx-auto w-full max-w-7xl">{children}</div>
      </main>
    </div>
  );
}
