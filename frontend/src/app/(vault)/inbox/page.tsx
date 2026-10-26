"use client";

import { useEffect } from 'react';
import { Inbox } from 'lucide-react';
import { RequestCard } from '@/components/request/RequestCard';
import { useWorkflowStore } from '@/store/workflowStore';

export default function InboxPage() {
  const { inbox, isLoading, fetchList } = useWorkflowStore();

  useEffect(() => {
    fetchList('inbox');
  }, [fetchList]);

  return (
    <div className="space-y-5">
      <header>
        <p className="text-sm font-medium text-emerald-300">Requests awaiting your signed decision</p>
        <h1 className="mt-1 text-3xl font-semibold">Pending My Approval</h1>
      </header>
      {isLoading ? (
        <p className="rounded-lg border border-zinc-800 bg-zinc-900 p-5 text-sm text-zinc-500">Loading approvals.</p>
      ) : inbox.length === 0 ? (
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-10 text-center">
          <Inbox className="mx-auto h-8 w-8 text-zinc-600" />
          <p className="mt-3 text-sm text-zinc-500">No pending approvals.</p>
        </div>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          {inbox.map((request) => <RequestCard key={request.id} request={request} />)}
        </div>
      )}
    </div>
  );
}
