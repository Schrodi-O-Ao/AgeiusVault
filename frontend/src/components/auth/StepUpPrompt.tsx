"use client";

import { useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { api } from '@/lib/api';

interface StepUpPromptProps {
  requestId: string;
  actionType: string;
  onSuccess: (token: string) => void;
  onCancel: () => void;
}

export default function StepUpPrompt({ requestId, actionType, onSuccess, onCancel }: StepUpPromptProps) {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    try {
      const res = await api.post('/auth/step-up', {
        request_id: requestId,
        action_type: actionType,
        totp_code: code,
      });
      onSuccess(res.data.step_up_token);
    } catch (err) {
      const detail = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      setError(detail || 'Step-up verification failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
      <div className="w-full max-w-md rounded-lg border border-zinc-800 bg-zinc-900 p-6 shadow-xl">
        <div className="mb-4 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-emerald-400 text-zinc-950">
            <ShieldCheck className="h-5 w-5" />
          </div>
          <div>
            <h3 className="text-lg font-semibold">Step-Up Verification</h3>
            <p className="text-sm text-zinc-400">Enter your TOTP code to continue</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-2 block text-sm font-medium text-zinc-300" htmlFor="totp-code">
              TOTP Code
            </label>
            <input
              id="totp-code"
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value)}
              maxLength={6}
              placeholder="000000"
              className="w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2.5 text-center text-lg tracking-widest outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20"
              autoFocus
            />
          </div>

          <div className="flex gap-3">
            <button
              type="button"
              onClick={onCancel}
              className="flex-1 rounded-lg border border-zinc-700 px-4 py-2.5 text-sm font-medium text-zinc-300 transition hover:bg-zinc-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || code.length !== 6}
              className="flex-1 rounded-lg bg-emerald-400 px-4 py-2.5 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50"
            >
              {isLoading ? 'Verifying...' : 'Verify'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
