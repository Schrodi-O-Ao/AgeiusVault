"use client";

import { FormEvent, useState, useEffect } from 'react';
import { Check, ShieldCheck, X, Lock, Unlock } from 'lucide-react';
import { api } from '@/lib/api';
import { decryptPayloadForApprover, importKeyFromPEM } from '@/lib/crypto';
import { useCryptoStore } from '@/store/cryptoStore';
import type { AegisVaultRequest } from '@/types';

const actions = [
  { value: 'APPROVED', label: 'Approve', icon: Check },
  { value: 'REJECTED', label: 'Reject', icon: X },
];

export function ApprovalPanel({ request, onUpdated }: { request: AegisVaultRequest; onUpdated: () => void }) {
  const [actionType, setActionType] = useState('APPROVED');
  const [totpCode, setTotpCode] = useState('');
  const [notes, setNotes] = useState('');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [decryptedPayload, setDecryptedPayload] = useState<string | null>(null);
  const [showDecrypted, setShowDecrypted] = useState(false);
  const { userPrivateKeyPEM } = useCryptoStore();

  useEffect(() => {
    const decryptIfEncrypted = async () => {
      if (request.is_encrypted && userPrivateKeyPEM) {
        setIsDecrypting(true);
        try {
          const response = await api.get(`/encrypted/${request.id}`);
          if (response.data && response.data.wrappedKey) {
            const privateKey = await importKeyFromPEM(userPrivateKeyPEM, 'PRIVATE');
            const encryptedData = {
              encryptedPayload: response.data.encryptedData,
              iv: response.data.iv,
              keyHash: '',
              wrappedKeys: [{ userId: 'current', wrappedKey: response.data.wrappedKey }]
            };
            const plaintext = await decryptPayloadForApprover(encryptedData, privateKey, 'current');
            setDecryptedPayload(plaintext);
          }
        } catch (err) {
          console.error('Decryption failed:', err);
          setError('Failed to decrypt request payload');
        } finally {
          setIsDecrypting(false);
        }
      }
    };
    decryptIfEncrypted();
  }, [request.is_encrypted, request.id, userPrivateKeyPEM]);

  if (!request.can_act || request.status !== 'PENDING') return null;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      const step = await api.post('/auth/step-up', {
        request_id: request.id,
        action_type: actionType.toLowerCase(),
        totp_code: totpCode,
      });
      await api.post(
        `/requests/${request.id}/action`,
        { action: actionType, nonce: request.nonce, notes: notes || undefined },
        { headers: { 'X-Step-Up-Token': step.data.step_up_token } },
      );
      setTotpCode('');
      setNotes('');
      onUpdated();
    } catch (err) {
      const detail = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      setError(detail || 'Action failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
      <div className="mb-4 flex items-center gap-2">
        <ShieldCheck className="h-5 w-5 text-emerald-300" />
        <h2 className="font-semibold">Step-Up Approval</h2>
        {request.is_encrypted && <Lock className="h-4 w-4 text-emerald-400" />}
      </div>
      {error && <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}
      
      {request.is_encrypted && (
        <div className="mb-4 rounded-lg border border-zinc-700 bg-zinc-950 p-3">
          <div className="mb-2 flex items-center justify-between">
            <span className="text-sm font-medium text-zinc-300">Encrypted Payload</span>
            {decryptedPayload && (
              <button
                type="button"
                onClick={() => setShowDecrypted(!showDecrypted)}
                className="text-xs text-emerald-400 hover:text-emerald-300"
              >
                {showDecrypted ? <Lock className="h-3 w-3 inline" /> : <Unlock className="h-3 w-3 inline" />}
                {showDecrypted ? 'Hide' : 'Show'}
              </button>
            )}
          </div>
          {isDecrypting ? (
            <div className="text-sm text-zinc-500">Decrypting...</div>
          ) : decryptedPayload ? (
            <div className={`text-sm text-zinc-300 ${showDecrypted ? '' : 'blur-sm'}`}>
              {decryptedPayload}
            </div>
          ) : (
            <div className="text-sm text-zinc-500">Unable to decrypt - your private key may not have access</div>
          )}
        </div>
      )}
      
      <div className="grid gap-3">
        <div className="grid grid-cols-2 gap-2">
          {actions.map((item) => (
            <button key={item.value} type="button" onClick={() => setActionType(item.value)}
              className={`inline-flex h-10 items-center justify-center gap-2 rounded-lg border px-3 text-sm font-medium transition ${actionType === item.value ? 'border-emerald-400/50 bg-emerald-400/10 text-emerald-100' : 'border-zinc-700 text-zinc-300 hover:bg-zinc-800'}`}>
              <item.icon className="h-4 w-4" />{item.label}
            </button>
          ))}
        </div>
        <label>
          <span className="mb-2 block text-sm font-medium text-zinc-300">Authenticator Code</span>
          <input value={totpCode} onChange={(e) => setTotpCode(e.target.value)} inputMode="numeric" maxLength={6} required className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-center text-lg outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
        </label>
        <label>
          <span className="mb-2 block text-sm font-medium text-zinc-300">Notes (optional)</span>
          <textarea value={notes} onChange={(e) => setNotes(e.target.value)} rows={3} className="w-full resize-none rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none transition focus:border-emerald-400 focus:ring-2 focus:ring-emerald-400/20" />
        </label>
        <button disabled={isLoading || !request.nonce} className="inline-flex h-10 items-center justify-center gap-2 rounded-lg bg-emerald-400 px-4 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:opacity-50">
          <ShieldCheck className="h-4 w-4" />{isLoading ? 'Submitting…' : 'Submit Signed Action'}
        </button>
      </div>
    </form>
  );
}
