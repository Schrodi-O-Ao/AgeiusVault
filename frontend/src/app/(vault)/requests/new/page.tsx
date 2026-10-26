"use client";

import { FormEvent, useState, useEffect } from 'react';
import { FilePlus2, Send, CalendarDays, DollarSign, Shield, FileText, Lock } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { api } from '@/lib/api';
import { encryptPayloadForApprovers, generateRSAKeyPair, exportKeyToPEM } from '@/lib/crypto';
import { useCryptoStore } from '@/store/cryptoStore';

const REQUEST_TYPES = [
  { id: 'ANNUAL_LEAVE', name: 'Annual Leave', icon: CalendarDays, fields: ['start_date', 'end_date', 'reason'] },
  { id: 'SICK_LEAVE', name: 'Sick Leave', icon: CalendarDays, fields: ['start_date', 'days', 'fit_note'] },
  { id: 'EXPENSE', name: 'Expense Claim', icon: DollarSign, fields: ['amount', 'currency', 'category', 'description'] },
  { id: 'IT_ACCESS', name: 'IT Access Request', icon: Shield, fields: ['system', 'access_level', 'justification'] },
  { id: 'ANON_HR', name: 'Anonymous HR Report', icon: FileText, fields: ['category', 'description'], isAnonymous: true },
];

export default function NewRequestPage() {
  const router = useRouter();
  const [requestType, setRequestType] = useState('ANNUAL_LEAVE');
  const [payload, setPayload] = useState<Record<string, string>>({});
  const [isAnonymous, setIsAnonymous] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [useEncryption, setUseEncryption] = useState(true);
  const [approverKeys, setApproverKeys] = useState<Array<{ userId: string; publicKeyPEM: string }>>([]);
  const { userPrivateKeyPEM, userPublicKeyPEM, setUserKeyPair, addApproverPublicKey } = useCryptoStore();

  const selectedType = REQUEST_TYPES.find((t) => t.id === requestType) || REQUEST_TYPES[0];

  useEffect(() => {
    const initializeKeys = async () => {
      if (!userPrivateKeyPEM || !userPublicKeyPEM) {
        const keyPair = await generateRSAKeyPair();
        const privateKeyPEM = await exportKeyToPEM(keyPair.privateKey, 'PRIVATE');
        const publicKeyPEM = await exportKeyToPEM(keyPair.publicKey, 'PUBLIC');
        setUserKeyPair(privateKeyPEM, publicKeyPEM);
      }
    };
    initializeKeys();
  }, [userPrivateKeyPEM, userPublicKeyPEM, setUserKeyPair]);

  useEffect(() => {
    const fetchApproverKeys = async () => {
      if (useEncryption) {
        try {
          const response = await api.get(`/encrypted/approvers/${selectedType.id}`);
          const approverResponse = response.data as {
            publicKeys?: Array<{ userId: string; publicKey: string }>;
          };
          if (approverResponse.publicKeys) {
            const keys = approverResponse.publicKeys.map((pk) => ({
              userId: pk.userId,
              publicKeyPEM: pk.publicKey
            }));
            setApproverKeys(keys);
            keys.forEach((k) => {
              addApproverPublicKey(k.userId, k.publicKeyPEM);
            });
          }
        } catch (err) {
          console.error('Failed to fetch approver keys:', err);
          setUseEncryption(false);
        }
      }
    };
    fetchApproverKeys();
  }, [selectedType.id, useEncryption, addApproverPublicKey]);

  const updateField = (name: string, value: string) => {
    setPayload((current) => ({ ...current, [name]: value }));
  };

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError('');
    setIsLoading(true);
    setIsEncrypting(true);

    try {
      const payloadString = JSON.stringify(payload);
      
      if (useEncryption && approverKeys.length > 0) {
        const encryptedData = await encryptPayloadForApprovers(payloadString, approverKeys);
        
        await api.post('/encrypted/encrypted', {
          encryptedPayload: encryptedData.encryptedPayload,
          iv: encryptedData.iv,
          keyHash: encryptedData.keyHash,
          requestType: selectedType.id,
          isAnonymous: selectedType.isAnonymous || isAnonymous,
          wrappedKeys: encryptedData.wrappedKeys
        });
        
        router.push(`/outbox`);
      } else {
        await api.post('/requests', {
          request_type: selectedType.id,
          payload,
          is_anonymous: selectedType.isAnonymous || isAnonymous,
        });
        router.push(`/outbox`);
      }
    } catch (err) {
      const detail = err && typeof err === 'object' && 'response' in err
        ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
        : undefined;
      setError(detail || 'Request could not be created.');
    } finally {
      setIsLoading(false);
      setIsEncrypting(false);
    }
  };

  return (
    <div className="space-y-5">
      <header>
        <p className="text-sm font-medium text-emerald-300">
          {useEncryption ? 'Client-side encrypted payload' : 'Encrypted workflow payload'}
        </p>
        <h1 className="mt-1 text-3xl font-semibold">Submit Request</h1>
      </header>

      <form onSubmit={submit} className="rounded-lg border border-zinc-800 bg-zinc-900 p-5">
        <div className="mb-5 flex items-center gap-2">
          <FilePlus2 className="h-5 w-5 text-emerald-300" />
          <h2 className="font-semibold">Request Details</h2>
          {useEncryption && <Lock className="h-4 w-4 text-emerald-400" />}
        </div>
        {error && <div className="mb-5 rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-200">{error}</div>}

        <div className="mb-5">
          <label className="mb-2 block text-sm font-medium text-zinc-300">Request Type</label>
          <select
            value={requestType}
            onChange={(e) => {
              setRequestType(e.target.value);
              setPayload({});
              setIsAnonymous(false);
            }}
            className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none transition focus:border-emerald-400"
          >
            {REQUEST_TYPES.map((type) => (
              <option key={type.id} value={type.id}>{type.name}</option>
            ))}
          </select>
        </div>

        <div className="grid gap-4 lg:grid-cols-2">
          {selectedType.fields.map((field) => (
            <label key={field} className={field === 'reason' || field === 'description' || field === 'justification' ? 'lg:col-span-2' : ''}>
              <span className="mb-2 block text-sm font-medium text-zinc-300">
                {field.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())}
              </span>
              {field === 'reason' || field === 'description' || field === 'justification' || field === 'fit_note' ? (
                <textarea
                  required
                  value={payload[field] || ''}
                  onChange={(e) => updateField(field, e.target.value)}
                  rows={4}
                  className="w-full resize-none rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm outline-none transition focus:border-emerald-400"
                />
              ) : field === 'start_date' || field === 'end_date' ? (
                <input
                  required
                  type="date"
                  value={payload[field] || ''}
                  onChange={(e) => updateField(field, e.target.value)}
                  className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none transition focus:border-emerald-400"
                />
              ) : field === 'days' ? (
                <input
                  required
                  type="number"
                  min="1"
                  value={payload[field] || ''}
                  onChange={(e) => updateField(field, e.target.value)}
                  className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none transition focus:border-emerald-400"
                />
              ) : (
                <input
                  required
                  type="text"
                  value={payload[field] || ''}
                  onChange={(e) => updateField(field, e.target.value)}
                  className="h-10 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 text-sm outline-none transition focus:border-emerald-400"
                />
              )}
            </label>
          ))}
        </div>

        {!selectedType.isAnonymous && (
          <label className="mt-5 flex items-center gap-2 text-sm text-zinc-300">
            <input
              type="checkbox"
              checked={isAnonymous}
              onChange={(event) => setIsAnonymous(event.target.checked)}
              className="h-4 w-4 accent-emerald-400"
            />
            Submit anonymously
          </label>
        )}

        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 border-t border-zinc-800 pt-4">
          <p className="text-xs text-zinc-500">
            {useEncryption && approverKeys.length > 0
              ? 'Request content is encrypted in this browser for the selected approver.'
              : 'Request content uses the server-side encryption workflow.'}
          </p>
          <button
            type="submit"
            disabled={isLoading || isEncrypting}
            className="inline-flex h-10 items-center gap-2 rounded-lg bg-emerald-400 px-4 text-sm font-semibold text-zinc-950 transition hover:bg-emerald-300 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Send className="h-4 w-4" />
            {isEncrypting ? 'Encrypting and submitting…' : isLoading ? 'Submitting…' : 'Submit request'}
          </button>
        </div>
      </form>
    </div>
  );
}
