import { create } from 'zustand';

interface CryptoState {
  userPrivateKeyPEM: string | null;
  userPublicKeyPEM: string | null;
  vaultKey: string | null;
  approverPublicKeys: Record<string, string>;
  setVaultKey: (key: string) => void;
  setUserKeyPair: (privateKeyPEM: string, publicKeyPEM: string) => void;
  addApproverPublicKey: (userId: string, publicKeyPEM: string) => void;
  getApproverPublicKey: (userId: string) => string | null;
  clearKeys: () => void;
}

export const useCryptoStore = create<CryptoState>((set, get) => ({
  userPrivateKeyPEM: null,
  userPublicKeyPEM: null,
  vaultKey: null,
  approverPublicKeys: {},
  
  setVaultKey: (key: string) => set({ vaultKey: key }),
  
  setUserKeyPair: (privateKeyPEM: string, publicKeyPEM: string) => 
    set({ userPrivateKeyPEM: privateKeyPEM, userPublicKeyPEM: publicKeyPEM }),
  
  addApproverPublicKey: (userId: string, publicKeyPEM: string) =>
    set((state) => ({
      approverPublicKeys: { ...state.approverPublicKeys, [userId]: publicKeyPEM }
    })),
  
  getApproverPublicKey: (userId: string) => {
    return get().approverPublicKeys[userId] || null;
  },
  
  clearKeys: () => set({
    userPrivateKeyPEM: null,
    userPublicKeyPEM: null,
    vaultKey: null,
    approverPublicKeys: {}
  })
}));
