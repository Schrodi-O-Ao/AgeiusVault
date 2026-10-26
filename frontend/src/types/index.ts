export interface UserProfile {
  id: string;
  full_name: string;
  email: string;
  key_salt?: string;
  totp_enabled?: boolean;
  role?: "STAFF" | "MANAGER" | "HR_ADMIN" | "SYS_ADMIN";
  department?: string | null;
  manager_id?: string | null;
}

export type AegisVaultRequestType =
  | "ANNUAL_LEAVE"
  | "SICK_LEAVE"
  | "EXPENSE"
  | "IT_ACCESS"
  | "ANON_HR";

export interface RequestTypeInfo {
  id: string;
  name: string;
  slug: string;
}

export interface ApprovalEntry {
  id: string;
  approver_id: string;
  action: "APPROVED" | "REJECTED";
  acted_at: string;
  step_nonce: string;
}

export interface AegisVaultRequest {
  id: string;
  requester_id: string | null;
  type: AegisVaultRequestType;
  status: "PENDING" | "APPROVED" | "REJECTED" | "CANCELLED";
  is_anonymous: boolean;
  is_encrypted?: boolean;
  submitted_at: string;
  updated_at: string;
  payload?: Record<string, unknown>;
  can_act?: boolean;
  nonce?: string;
  approvals?: ApprovalEntry[];
}

export interface DashboardStats {
  pending_approvals: number;
  my_requests: number;
  approved: number;
  security_score: number;
}

export interface Delegation {
  id: string;
  delegator_id: string;
  delegator_name: string | null;
  delegatee_id: string;
  delegatee_name: string | null;
  valid_from: string;
  valid_until: string;
  is_active: boolean;
  created_at: string;
}

export interface TeamMember {
  id: string;
  full_name: string;
  email: string;
  role: string;
  department: string | null;
  totp_enabled: boolean;
}

export interface AuditChainEntry {
  id: string;
  request_id: string;
  step_index: number;
  actor_id: string | null;
  action: string;
  chain_hash: string;
  prev_hash: string;
  recorded_at: string;
}

export interface AuditVerification {
  is_valid: boolean;
  entries_checked: number;
  violations: Array<{
    entry_id: string;
    type: string;
    expected_prev?: string;
    stored_prev?: string;
    expected_hash?: string;
    stored_hash?: string;
  }>;
}

export interface SessionInfo {
  id: string;
  device_label: string | null;
  ip_country: string | null;
  created_at: string;
  expires_at: string;
  last_active_at: string | null;
}
