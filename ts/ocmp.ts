// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
//
// OCMP offline profile (R2–R7), mirroring register/ocmp and ocmp.py.

export interface OcInputs {
  grant_covers?: boolean;
  trust_anchor?: boolean;
  local_policy?: boolean;
  status?: {
    present?: boolean;
    verified?: boolean;
    as_of?: number;
    valid_until?: number;
    version?: number;
    last_accepted?: number;
  };
  credential_expired?: boolean;
  revoked?: boolean;
  replay_enabled?: boolean;
  counter?: number;
  last_consumed?: number;
  required_fact?: boolean;
  fact_available?: boolean;
  trusted_time?: number;
  clock_offset?: number;
  clock_tolerance?: number;
}

export function evaluate(inp: OcInputs): [string, string] {
  const st = inp.status ?? {};
  if (!inp.grant_covers) return ['deny', 'capability_not_authorized'];
  if (!inp.trust_anchor) return ['deny', 'trust_anchor_missing'];
  if (!inp.local_policy) return ['deny', 'local_policy_missing'];
  if (!st.present || !st.verified) return ['deny', 'status_snapshot_missing'];
  const t = inp.trusted_time ?? 0;
  if (t < (st.as_of ?? 0) || t > (st.valid_until ?? 0)) return ['deny', 'status_snapshot_expired'];
  if ((st.version ?? 0) < (st.last_accepted ?? 0)) return ['deny', 'status_snapshot_rollback'];
  if (inp.revoked) return ['deny', 'revoked'];
  if (inp.credential_expired) return ['deny', 'capability_not_authorized'];
  if (inp.replay_enabled) {
    if ((inp.counter ?? 0) === (inp.last_consumed ?? 0)) return ['deny', 'replay_detected'];
    if ((inp.counter ?? 0) < (inp.last_consumed ?? 0)) return ['deny', 'replay_state_invalid'];
  }
  if (inp.required_fact && !inp.fact_available) return ['deny', 'fact_unavailable'];
  if ((inp.clock_offset ?? 0) > (inp.clock_tolerance ?? 0)) return ['deny', 'clock_unsynchronized'];
  return ['allow', ''];
}
