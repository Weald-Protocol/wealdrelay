// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! The admission-blind per-group abuse budget on `SEND` (WEALD-L1090).
//!
//! `specs/backend/relay/wire.md` requires it: the relay cannot tell an MLS member
//! from an access-set principal who merely knows a group id, so without this any
//! admitted device could make a known group expensive with invalid ciphertext.
//! `crate::send_budget` bounds one device across every group; this bounds one
//! device into one group, and one workspace across all of its devices.
//!
//! Charged after `authorize_group` (the group is known to be this session's
//! workspace's) and before `accept::accept` opens its transaction, so a refused
//! frame is never stored. Both limits are checked before either is committed, so
//! a refusal charges nothing. Answered `quota/group_ingress_limited` with the
//! window as the retry interval, on a socket that stays up.

use crate::frame::{ErrorCode, FrameError};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// The window both limits are counted over, the minute `wire.md` states them in.
pub const GROUP_INGRESS_WINDOW_MS: u64 = 60_000;

/// Bytes per principal per target group per window (`wire.md`: 8 MiB).
pub const DEFAULT_PRINCIPAL_GROUP_BYTES_PER_MINUTE: u64 = 8 * 1024 * 1024;

/// Bytes per workspace per window (`wire.md`: 64 MiB).
pub const DEFAULT_WORKSPACE_BYTES_PER_MINUTE: u64 = 64 * 1024 * 1024;

/// Entries held before stale windows are swept. Bounds churn, not membership.
pub const MAX_TRACKED_KEYS: usize = 16_384;

/// Which limit a refused `SEND` met.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressRefusal {
    /// Over the per-principal, per-group allowance.
    PrincipalGroup,
    /// Over the per-workspace allowance.
    Workspace,
}

impl IngressRefusal {
    /// The whole refusal, as it goes on the wire. The detail is the limit met,
    /// never anything derived from content.
    pub fn to_frame_error(self, budget: &GroupIngressBudget) -> FrameError {
        let limit = match self {
            Self::PrincipalGroup => budget.principal_group_bytes,
            Self::Workspace => budget.workspace_bytes,
        };
        FrameError::new(ErrorCode::GroupIngressLimited)
            .retry_after((GROUP_INGRESS_WINDOW_MS / 1_000).max(1) as u32)
            .detail(limit.to_be_bytes())
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct Usage {
    window: u64,
    bytes: u64,
}

#[derive(Debug, Default)]
struct Counters {
    principal_group: HashMap<(Vec<u8>, Vec<u8>), Usage>,
    workspace: HashMap<String, Usage>,
}

/// The per-group and per-workspace `SEND` byte budget.
#[derive(Debug)]
pub struct GroupIngressBudget {
    counters: tokio::sync::Mutex<Counters>,
    refused: AtomicU64,
    pub principal_group_bytes: u64,
    pub workspace_bytes: u64,
}

impl Default for GroupIngressBudget {
    fn default() -> Self {
        Self::new(
            DEFAULT_PRINCIPAL_GROUP_BYTES_PER_MINUTE,
            DEFAULT_WORKSPACE_BYTES_PER_MINUTE,
        )
    }
}

fn current(usage: &mut Usage, window: u64) -> u64 {
    if usage.window != window {
        *usage = Usage { window, bytes: 0 };
    }
    usage.bytes
}

impl GroupIngressBudget {
    pub fn new(principal_group_bytes: u64, workspace_bytes: u64) -> Self {
        Self {
            counters: tokio::sync::Mutex::new(Counters::default()),
            refused: AtomicU64::new(0),
            principal_group_bytes,
            workspace_bytes,
        }
    }

    /// Charge one `SEND` of `bytes` from `principal` into `group` of `workspace`.
    pub async fn charge(
        &self,
        principal: &[u8],
        group: &[u8],
        workspace: &str,
        bytes: u64,
        now_ms: u64,
    ) -> Result<(), IngressRefusal> {
        let window = now_ms / GROUP_INGRESS_WINDOW_MS;
        let mut counters = self.counters.lock().await;
        if counters.principal_group.len() > MAX_TRACKED_KEYS {
            counters
                .principal_group
                .retain(|_, usage| usage.window == window);
        }
        if counters.workspace.len() > MAX_TRACKED_KEYS {
            counters.workspace.retain(|_, usage| usage.window == window);
        }
        let key = (principal.to_vec(), group.to_vec());
        let pair = current(
            counters.principal_group.entry(key.clone()).or_default(),
            window,
        )
        .saturating_add(bytes);
        let whole = current(
            counters.workspace.entry(workspace.to_string()).or_default(),
            window,
        )
        .saturating_add(bytes);
        if pair > self.principal_group_bytes {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return Err(IngressRefusal::PrincipalGroup);
        }
        if whole > self.workspace_bytes {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return Err(IngressRefusal::Workspace);
        }
        if let Some(usage) = counters.principal_group.get_mut(&key) {
            usage.bytes = pair;
        }
        if let Some(usage) = counters.workspace.get_mut(workspace) {
            usage.bytes = whole;
        }
        Ok(())
    }

    /// How many `SEND`s this process refused on this budget. The operator metric
    /// `wire.md` asks for: a count, with no content-derived label.
    pub fn refused(&self) -> u64 {
        self.refused.load(Ordering::Relaxed)
    }
}
