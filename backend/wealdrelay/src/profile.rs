// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Which deployment this relay is, and the settings that deployment forbids.
//!
//! `specs/backend/relay/server.md` states four things about the hosted tier that
//! nothing in the configuration surface was previously able to enforce:
//!
//! - `WEALD_RELAY_SMTP_URL` is "self-host only" and "refused outright on the
//!   hosted tier", because our relay holding invitee email addresses would put a
//!   list of humans inside the blind half of the system
//!   (`specs/backend/relay/invites.md`).
//! - `WEALD_RELAY_ACCESS_SET` "is always `enforce`" there "and the value is not
//!   customer-configurable".
//! - `WEALD_RELAY_MIN_ENC` is pinned to `mls`, which is a property of that
//!   deployment rather than of the default.
//! - `WEALD_RELAY_METRICS_GROUP_LABELS` "is never enabled on the hosted tier",
//!   so per-group counts are not merely something the control plane declines to
//!   retain: they are something it is not offered
//!   (`specs/backend/cloud/billing.md`).
//!
//! **This is configuration, not a code fork.** The rule that the hosted binary
//! must be the audited binary (`specs/backend/build/environments.md`) means a
//! build must never branch on its environment. It does not mean the binary
//! cannot be told which deployment it is and refuse a setting that deployment
//! forbids: both profiles are compiled into every build, both are reachable from
//! every build's tests, and the digest is the same either way. A self-hoster can
//! set `hosted` and watch their relay refuse the same things ours refuses, which
//! is the only version of this claim that is checkable from outside.
//!
//! The refusal is at startup and it is fatal. A relay that started with a
//! forbidden setting and merely logged about it would be a relay whose posture
//! nobody chose, and three of the four settings here decide posture.

use crate::config::{keys, AccessSetMode, Config, ConfigError, MinEncryption};

/// Which deployment this is.
///
/// `SelfHost` is the default in every environment including ours, because a
/// default that only the hosted tier gets right is a default a self-hoster
/// discovers by being refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    #[default]
    SelfHost,
    Hosted,
}

impl Profile {
    /// The label `/readyz`, the startup log and `--check-config` all use.
    pub fn label(self) -> &'static str {
        match self {
            Self::SelfHost => "self_host",
            Self::Hosted => "hosted",
        }
    }

    /// The accepted spellings, for the configuration parser and its error
    /// message. One list, so a value the parser takes and a value the message
    /// names cannot drift apart.
    pub const ALLOWED: &'static str = "self_host, hosted";

    pub const TABLE: &'static [(&'static str, Self)] =
        &[("self_host", Self::SelfHost), ("hosted", Self::Hosted)];
}

/// Every setting the hosted tier forbids, with the reason the operator needs.
///
/// Returns the first refusal rather than collecting them, because the operator's
/// next action is to remove one variable and try again, and a wall of four
/// errors is not more useful than the first one.
pub fn enforce(config: &Config) -> Result<(), ConfigError> {
    if config.profile != Profile::Hosted {
        return Ok(());
    }

    if config.smtp_url.is_some() {
        return Err(refused(
            keys::SMTP_URL,
            "the hosted relay must not hold invitee email addresses, which \
             would put a list of humans inside the blind half of the system. \
             Invites are copied by the admin instead",
        ));
    }

    if config.access_set != AccessSetMode::Enforce {
        return Err(refused(
            keys::ACCESS_SET,
            "the hosted tier is always enforce and the value is not \
             customer-configurable there. `off` is defensible only on a \
             deployment with no public ingress",
        ));
    }

    if config.min_encryption != MinEncryption::Mls {
        return Err(refused(
            keys::MIN_ENC,
            "the hosted tier pins mls. A self-hoster mid-migration may accept \
             plaintext envelopes; a hosted workspace may not",
        ));
    }

    if config.metrics_group_labels {
        return Err(refused(
            keys::METRICS_GROUP_LABELS,
            "per-group envelope counts are never enabled on the hosted tier, \
             so they are not something the control plane declines to retain \
             but something it is not offered",
        ));
    }

    Ok(())
}

fn refused(key: &'static str, reason: &'static str) -> ConfigError {
    ConfigError::RefusedOnHostedProfile { key, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_round_trip_with_the_parse_table() {
        for (spelling, profile) in Profile::TABLE {
            assert_eq!(profile.label(), *spelling);
            assert!(Profile::ALLOWED.contains(spelling));
        }
    }

    #[test]
    fn the_default_is_self_host() {
        // A default that only the hosted tier gets right is a default a
        // self-hoster discovers by being refused.
        assert_eq!(Profile::default(), Profile::SelfHost);
        assert_eq!(Profile::default().label(), "self_host");
    }

    #[test]
    fn profile_is_copy_comparable_and_printable() {
        let a = Profile::Hosted;
        let b = a;
        assert_eq!(a, b);
        assert_ne!(a, Profile::SelfHost);
        assert!(format!("{a:?}").contains("Hosted"));
    }
}
