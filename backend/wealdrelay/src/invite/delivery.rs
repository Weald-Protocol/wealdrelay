// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! Who sends the invite mail, decided by configuration and by nothing else.
//!
//! `specs/backend/relay/invites.md`, step 2 of the join flow: a **self-hosted**
//! relay may send the link via the operator's own SMTP, because the operator is the
//! customer and an invitee address in their own mail server is not a disclosure to
//! anyone. On the **hosted** tier relay-sent mail is off and cannot be enabled,
//! because otherwise we would hold the email addresses of people being invited, in
//! the data plane, which contradicts the claim in
//! `specs/backend/cloud/overview.md` that we cannot tell which humans exist.
//!
//! ## Why there is no `if hosted` in this file
//!
//! `specs/backend/build/environments.md` requires the hosted binary to be the
//! audited binary, so a build must never branch on its environment. The difference
//! is therefore carried entirely by one configuration value: this module asks
//! whether an SMTP endpoint is configured, and `crate::profile` refuses
//! `WEALD_RELAY_SMTP_URL` at startup on the hosted profile. A hosted relay reaches
//! ``decide`` with `None` because it could not have started with anything else, and
//! a self-hoster who sets the hosted profile watches their own relay refuse the same
//! thing ours refuses, which is the only version of this claim checkable from
//! outside.
//!
//! ``decide`` takes the resolved value rather than the `Config`, so the type system
//! carries the rule: there is no `Profile` in scope here to branch on.

/// What the admin's client is told to do with the link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The relay will send it, over the operator's own SMTP.
    RelaySends,
    /// The relay will not. The admin's client sends it through the admin's own mail
    /// client, or copies the link.
    ///
    /// Never a degraded mode: copy-to-clipboard is always available and is the
    /// default on hosted, so no admin is ever forced to configure mail to onboard
    /// someone.
    CopyLink,
}

impl Delivery {
    /// The label the admin UI and the startup log use.
    pub fn label(self) -> &'static str {
        match self {
            Self::RelaySends => "relay_sends",
            Self::CopyLink => "copy_link",
        }
    }
}

/// The decision, from the one value it depends on.
pub fn decide(smtp_configured: bool) -> Delivery {
    if smtp_configured {
        Delivery::RelaySends
    } else {
        Delivery::CopyLink
    }
}

/// The landing page the relay serves at `/join/<token>`.
///
/// Static, no control plane involved, so self-host works identically. It cannot
/// display the workspace name, the inviter's name, or anything else, because the
/// relay does not know them: everything it holds about an invite is a token, a
/// public key, an Argon2id hash and ciphertext.
///
/// The token is **not** interpolated into the page and the fragment could not be
/// even if it were wanted, because a browser does not send a fragment to a server.
/// This function therefore takes no argument and the response is identical for every
/// token, including tokens that do not exist. That is the point: a page that varied
/// with the token would confirm which tokens exist to anyone who could fetch it,
/// which is the same oracle the flat unavailable response exists to close.
///
/// The deep link is assembled in the browser from `location`, which is the only
/// place both halves are present at once.
pub fn landing_page() -> &'static str {
    LANDING_PAGE
}

const LANDING_PAGE: &str = "<!doctype html>\
<html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
<meta name=\"robots\" content=\"noindex\">\
<title>Weald</title></head>\
<body><h1>You've been invited to a Weald workspace</h1>\
<p>Open this invite in your Weald client. You will need the one-time code the \
person who invited you sent separately, which is not in this link.</p>\
<p><a id=\"open\" href=\"#\">Open in Weald</a></p>\
<p>No client yet? Ask the person who invited you which one this workspace uses. \
The relay serving this page does not host client downloads.</p>\
<script>\
var open = document.getElementById('open');\
open.href = 'weald://join/' + location.pathname.split('/').pop() + location.hash;\
</script>\
</body></html>";
