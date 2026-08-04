// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dicyanin Labs
//! What happens to an invite link once it exists: the admin's client delivers it, and
//! this relay serves the page it points at.
//!
//! ## Why the relay does not send mail
//!
//! It used to say it might. `Delivery::RelaySends` existed here, `decide` returned it
//! whenever `WEALD_RELAY_SMTP_URL` was set, and the label `relay_sends` was a string a
//! client could read. There was no SMTP client behind any of it and no mail crate in
//! either `Cargo.toml`: a self-hoster who configured mail got a relay that reported it
//! would send and then did not. A promise a binary cannot keep is worse than an absence,
//! because the absence is at least visible from the admin surface, so the arm is gone
//! rather than stubbed. See WEALD-L072.
//!
//! Delivery is therefore always the admin's own client. That was already the only path
//! that worked and it is not a degraded mode: it is the path that keeps the invitee's
//! address out of every server involved, which is the claim
//! `specs/backend/cloud/overview.md` rests on. `Sources/UI/Invite/InviteSheet.swift`
//! opens a local draft carrying the link, and the one-time code stays on its own button
//! and its own channel.
//!
//! `WEALD_RELAY_SMTP_URL` is still accepted on a self-host profile and still refused on
//! the hosted one (`crate::profile`), because the variable is in
//! `specs/backend/build/env-registry.json` and removing it is a separate change from
//! removing the arm that lied about it. It configures nothing today, which is exactly
//! what the label used to hide.

/// What the admin's client is told to do with the link, which is always the same thing.
///
/// One arm, deliberately. It is kept as a named value rather than collapsed into a string
/// literal at each call site so that the day a relay really can send mail, the second arm
/// arrives with a sender behind it and every reader is already switching on the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// The relay will not send it. The admin's client opens a draft, or copies the link.
    CopyLink,
}

impl Delivery {
    /// The label the admin UI and the startup log use.
    pub fn label(self) -> &'static str {
        match self {
            Self::CopyLink => "copy_link",
        }
    }
}

/// What this relay does with an invite link, whatever it is configured with.
///
/// Takes no argument, and that is the change. It used to take whether SMTP was
/// configured, which made a configuration value look load-bearing when nothing read it.
pub fn decide() -> Delivery {
    Delivery::CopyLink
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
///
/// A fragment eaten in transit is the likely failure rather than an edge case,
/// because chat clients linkify a URL and drop everything after the `#`. When the
/// fragment is absent the page says so specifically, in the same words the hosted
/// page at `backend/weald-web/src/workspace-invite.tsx` uses, and withholds the deep
/// link rather than offering one that cannot work. Both surfaces telling the person
/// the same thing is the point: an invitee who lands on one of two pages should not
/// get a diagnosis on one and silence on the other. See WEALD-L079.
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
<p id=\"missing-secret\" hidden>This link is missing the part after the \
<code>#</code>, which is the half that unlocks the workspace. Chat clients and link \
previews sometimes cut it off. Ask for the link again, pasted as plain text.</p>\
<p>No client yet? Get the Weald app from \
<a href=\"https://getweald.com/download\">getweald.com/download</a>, then open this \
same link again: the invite stays valid, and the part after the <code>#</code> \
never leaves this page. This relay does not host client downloads itself, and if \
this workspace uses a different client, ask the person who invited you.</p>\
<script>\
var open = document.getElementById('open');\
open.href = 'weald://join/' + location.pathname.split('/').pop() + location.hash;\
if (location.hash === '') {\
document.getElementById('missing-secret').hidden = false;\
open.removeAttribute('href');\
}\
</script>\
</body></html>";
