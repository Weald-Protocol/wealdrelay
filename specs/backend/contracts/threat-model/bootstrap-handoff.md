# Threat model: the provisioning handoff

The trust-root race. One boundary, one attack, and it is the single highest-risk
edge in the system because the control plane briefly touches a capability that
grants workspace administration.

## The attack

The bootstrap invite is a capability to become admin of an empty workspace. The
control plane handles its link half, which means the control plane could, in
principle, use it first: enroll its own device as trust root, then invite the
paying customer as an ordinary member. The customer would then be inside a
workspace we administer, and could be silently added to groups.

An insider with control plane access is the realistic adversary. So is a
compromised control plane.

## Controls, in the order they apply

| # | Control | Answer class | Proof |
| --- | --- | --- | --- |
| B1 | The invite is split into two halves delivered over two channels. The link half returns in the API response; the code half is emailed to the verified Clerk email locked into the Checkout session. Neither half enrolls anyone on its own. | 3 | Integration test asserting a single half cannot redeem. |
| B2 | The code destination is the initiating owner's already-verified Clerk email, locked into Checkout. Not a mutable Stripe invoice address. | 3 | Test asserting a portal email change does not move the destination. |
| B3 | The relay seals the link half to an ephemeral per-instance handoff public key supplied at provisioning. The provisioning worker never streams or claims it. | 3 | Test asserting the worker has no code path that decrypts. |
| B4 | The handoff private key is KMS-wrapped in `bootstrap_handoffs`, unwrapped only in request memory, and the wrapped key is deleted in the same transaction that records the **code half being issued**. | 3 | Test asserting the wrapped key is empty after the code is issued. |
| B5 | Available only while the relay reports zero admitted principals. The relay exposes a count and nothing else about the roster. | 3 | `bootstrap_instance_enrolled`. |
| B6 | Single use, and it is the **code half** that is single-issue. The genesis key signs exactly one bootstrap invite and the relay destroys it on redemption, so a second code request returns 409 permanently. There is no reissue and no support path that reopens it. | 1 after redemption, 3 before. | `bootstrap_handoff_already_used`. |
| B7 | A crashed response is not replayed with a secret. The operation status says a claim occurred and offers the reprovision remedy. | 3 | Test injecting a response-time crash. |
| B8 | Owner-only, step-up within 15 minutes, rate limited to 5 per minute. | 3 | |
| B9 | Every issuance is recorded in the customer-visible audit log with timestamp and source IP, in an append-only chain with a daily signed checkpoint in a separately permissioned bucket-locked prefix. | 3 | Chain verification test. |
| B10 | The link half is never written to our database, logs or analytics. The post-checkout page holds it in browser session storage for its 24-hour lifetime only. | 3 | Log-scraping test asserting the secret never appears. |
| B11 | The client hard-fails enrollment if the workspace already has an admin. | 3 | This is what turns an invisible attack into a visible one. |
| B12 | `POST /instances/:id/reprovision` within 7 days destroys and replaces the instance on the same subscription at no extra charge. | 3 | |

## Which half is once-only, and why the other is not

"Shown once" applies to the **code half** and not to the link half. That is a
correction to an earlier reading of B4 and B6, and it changes nothing about what
an attacker needs.

The link half is re-revealable for as long as the handoff is unclaimed and
unexpired. `POST /instances/:id/bootstrap` may be called repeatedly and returns
the same link every time, because it is the relay's own enrollment URL and is not
minted per request. `POST /instances/:id/bootstrap/code` may be called once, and
that call is what stamps `claimed_at`, destroys the wrapped private key, and ends
the reveals along with it, because the key that opens one blob is the key that
opens the other.

The link half was never the secret. It admits nobody on its own; the code is the
secret and it arrives on a different channel; and the relay's join page is
deliberately byte-identical for every token including tokens that never existed
(`invite::delivery::landing_page`), so a leaked link tells the holder not even
whether it is live. Guarding it as if it were the code bought no security and cost
the harshest failure mode in the product: a browser tab closed at the wrong moment
meant reprovisioning the relay, which is a new workspace id, a new genesis key, and
a purchase-day flow restarted.

What the change costs, stated rather than implied: the wrapped private key now
lives for as long as the handoff does, up to 24 hours, rather than until the first
reveal. So the window in the residual-risk section below is 24 hours of requests
rather than one request. It is still bounded by the same five properties, it still
requires the customer's own verified mailbox as the second channel, and every
reveal is recorded in the customer-visible audit chain as `handoff_revealed`
alongside the single `handoff_claimed`. A customer who reveals once and sees three
reveals in their audit log is being told something true and actionable, which the
old shape could not tell them at all.

## Residual risk, stated plainly

B1 through B10 make the attack detectable and expensive. They do not make it
impossible. A control plane that is fully compromised at the moment of the claim
can read the link half in request memory, and if it also controls the customer's
email it holds both halves.

This is the one place in the system where the answer is not "a key we do not
hold". It is bounded by:

- The window is one request, once, per instance, ever.
- It requires compromising two channels, one of which is the customer's own
  verified mailbox.
- It leaves an audit event the customer can read, in a hash chain checkpointed
  into a separately permissioned store.
- The client's hard-fail turns success into a visible dead end rather than a
  silent membership.
- Reprovision gives the customer a remedy that is not an email to support.

Without B11 and B12 the residual risk would be an invisible compromise. With
them it is a visible, remediable one. That difference is the whole reason the
reprovision endpoint exists, and it is why the 7-day window is generous rather
than tight.

## What we must never do

- Reissue a bootstrap invite. A second bootstrap authority is a quieter version
  of the attack this document is about.
- Let the relay report **who** was admitted rather than **whether**. That would
  link billing and workspace identity, which is the trade the product refuses.
- Add a support path that reopens the handoff. Every request for one is a
  request to reintroduce this attack, however it is phrased.
- Store the link half anywhere, for any duration, for any reason. Re-revealing it
  is not storing it: each reveal fetches the relay's ciphertext and opens it in
  request memory, exactly as the first one did.
- Make the code half re-issuable in the name of symmetry with the link half. The
  asymmetry is the point: one of the two is a secret and one is not.
