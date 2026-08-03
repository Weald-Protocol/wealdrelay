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
| B4 | The handoff private key is KMS-wrapped in `bootstrap_handoffs`, unwrapped only in request memory, and the wrapped key is deleted in the same transaction that records the claim. | 3 | Test asserting the row is gone after a successful claim. |
| B5 | Available only while the relay reports zero admitted principals. The relay exposes a count and nothing else about the roster. | 3 | `bootstrap_instance_enrolled`. |
| B6 | Single use. The genesis key signs exactly one bootstrap invite and the relay destroys it on redemption, so a second claim returns 409 permanently. There is no reissue and no support path that reopens it. | 1 after redemption, 3 before. | `bootstrap_handoff_already_used`. |
| B7 | A crashed response is not replayed with a secret. The operation status says a claim occurred and offers the reprovision remedy. | 3 | Test injecting a response-time crash. |
| B8 | Owner-only, step-up within 15 minutes, rate limited to 5 per minute. | 3 | |
| B9 | Every issuance is recorded in the customer-visible audit log with timestamp and source IP, in an append-only chain with a daily signed checkpoint in a separately permissioned bucket-locked prefix. | 3 | Chain verification test. |
| B10 | The link half is never written to our database, logs or analytics. The post-checkout page holds it in browser session storage for its 24-hour lifetime only. | 3 | Log-scraping test asserting the secret never appears. |
| B11 | The client hard-fails enrollment if the workspace already has an admin. | 3 | This is what turns an invisible attack into a visible one. |
| B12 | `POST /instances/:id/reprovision` within 7 days destroys and replaces the instance on the same subscription at no extra charge. | 3 | |

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
- Store the link half anywhere, for any duration, for any reason.
