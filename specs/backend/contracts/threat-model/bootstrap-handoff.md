# Threat model: the provisioning handoff

The trust-root race. One boundary, one attack, and it is the single highest-risk
edge in the system, because whoever provisions a relay briefly touches a
capability that grants workspace administration.

This document is written for the case where the person who runs the relay and
the person who will administer the workspace are not the same party: a managed
or hosted deployment. If you provision your own relay and enroll your own first
device, the adversary below is you and there is nothing here to defend against.
The relay-side controls still apply, because they are properties of the binary
rather than of any particular operator.

## The attack

The bootstrap invite is a capability to become admin of an empty workspace. A
provisioning operator handles one half of it, which means that operator could, in
principle, use it first: enroll its own device as trust root, then invite the
customer as an ordinary member. The customer would then be inside a workspace
somebody else administers, and could be silently added to groups.

The realistic adversary is an insider at the provisioning operator, or a
compromised provisioning system. Not an outsider on the network.

## Controls, in the order they apply

Controls B1, B2, B4, B7 through B10 and B12 are obligations on a provisioning
operator, and a self-hoster has no use for them. B3, B5 and B6 are enforced by
the relay in this repository and hold whoever provisions it.

| # | Control | Enforced by | Proof |
| --- | --- | --- | --- |
| B1 | The invite is split into two halves delivered over two channels. The link half returns in the provisioning response; the code half goes to an address the operator verified before provisioning began. Neither half enrolls anyone on its own. | Operator | Integration test asserting a single half cannot redeem. |
| B2 | The code destination is an address verified before provisioning and immutable afterwards, rather than one a later billing or profile edit can move. | Operator | Test asserting a profile email change does not move the destination. |
| B3 | The relay seals the link half to an ephemeral per-instance handoff public key supplied at provisioning. The provisioning worker has no code path that decrypts it. | Relay | Test asserting the worker never sees the cleartext half. |
| B4 | The handoff private key is held wrapped, unwrapped only in request memory, and the wrapped key is destroyed in the same transaction that records the claim. | Operator | Test asserting the record is gone after a successful claim. |
| B5 | Available only while the relay reports zero admitted principals. The relay exposes a count and nothing else about the roster. | Relay | `bootstrap_instance_enrolled`. |
| B6 | Single use. The genesis key signs exactly one bootstrap invite and the relay destroys it on redemption, so a second claim is refused permanently. There is no reissue and no support path that reopens it. | Relay | `bootstrap_handoff_already_used`. |
| B7 | A crashed response is not replayed with a secret. The operation status says a claim occurred and offers the reprovision remedy. | Operator | Test injecting a response-time crash. |
| B8 | Owner-only, with a recent re-authentication, and rate limited. | Operator | |
| B9 | Every issuance is recorded in a customer-visible audit log with timestamp and source address, in an append-only chain with a periodic signed checkpoint held under separate permissions. | Operator | Chain verification test. |
| B10 | The link half is never written to a database, log or analytics sink. It lives in the claiming browser for its 24-hour lifetime and nowhere else. | Operator | Log-scraping test asserting the secret never appears. |
| B11 | The client hard-fails enrollment if the workspace already has an admin. | Client | This is what turns an invisible attack into a visible one. |
| B12 | Within a stated window, the customer can have the instance destroyed and replaced at no cost, without asking anyone. | Operator | |

## Residual risk, stated plainly

B1 through B10 make the attack detectable and expensive. They do not make it
impossible. A provisioning system that is fully compromised at the moment of the
claim can read the link half in request memory, and if it also controls the
customer's mailbox it holds both halves.

This is the one place in the system where the answer is not "a key the operator
does not hold". It is bounded by:

- The window is one request, once, per instance, ever.
- It requires compromising two channels, one of which is the customer's own
  verified mailbox.
- It leaves an audit event the customer can read, in a hash chain checkpointed
  into a separately permissioned store.
- The client's hard-fail turns success into a visible dead end rather than a
  silent membership.
- Reprovision gives the customer a remedy that is not an email to support.

Without B11 and B12 the residual risk would be an invisible compromise. With them
it is a visible, remediable one. That difference is the whole reason a reprovision
path exists, and it is why its window is generous rather than tight.

## What an operator must never do

- Reissue a bootstrap invite. A second bootstrap authority is a quieter version
  of the attack this document is about.
- Let the relay report **who** was admitted rather than **whether**. That would
  link an account to a workspace identity, which is the trade the design refuses.
- Add a support path that reopens the handoff. Every request for one is a request
  to reintroduce this attack, however it is phrased.
- Store the link half anywhere, for any duration, for any reason.
