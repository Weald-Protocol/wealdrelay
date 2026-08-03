# ADR-0004: The bootstrap invite is split across two channels

- Status: accepted
- Date: 2026-06
- Source: `specs/backend/contracts/threat-model/bootstrap-handoff.md`,
  `specs/backend/relay/invites.md`

## Context

A freshly provisioned relay has an empty roster. The first device to redeem the
bootstrap invite self-admits and becomes the workspace trust root, permanently.
That invite is therefore a capability to administer the workspace.

On a hosted instance, something other than the customer's laptop takes part in
delivering it, because the customer has not enrolled yet and there is nothing
else to deliver it to. Whatever handles delivery could in principle redeem it
first, enroll its own device as trust root, and invite the paying customer in as
an ordinary member. This is the single highest-risk edge in the system: not
because it is likely, but because success would be invisible and permanent.

## Decision

The bootstrap invite is split into two halves delivered over two channels, and
neither half enrolls anyone on its own.

- The link half is sealed to an ephemeral per-instance handoff public key that
  the relay is given at provisioning time. Whatever provisions the instance
  never holds the private key in durable storage and has no code path that
  decrypts it.
- The code half travels to an address verified before purchase, independently of
  the API response that carries the link half.
- The invite is available only while the relay reports zero admitted principals,
  is single use, and is destroyed on redemption. A second claim fails
  permanently. There is no reissue path and no support path that reopens one.
- The relay exposes the admitted-principal count and nothing else about the
  roster, so the availability window can be checked without learning who is in
  it.
- A client hard-fails enrollment if the workspace already has an admin.

Self-hosting has no second channel and needs none: the invite is printed to the
operator's own log on first boot, so the operator is already the customer.

## Rationale

The controls do not make the attack impossible, and the threat model says so in
those words. They make it require two channels at once, one of which is the
customer's own mailbox, inside a one-request window that occurs once per
instance ever, while leaving an audit record the customer can read.

The hard-fail is what carries the decision. Without it a successful attack looks
like a normal workspace. With it, success is a visible dead end, and a visible
dead end has a remedy: destroy and replace the instance.

## Consequences

- Provisioning is a handoff rather than a setup step. The provisioner arranges
  for the customer to become trust root, and cannot become one itself.
- There is exactly one place in this system where the answer is not "a key we do
  not hold", and it is written down as such rather than rounded up.
- A crashed response is never replayed with a secret in it. The remedy is
  reprovision, not resend.
- The relay side of this is unconditional: it is the same binary and the same
  refusals whether or not anything hosted is involved.

## Rejected

A single delivery channel, with the provisioner trusted not to look. That is a
promise about an operator's conduct, which is the class of claim this product
exists to avoid making.
