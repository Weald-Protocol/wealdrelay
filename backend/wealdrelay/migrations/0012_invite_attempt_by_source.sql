-- Re-key the invite attempt counter on (token, source), dropping the device.
--
-- The old key was (token, source_hash, device_hash), and `device_hash` is a hash
-- of an arbitrary byte string the joiner supplies in its `Reserve` frame, before
-- any authentication. An attacker holding an invite link sent a fresh random
-- device on every guess, every tuple was new, and the documented five-guesses-
-- per-fifteen-minutes bound on the 60-bit code was unbounded from a single IP.
-- Each guess also ran Argon2id on an unauthenticated path and inserted a fresh
-- row, so the same loop was a CPU lever and an unbounded table.
--
-- The device leaves the key. What remains is the one component the joiner cannot
-- choose (the salted source hash), and the code adds a per-token ceiling across
-- all sources so a distributed guesser is bounded too. Existing rows are
-- collapsed by summing failures per (token, source): the sum is the honest count
-- of wrong codes that source has offered, however many device strings it wore.
create table if not exists relay_invite_attempt_v2 (
    token          bytea       not null references relay_invite (token) on delete cascade,
    source_hash    bytea       not null,
    failures       integer     not null default 0,
    window_started timestamptz not null default now(),
    cooldown_until timestamptz,
    primary key (token, source_hash),
    constraint relay_invite_attempt_v2_source_is_32_bytes check (octet_length(source_hash) = 32),
    constraint relay_invite_attempt_v2_failures_not_negative check (failures >= 0)
);

insert into relay_invite_attempt_v2 (token, source_hash, failures, window_started, cooldown_until)
select token, source_hash, sum(failures), min(window_started), max(cooldown_until)
from relay_invite_attempt
group by token, source_hash;

drop table relay_invite_attempt;
alter table relay_invite_attempt_v2 rename to relay_invite_attempt;
