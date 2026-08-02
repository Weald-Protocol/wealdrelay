# On this repository's history

The relay was developed inside a private monorepo alongside the Weald macOS
client, and its history is interleaved with that client's throughout. This
repository therefore starts at a single commit rather than carrying that history
across.

That was a deliberate choice and not a convenience. Rewriting the monorepo's
history to extract only the relay's commits would mean filtering thousands of
commits and betting that nothing proprietary survived in a blob, a merge, or a
reverted change. A rewrite that misses one object publishes it permanently. The
value of the recovered history did not justify a mistake that cannot be undone.

What is preserved is everything that lets you check the code rather than trust
it: the full specifications, the conformance vectors, the reproducible build
tooling, and the release pipeline that signs a digest two independent runners
and a clean clone all agree on.

The build context is byte-identical to the monorepo's at the point of the split,
verified with `scripts/repro-context-digest.py` against both trees. Images built
from this repository and from the monorepo at the same commit produce the same
digest, so the move did not silently change what ships.
