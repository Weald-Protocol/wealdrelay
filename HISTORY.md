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

At the split commit the build context was byte-identical to the monorepo's,
verified with `scripts/repro-context-digest.py` against both trees: an image
built from either tree produced the same digest, so the move did not silently
change what ships. That was a check on the move rather than a promise about the
future, and the two trees diverge from here. What replaces it is stronger and is
not about us: every release digest is one that two independent runners and a
clean clone of the tag all produced, and `scripts/relay-reproduce.sh` lets you be
a fourth.
