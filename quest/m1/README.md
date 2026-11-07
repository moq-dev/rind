# m1: MoQ coverage and Bun

## Goal

rind carries everything [MoQ](https://github.com/moq-dev/moq) needs to take
all its cryptography from rind, on every target MoQ releases, and publishes it.
Bun's fastest asymmetric operations run on rind, ahead of Bun writing its own.

## Required

- [Bun runs its fastest asymmetric crypto on rind](/quest/m1/bun.md) - Ed25519, X25519, P-384, and P-521 in Bun on rind, before Bun writes its own
- [The launch post can say what building rind cost in AI tokens, time, and money](/quest/m1/ai-usage.md) - tokens, agent and maintainer hours, and API-price cost, before the post
- [rind's launch blog post is published](/quest/m1/launch-post.md) - the Bun PR waits on it
- [rind covers MoQ](/quest/m1/moq/README.md) - the primitives, CPU check, armv7 backend, and `rind-*` adapters MoQ needs, verified and released
