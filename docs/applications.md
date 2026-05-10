# Applications

VOS is a substrate. Concrete applications live on top of it as groups
of actors and services arranged into spaces.

This part of the book is where each application gets its own slice —
its motivation, its data model, its threat model, its concrete actors,
and the integration points with the rest of the platform.

## Currently documented

- **[Kunekt](kunekt.md)** — Private-by-default real-time collaboration.
  The application VOS was originally shaped around: CRDT documents +
  group encryption + untrusted persistence + anonymity-preserving
  authorization. Most of the early VOS design pressure came from
  Kunekt's requirements.

## How to add an application here

1. Add a top-level `<app>.md` overview chapter alongside this one.
2. Add a sub-list under it in [`SUMMARY.md`](SUMMARY.md) for any
   per-application chapters.
3. Keep platform-level details (the PVM, replication, networking)
   in Part I and link to them from the application chapters rather
   than re-explaining.
