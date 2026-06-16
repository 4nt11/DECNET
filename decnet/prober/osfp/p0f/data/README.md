# p0f v2 fingerprint database (vendored)

This directory contains the p0f v2.0.8 TCP/IP fingerprint database as
published by Michal Zalewski in 2006, vendored here so DECNET's prober
and profiler can do passive / active OS fingerprinting without a runtime
network fetch.

## What's in here

| File                  | Purpose                                       | Sigs |
|-----------------------|-----------------------------------------------|------|
| `p0f.fp`              | SYN fingerprints (passive, incoming)          | 262  |
| `p0fa.fp`             | SYN-ACK fingerprints (active probe responses) |  61  |
| `p0fr.fp`             | RST+ fingerprints (reset-response quirks)     |  46  |
| `p0fo.fp`             | "stray" fingerprints                          |   6  |
| `LICENSE.p0f-upstream`| Verbatim LGPL-2.1 text from upstream          | —    |

## Provenance

**Authoritative source:** Debian snapshot archive, `p0f_2.0.8.orig.tar.gz`.

- Archive URL: `https://snapshot.debian.org/archive/debian-archive/20120328T092752Z/debian/pool/main/p/p0f/p0f_2.0.8.orig.tar.gz`
- SHA-1 (upstream-recorded by Debian): `7b4d5b2f24af4b5a299979134bc7f6d7b1eaf875`

Files in this directory are byte-identical copies of the corresponding
files inside `p0f_2.0.8.orig.tar.gz::p0f/{doc/COPYING, *.fp}`.

## License + DECNET-side licensing stance

Upstream files are licensed under the **GNU Lesser General Public
License, version 2.1** (see `LICENSE.p0f-upstream` — verbatim copy of
upstream's `doc/COPYING`). Attribution belongs to Michal Zalewski and
the named contributors in the original upstream `CREDITS` file.

DECNET is licensed under **GPL-3.0-or-later**. LGPL-2.1 §3 explicitly
permits converting an LGPL-2.1 work to any version of the GPL at the
recipient's choice. DECNET exercises that conversion for the vendored
files: when consumed as part of DECNET they are effectively under
GPL-3.0. The upstream LGPL-2.1 notice is preserved so:

- Recipients of DECNET see the full chain (original LGPL-2.1 → §3
  conversion → GPL-3.0), and
- Anyone who wants to use these signatures under LGPL-2.1 terms
  (e.g. in an unrelated library) can still do so by pulling the files
  directly from upstream.

## Modifications to upstream

**None.** The four `.fp` files in this directory are verbatim copies.
Any DECNET-authored additions go into a sibling file (`p0f-decnet.fp`,
currently absent) under GPL-3.0, loaded by the same parser. Keeping
upstream untouched means:

1. Syncing future upstream changes is a one-step file replacement.
2. Attribution is unambiguous: entries in `p0f*.fp` here are Michal's,
   entries in `p0f-decnet.fp` are DECNET's.
3. If we ever want to contribute signatures back to upstream, it's a
   one-file diff.

## Refreshing upstream

```
curl -O https://snapshot.debian.org/archive/debian-archive/20120328T092752Z/debian/pool/main/p/p0f/p0f_2.0.8.orig.tar.gz
echo "7b4d5b2f24af4b5a299979134bc7f6d7b1eaf875  p0f_2.0.8.orig.tar.gz" | sha1sum -c
tar xzf p0f_2.0.8.orig.tar.gz
cp p0f/p0f.fp p0f/p0fa.fp p0f/p0fr.fp p0f/p0fo.fp decnet/prober/osfp/p0f/data/
cp p0f/doc/COPYING decnet/prober/osfp/p0f/data/LICENSE.p0f-upstream
```

p0f v2 is no longer actively maintained upstream (last release 2006),
so refreshes are effectively N/A — but the procedure is recorded for
the case where a mirror we trust publishes a signed rebuild.
