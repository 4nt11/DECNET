# bait/

Default operator-supplied email seed for IMAP/POP3 deckies. Drop `*.eml` and/or `*.json` files here; the IMAP/POP3 services bind-mount this dir read-only at `/var/spool/decnet-emails/seed` when no per-decky `email_seed` is configured. Entries concatenate onto the hardcoded bait baseline (additive to realism-engine output, never replacing).

JSON shape: list of dicts with required `from_addr`, `to_addr`, `subject`, `body`; optional `from_name`, `date`, `flags`. See `decnet/templates/imap/server.py` for the loader.
