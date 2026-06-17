# Licensing

DECNET is **dual-licensed open core**.

## Community (this repository)

DECNET core — everything in this repository — is licensed under the **GNU Affero
General Public License v3.0 or later (AGPL-3.0-or-later)**. See [LICENSE](./LICENSE).

AGPL (not GPL) is deliberate: DECNET is a network-deployed honeypot platform, so
the AGPL §13 network-use clause matters — anyone who offers DECNET to others over
a network must make their source available. GPLv3 would leave that loophole open.

## Commercial / Professional

Because the DECNET Foundation holds copyright in the core, the core is **also
available under a commercial license**. A commercial core license is what lets
the proprietary **DECNET Professional** add-on (advanced honeypots, distributed
separately) be combined and shipped with the core without triggering the AGPL's
copyleft obligations.

DECNET Professional itself is closed source, licensed under the
[DECNET Commercial EULA](https://github.com/DECNET-Foundation/decnet-professional),
and is **not** part of this repository. The open-core build neither contains nor
depends on it.

| Tier         | Code                                   | License                    |
|--------------|----------------------------------------|----------------------------|
| Community    | this repo                              | AGPL-3.0-or-later          |
| Professional | `decnet/services/pro/` (private repo)  | DECNET Commercial EULA     |

To use DECNET core under terms other than the AGPL, or to obtain DECNET
Professional, contact **licensing@decnet.cl**.

## Contributing

Contributions to the core are accepted under the AGPL. Because the project is
dual-licensed, contributors must agree that their contributions may also be
distributed under the commercial license (a CLA / DCO sign-off). Relicensing
requires that the Foundation hold or be granted rights to all contributed code.
