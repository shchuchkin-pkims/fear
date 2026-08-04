# Licensing

F.E.A.R. is free software. The project ships both a network **server** and
end-user **clients**, and they carry different licenses.

| Component | Path | License |
|---|---|---|
| Relay server + console binary | `client-console/` | AGPL-3.0-or-later |
| Identity / key schedule (linked into the server binary) | `identity/` | AGPL-3.0-or-later |
| Server container image | `Dockerfile` | AGPL-3.0-or-later |
| Web bridge (Express + WebSocket proxy) | `web/server.js`, `web/package.json` | AGPL-3.0-or-later |
| Desktop GUI client (Qt) | `gui/` | GPL-3.0-or-later |
| Audio calls | `audio_call/` | GPL-3.0-or-later |
| Video calls | `video_call/` | GPL-3.0-or-later |
| Key exchange (client side) | `key-exchange/` | GPL-3.0-or-later |
| Updater | `updater/` | GPL-3.0-or-later |
| Browser client | `web/public/` | GPL-3.0-or-later |
| Tests | `tests/`, `build-tests/` | GPL-3.0-or-later |

Anything not listed above falls under the repository default: **AGPL-3.0-or-later**.

Full texts: [`LICENSE`](LICENSE) (AGPL-3.0) and [`LICENSE.GPL-3.0`](LICENSE.GPL-3.0) (GPL-3.0).

## Why the split

The **server** is offered to users over a network. Section 13 of the AGPL-3.0
requires anyone who runs a modified server as a service to publish their
modifications. For an end-to-end encrypted messenger this is a security
property, not merely a licensing preference: the server sees metadata and takes
part in key exchange, so users must be able to verify that the server they
connect to matches the published source.

**Clients** run on the user's own machine and are not offered as a network
service, so the plain GPL-3.0 is sufficient.

## Note on the `fear` binary

`client-console/` builds a single executable that acts both as the relay
(`fear server`) and as the console client. One binary cannot carry two
licenses, so the entire directory is AGPL-3.0-or-later. In practice the AGPL
and the GPL impose identical obligations on software that is not offered over a
network, so this does not restrict console-client users.

Section 13 of the GPL-3.0 explicitly permits linking GPL-3.0 code with the
AGPL-3.0 components of this repository.

## Third-party components

Third-party libraries keep their own licenses. Of note:

- **Qt 6** (Widgets, Network, Sql, Concurrent) - LGPL-3.0
- **FFmpeg** - LGPL-2.1-or-later, or GPL-2.0-or-later when built with `--enable-gpl`
- libsodium (ISC), SQLite (public domain), Opus (BSD), PortAudio (MIT),
  SDL3 (Zlib), libcurl (MIT-style), libvpx (BSD)

See the Acknowledgements page in the project wiki for the full list.

## Copyright

Copyright (C) 2025-2026 F.E.A.R. Messenger Project.

The copyright holder reserves the right to distribute this software under other
terms, including commercial licenses. Contributions are accepted under the
licenses listed above.
