# Preliminary protocol research

This is an engineering shortlist, **not** a measured ranking or completed DPI audit. Primary upstream metadata, latest release, source HEAD and three recent issue/PR references were captured on 2026-11-16. The fetcher is `scripts/research.py`; [the compact evidence](evidence/upstreams.json) records results and gaps. Issue samples include PRs and do not prove absence of bugs. Release API HTTP 404 for WireGuard-go and AmneziaWG does not imply absence of version tags. Only quic-go source has been inspected in detail for the implemented adapter; full source/security review of every candidate remains pending.

| Candidate | Primary references / observed release | Implications and benchmark status |
|---|---|---|
| Hysteria 2 | [Protocol](https://v2.hysteria.network/docs/developers/Protocol/), [upstream](https://github.com/apernet/hysteria), app/v2.14.0 | QUIC streams/datagrams; certificate and auth required. HTTP/3-like behavior is not proof of DPI resistance. Not benchmarked here. |
| TUIC | [Specification](https://github.com/tuic-protocol/tuic), tuic-server-1.0.0 | Select implementation separately from specification; review early-data replay properties. Not benchmarked. |
| WireGuard | [Protocol](https://www.wireguard.com/protocol/), [Go mirror](https://github.com/WireGuard/wireguard-go) | Native IP tunnel; UDP availability and identifiable behavior remain constraints. Historical legacy results are not a fair current comparison. |
| AmneziaWG | [Source](https://github.com/amnezia-vpn/amneziawg-go) | Pin peer versions and obfuscation parameters together. Randomization does not prove indistinguishability. Not benchmarked. |
| QUIC baseline | [quic-go](https://github.com/quic-go/quic-go), pinned v0.65.0 | Local DATAGRAM path implemented. Go minimum 1.26; final local toolchain 1.27.4. Requires successful vulnerability review before production. |
| MASQUE | [RFC 9298](https://www.rfc-editor.org/rfc/rfc9298.html), [masque-go](https://github.com/quic-go/masque-go), v0.6.0 | HTTP UDP proxying needs correct capsules/datagrams, authorization and deployment compatibility. Not implemented/tested. |
| VLESS + REALITY | [Xray](https://github.com/XTLS/Xray-core), [docs](https://xtls.github.io/en/config/transports/reality.html), v26.11.9 | Validate version-specific identity, target and transport settings. Not implemented/tested in new core. |
| XHTTP | [Official docs](https://xtls.github.io/en/config/transports/xhttp.html) | HTTP versions, CDN behavior and upload/download modes matter. Not benchmarked. |
| TLS 1.3 | [Go TLS](https://pkg.go.dev/crypto/tls) | Implemented baseline with dedicated mutual TLS. No public domain/public CA necessary. Identifiable fingerprint; DPI resistance unverified. |
| WebSocket / HTTP2 over TLS | [Xray transports](https://xtls.github.io/en/config/transport.html) | Domain, certificate, path and proxy must match. UDP framing over reliable streams inherits HOL. Not benchmarked. |
| AnyTLS | [Source](https://github.com/anytls/anytls-go), v0.0.13 | Padding and pooling are implementation-specific. A TLS wrapper alone is not AnyTLS. Not benchmarked. |
| Trojan | [Source](https://github.com/trojan-gfw/trojan), v1.16.0 | Review maintenance, fallback behavior and certificate deployment. Release age alone does not establish insecurity. Not benchmarked. |
| Phantun | [Source](https://github.com/dndx/phantun), v0.8.1 | Fake TCP needs routing/TUN/firewall integration; it is not encryption or ordinary reliable TCP. Not benchmarked locally. |
| udp2raw | [Source](https://github.com/wangyu-/udp2raw), 20230206.0 | Carrier under legacy WireGuard; raw socket privileges and firewall interactions require review. Historical tests are not comparable with new loopback numbers. |

Go was chosen for standard TLS/network libraries, memory safety, cross-compilation and race tooling. Rust is viable but adds another async/build stack; no comparative Go/Rust performance claim is made.

QUIC and TLS are **provisional measurement baselines**, not selected winners for Iranian DPI. A small fixed-target framing layer makes repeatable tests possible without inventing cryptography. Hysteria/Xray/MASQUE adapters remain pending. No custom padding, packet randomization, migration, pooling or multipath is enabled speculatively. Keepalive and authenticated heartbeat exist; their fingerprint and CPU cost require field measurement.

TLS fingerprint compatibility, active probing, timing/length distributions, DNS/IPv6 policy and actual Iranian-network blocking remain **Not Verified**. Controlled measurements of each candidate on the same route must precede the final production protocol choice.
