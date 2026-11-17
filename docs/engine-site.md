# Optional engine and isolated sites

Optional [GRE and VXLAN overlays](overlays.md) add owned interfaces inside the existing TCP-backed site. Their separate installer manages boot ordering and removal without editing the engine/site stack.

The native installer manages the Go core. The separate transactional stack installer manages the optional engine, WireGuard site and client recovery timer together. Core bundles exclude the engine; the Linux amd64 `-full` bundle includes its verified binary, GPL license and matching offline corresponding source. Neither bundle includes deployment credentials.

## Permanent isolated site

Use Linux with systemd, Python 3, iproute2 and wireguard-tools. Generate a protected engine profile with the commands below. Keep the CA and listener private keys on the listener. Send only `client.json` and the public CA to the initiator over authenticated SSH, then adjust its CA path. On each node derive the bounded carrier:

```sh
# Listener, from the generated server JSON:
python3 scripts/stack_prepare.py --role listener --redundant --source /private/configs/server.json --output /private/carrier.json
# Initiator, from the exported client JSON:
python3 scripts/stack_prepare.py --role initiator --redundant --source /private/client.json --output /private/carrier.json
```

The default selects REALITY with smux and authenticated TLS. Before preparing the listener, replace the generated laboratory REALITY handshake target with a literal IPv4 target that actually serves compatible TLS 1.3 for its configured server name; verify its certificate and test REALITY authentication. `stack_prepare.py` refuses a loopback target. With `--redundant`, the listener accepts only forwarding to `127.0.0.1:51851`; its local relay forwards to WireGuard port 51850. The initiator exposes only UDP `127.0.0.1:51811`. Configure both roles consistently. There is no automatic protocol switching in this profile. `--transport hysteria2-gecko` selects an experimental alternative: short tests succeeded, but its permanent field reboot acceptance failed.

The rc3 bidirectional candidate requires core 0.3.0-rc3 or later and `--redundant` on both roles. The initiating profile defaults to two independent REALITY TCP connections. `--carriers 3` or `--carriers 4` selects an experimental larger set; four carriers did not establish strict UDP field stability and are not the default. The installer derives a loopback relay. WireGuard authenticates the duplicated encrypted datagrams and rejects replayed copies. All carriers share one physical network path; this cannot supply independent provider diversity or repair complete path loss. Two copies approximately double useful WireGuard traffic in each direction; four copies approximately quadruple it, plus transport overhead. Check STATUS.md before deployment.

UDP application traffic in this profile already crosses the public Iran–Turkey link inside REALITY/smux TCP connections on port 443. The UDP sockets used by WireGuard and the relays are local to each host or isolated namespace; they do not require a public UDP carrier between the two servers. The direct UDP echo on port 29401 in lab comparisons is a separate temporary control, not a production fallback. A reported site UDP deadline miss therefore means an application datagram carried over TCP missed its deadline; it does not imply that the public carrier used UDP. UDP-over-TCP can still have delayed datagrams, and this profile has not passed the field deadline criteria. The separately tested Trojan/TLS alternative also used TCP and did not establish a stability improvement.

The initiating relay accepts packets only from its configured WireGuard socket. The passive listener pins WireGuard to one local UDP socket and fans replies out to up to four recently active loopback carrier endpoints; this prevents last-arriving-carrier endpoint roaming from removing reverse redundancy. Its peer cache expires after 30 seconds and queues are bounded to 64 datagrams per carrier with 100 ms socket write deadlines. It filters WireGuard packet shapes; cryptographic authentication remains in WireGuard. Use dedicated hosts with trusted local users: the passive loopback relay does not authenticate local processes. Do not expose relay ports publicly.

Generate independent WireGuard keys on each node with `site.py keygen --directory /private/wg`. Exchange only public keys. A listener site JSON follows; replace the peer key, keep the file root-only, and choose non-overlapping addresses:

```json
{
  "name": "ngt-site-main",
  "private_key_file": "/private/wg/private.key",
  "peer_public_key": "REPLACE_WITH_INITIATOR_PUBLIC_KEY",
  "addresses": ["10.77.240.1/30", "fd77:240::1/126"],
  "remote_routes": ["10.77.240.2/32", "fd77:240::2/128"],
  "listen_port": 51850,
  "redundant_listener_port": 51851,
  "mtu": 1280
}
```

On the initiator use its own local key, listener's public key, local `.2`/`::2` addresses and remote `.1/32`/`::1/128` routes. Remove `redundant_listener_port`, set `listen_port` to 51860, add `"endpoint": "127.0.0.1:51811"` and `"persistent_keepalive": 1`. Only the listener has `redundant_listener_port`, matching the generated engine destination; it has no endpoint field. For a different `--remote-wg-port`, the redundant listener relay port is that port plus 1. The optional PSK is described below. Check both engine configs before installation:

```sh
bin/nextgen-tunnel engine-check -binary "$PWD/bin/sing-box" -sha256 606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf -config /private/carrier.json
sudo python3 scripts/stack_install.py install \
  --binary "$PWD/bin/nextgen-tunnel" --sha256 CORE_HASH_FROM_SHA256SUMS \
  --engine "$PWD/bin/sing-box" --engine-sha256 606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf \
  --engine-config /private/carrier.json --site-config /private/site.json --apply
```

Use `status` to verify owned listeners and services. Use `update` with the same input arguments for changes, `recover --apply` after an interrupted transaction, or `uninstall --apply` after stopping namespace applications. Without `--apply`, operations show preflight only. Uninstall retains protected backups. Do not alter installed owned files manually: hashes prevent accidental replacement. The engine runs as a dynamic unprivileged user; systemd loads protected credentials. The privileged site service owns the namespace and the bounded recovery timer may rekey its configured initiating peer or restart its carrier after repeated failed probes.

Applications run through `sudo ip netns exec ngt-site-main COMMAND`. This supplies a routed site between isolated application namespaces. Physical LAN forwarding, NAT, Internet egress and host default routes need a separate explicit routing plan. Installation does not change host routes, firewall, forwarding sysctls or SSH.

Build with Go 1.27.4 and Git:

```sh
python3 scripts/build_engine.py --output /absolute/private/sing-box
```

This pins upstream commit `c005f35300ce76427dc285481ec5695f5b179cd2`, applies the included dependency patch, verifies modules and builds Linux with `with_quic,with_utls`. The reproduced amd64 binary has SHA256 `606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf`. Review its manifest and scan the exact output before use. Preserve upstream GPL license and corresponding source when redistributing an engine build. The MIT core does not incorporate that binary.

Generate a new protected profile using `nextgen-tunnel engine-init -dir /absolute/private/profile -server-ip LITERAL_IP -server-name SERVER_IDENTITY`. Edit ports, literal REALITY handshake target, server name, allowed destination CIDRs and health URL before `engine-plan -profile /absolute/private/profile/profile.json -output /absolute/private/configs`. The REALITY target must actually serve compatible TLS for the chosen name. Its generated loopback handshake target is a laboratory default.

Do not transfer the whole profile to the client: it contains server and CA private keys. Transfer only generated client JSON and the public CA over an authenticated channel, and adjust the client's CA path. Restrict configs to root. Generated server CIDRs allow all destinations to an authenticated engine client, including private/loopback services; narrow them to the intended policy.

Run `engine-check` or `engine-run` with absolute `-binary`, trusted `-sha256` and `-config` arguments. Linux TUN additionally needs root and an explicitly owned namespace:

```sh
sudo python3 scripts/namespace.py create --name ngt-apps --apply
sudo nextgen-tunnel engine-run -binary /absolute/private/sing-box -sha256 TRUSTED_HASH -config /absolute/private/client.json
```

Run applications with `sudo ip netns exec ngt-apps COMMAND`. This namespace has no physical/veth underlay; stopping the engine removes its egress. DNS is namespace-specific. Stop applications and engine before `namespace.py remove --name ngt-apps --apply`. This lifecycle is not integrated into the native installer's service account or crash journal.

`scripts/site.py` requires Linux kernel WireGuard, `wireguard-tools` and `iproute2`. Generate a separate key on each node with `site.py keygen --directory NEW_PRIVATE_DIRECTORY`; exchange only `public.key`. Private JSON config fields are `name` starting `ngt-site-`, absolute `private_key_file`, `peer_public_key`, `addresses`, explicit `remote_routes`, `listen_port`, and MTU 1280–1420. Optional `preshared_key_file` adds a separately shared private key. The initiating node's `endpoint` must be a loopback UDP carrier address. The remote peer learns its endpoint through authenticated WireGuard traffic.

Create with `sudo python3 scripts/site.py create --config /absolute/site.json --apply`. Run site applications through `ip netns exec SITE_NAME COMMAND`. Inspect with `site.py status --name SITE_NAME`. Stop namespace applications before `site.py remove --name SITE_NAME --apply`; original key files remain protected. The tool does not connect physical LANs, enable host forwarding, or change host routes/firewall. Physical LAN integration needs a separate routing plan; acceptance uses routed addresses inside two site namespaces.

The loopback carrier forwards UDP to the remote WireGuard listener over an authenticated engine path. `scripts/lab/field_client.py` creates bounded field-test carriers; `--site-target-port` chooses the remote listener. `udp_carrier.py` supplies an uncamouflaged direct WireGuard baseline and no encryption of its own. These are test helpers, not a production installer.

The successful field arrangement initiated REALITY from Turkey to the listener in Iran. Turkey's WireGuard peer used the local carrier endpoint; Iran's WireGuard peer learned its loopback endpoint from authenticated traffic. This carried bidirectional site traffic, including connections initiated inside the Iranian site. Initiating the outer transport in Iran had failed sustained tests. A generated engine profile accepts either node's literal IP; no protocol-role inference should be made from the country's name. Transfer only client-side auth and public CA, never the listener's private profile. This arrangement is not a reverse Internet proxy or automatic physical LAN integration. See [measured limits](STATUS.md).
