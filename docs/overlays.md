# GRE, VXLAN and IPIP inside the TCP-backed site

These optional overlays run inside the existing owned `ngt-site-main` namespace. The public Iran–Turkey carrier remains REALITY/smux over TCP443. GRE packets and VXLAN datagrams are carried inside WireGuard, whose local UDP endpoint is forwarded through that TCP carrier. No public GRE or VXLAN port is opened, no physical LAN is bridged, and host routes, firewall and forwarding are left alone.

Use GRE for an additional routed IPv4 point-to-point interface. VXLAN provides a point-to-point Ethernet interface with a fixed unicast peer and learning disabled. IPIP provides IPv4-in-IPv4 on a separate point-to-point subnet. The current helper assigns IPv4 only; it does not configure LAN bridges, NAT or Internet egress. These layers add encapsulation and do not repair delay in the underlying TCP connection.

The Linux kernel supplies GRE, VXLAN and IPIP. Creation options follow the [iproute2 manual](https://man7.org/linux/man-pages/man8/ip-link.8.html). The helper binds each overlay to the existing owned WireGuard interface, requires the peer route to use that interface, rejects overlapping addresses/routes and checks the MTU budget. With an IPv4 underlay, the configured maximum is parent MTU minus24 bytes for basic GRE, minus50 for VXLAN Ethernet framing or minus20 for IPIP. Examples use MTU1200 under the site's MTU1280, without VLAN tags. IPv6 payload support is not enabled by these examples; an IPv6-ready MTU requires a different validated parent MTU plan.

## Install on each endpoint

Prerequisites: Linux, systemd, Python3, iproute2, an already installed and active owned `nextgen-site.service`, and a working TCP-backed engine. Use matching examples from `configs/examples/overlays/`. The examples assume site addresses10.77.240.1/.2; change them to your actual private endpoints. Both peers must use matching overlay subnets, VNI and destination port, with opposite local/remote addresses. Both features can coexist on separate subnets.

```sh
# First endpoint; inspect the plan before applying.
python3 scripts/overlay_service.py install --config configs/examples/overlays/gre-a.json
sudo python3 scripts/overlay_service.py install --config configs/examples/overlays/gre-a.json --apply
sudo python3 scripts/overlay_service.py install --config configs/examples/overlays/vxlan-a.json --apply
sudo python3 scripts/overlay_service.py install --config configs/examples/overlays/ipip-a.json --apply
# Use gre-b.json, vxlan-b.json and ipip-b.json on the second endpoint.
```

The installer creates independent services `nextgen-overlay-ngo-gre.service`, `nextgen-overlay-ngo-vxlan.service` and `nextgen-overlay-ngo-ipip.service`. They require and start after `nextgen-site.service`, stop with it, and are enabled at boot. Each has its own root-owned config, helper and file-hash manifest. It does not edit the permanent stack's files or adopt unknown interfaces. Same-config installation is idempotent; changed configs or owned files are refused. Change a config by removing the original service first.

Run applications inside the namespace, for example:

```sh
sudo ip netns exec ngt-site-main ping -M do -s1172 10.78.250.2
sudo ip netns exec ngt-site-main ping -M do -s1172 10.78.251.2
sudo ip netns exec ngt-site-main ping -M do -s1172 10.78.252.2
sudo python3 scripts/overlay_service.py status --config configs/examples/overlays/gre-a.json
sudo systemctl restart nextgen-overlay-ngo-vxlan.service
```

Only applications using the overlay addresses use these extra layers. Existing applications using10.77.240.1/.2 continue using the base site directly. Nothing automatically redirects host or Internet traffic to GRE/VXLAN. A physical LAN bridge needs a separate explicit topology and address plan.

## Remove and recover

```sh
sudo python3 scripts/overlay_service.py remove --config configs/examples/overlays/vxlan-a.json --apply
sudo python3 scripts/overlay_service.py remove --config configs/examples/overlays/gre-a.json --apply
sudo python3 scripts/overlay_service.py remove --config configs/examples/overlays/ipip-a.json --apply
```

Stop/remove overlays before manually removing their parent site. The repository's `site.py` refuses to remove a namespace containing `ngo-` interfaces. Older deployed site helpers may lack that guard; use the service lifecycle and remove overlays first. Uninstall verifies owned file hashes before stopping or deleting anything. A systemd stop/start removes and recreates only the owned overlay. A different boot permits recreation of matching stale overlay state after the owned parent site has recovered. Incomplete same-boot state or mismatched ownership requires inspection, rather than deleting an unidentified interface. If installation fails and stopping cannot be verified, its manifest/files are retained for inspection.

## Field validation and limits

Version0.1.0 originally validated GRE/VXLAN for30seconds each and did not reboot the hosts; the old [field evidence](evidence/overlay-field.json) is preserved. Version0.2.0 adds IPIP and a concurrent3600second-per-node comparison of GRE, VXLAN, IPIP and the base site. The [hour/reboot evidence](evidence/overlay-hour-comparison.json) supersedes the earlier limited recovery claim.

All four TCP paths had no errors in the full hour. All three overlays failed the unchanged UDP500ms deadline loss/burst criteria; the base path also failed. IPIP had the lowest aggregate deadline-miss count in this sample, but differences were small on a shared physical carrier, and no lasting stability advantage was established. Late responses are counted separately; deadline misses do not establish permanent packet loss. The existing main engine and link identities remained stable during the hour.

Turkey and then Iran were actually rebooted after the hour. Both had changed boot IDs, automatically active+enabled main/site/watchdog and all three overlay services, and unchanged owned file hashes and host routes/firewall/forwarding. No permanent service was manually started. Each reboot was followed by authenticated30second TCP/UDP tests on all four paths on both nodes; connectivity returned everywhere, while UDP deadline misses persisted. Reboot elapsed values are observation bounds, not exact downtime measurements. Temporary probes/echo credentials and helpers were removed; the three installed overlay services remain enabled.

These results do not establish production stability, physical path diversity or DPI resistance. GitHub publication remains deferred. The0.2.0add-on archive contains Python helpers, six example configs and both evidence reports; it leaves the existing rc3 core/engine and0.1.0archives unchanged. Applications must explicitly use the overlay addresses within the site namespace; host, LAN and Internet traffic is not automatically redirected.
