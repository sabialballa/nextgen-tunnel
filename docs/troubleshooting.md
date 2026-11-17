# Troubleshooting

1. Run `nextgen-tunnel check -config FILE`. Unknown JSON fields, invalid limits, nonliteral addresses and nonloopback forwarding binds are rejected. TLS paths must be absolute.
2. Verify the backend really listens at the configured fixed target. The tunnel does not install application services or turn a backend failure into a successful probe.
3. Run client `probe`. It validates every configured endpoint. A working TCP path does not establish UDP/QUIC availability. Check both TCP and UDP at the server port in the existing host/provider firewall.
4. Review `journalctl -u nextgen-tunnel --since -10min --no-pager` and `systemctl status nextgen-tunnel`. These commands may expose operational data; review before sharing.
5. Status needs two successful probes before a path becomes ready. Three failed probes plus handshake timeouts/backoff determine failover delay. Status older than ten seconds is reported stale. A healthy backup remains selected until it fails; no automatic failback occurs.
6. A UDP payload above 1150 bytes is dropped and counted. Reduce application datagram size or use a separately validated IP tunnel. UDP-over-TCP can add latency under loss despite successful packet delivery.
7. Correct CA, certificate SAN/server name, client identity, EKU and system clocks. There is no `insecure` switch. Rotate expired certificates securely.
8. A client exits if it cannot atomically write its configured status file. Ensure the parent directory exists and is writable only by the service account. Installer-created state is separate from root-owned installer journals.
9. On a failed update inspect the root-owned transaction journal; recover with `sudo python3 scripts/host_install.py recover --apply`. Never manually flush firewall tables or delete other tunnel services to fix this tool.

Windows runs the Go core and local lab; the privileged Python agent and systemd installer require Linux. Linux-specific tests are skipped explicitly on Windows rather than simulated as passes. Path/IP secrets and old private deployment records are not needed for the local lab.
