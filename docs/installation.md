# Local build and Linux installation

Build with a maintained Go toolchain and a verified module graph. The local binary is installed offline; no `curl | sh`, remote binary execution or automatic package upgrades occur. Cross-build using `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o dist/nextgen-tunnel-linux-amd64 ./cmd/nextgen-tunnel` (PowerShell users set environment variables separately). Use `arm64` for aarch64.

Offline archives contain `bin/nextgen-tunnel` (or `.exe`), source, scripts, notices and an internal `SHA256SUMS`. Verify the archive against a trusted external checksum first, then check the internal manifest. From an extracted Linux bundle pass `--binary ./bin/nextgen-tunnel` to the installer and use that member's SHA256 from the verified manifest. Paths under `dist/` in development instructions refer to the source workspace, not the extracted bundle.

Create a dedicated PKI with `nextgen-tunnel pki -dir NEW_DIRECTORY`. It refuses an existing directory. Endpoint certificates last 90 days; the CA lasts one year. Rotate before expiry, distribute new trust securely and restart in a maintenance window. There is no automatic certificate renewal or revocation service. Keep the CA key offline. Windows file modes do not enforce POSIX permissions: protect the local PKI with appropriate Windows ACLs and do not store it in a shared directory.

For rotation, place new material in separate source paths and run the explicit update command with a config referring to those sources. Do not edit installer-owned destination files in place; ownership hashes intentionally reject unexpected edits.

Configure examples with absolute certificate paths. Install the exit/server first, then entry/client. Both transports share the configured TCP/UDP port on the server. TLS identity is `tunnel.internal` by default and does not require public DNS when using the private CA. Target addresses are literal IPs. Existing services must already be listening. Local forwarding listeners are loopback-only. Public exposure requires a separately reviewed deployment; it is not done by the installer.

Run `sh scripts/install.sh --binary BINARY --sha256 HASH --config CONFIG` to review read-only inventory. Add `sudo` and `--apply` to install. The allowlisted OS/version check currently accepts Ubuntu 22.04/24.04 and Debian 12/13, x86_64/aarch64 ELF64 binaries. These are intended targets, not a claim that clean installation has been tested on every target.

The installer inspects listeners, routes, active services, SSH status and nftables when available. It never changes firewall, route, kernel tunables, SSH configuration or another VPN. Missing nftables inspection is reported. Port conflicts fail startup and trigger rollback, rather than killing another process. Keep independent SSH/console access for real deployment. A server's post-install service check is not a remote connectivity test; run client `probe` afterward. Client install requires every configured endpoint's encrypted probe to pass.

Owned paths:

- `/usr/local/bin/nextgen-tunnel`
- `/etc/nextgen-tunnel/{config.json,ca.crt,cert.crt,endpoint.key}`
- `/etc/systemd/system/nextgen-tunnel.service`
- Root-owned installer journal, ownership hashes, backups and preflight under `/var/lib/nextgen-tunnel-installer`
- Service-owned status under `/var/lib/nextgen-tunnel`

Unmanaged existing targets and unexpected edits to owned files are refused. Existing service accounts without the installer's account ownership record are refused. A repeat installation with identical inputs is unchanged and requires the service to be active. Use `sh scripts/update.sh` with the same binary/hash/config flags and `--apply` for explicit changes. Updates interrupt established sessions; no zero-downtime promise is made.

Changes are backed up before writing; a root-owned journal permits `sudo python3 scripts/host_install.py recover --apply` after a crash. An installation/startup/probe failure invokes rollback automatically. If rollback itself fails, retain the journal and recover through the console. The service account and empty directories remain after rollback to avoid deleting shared state. No timer-based SSH rollback is needed for this installer because it changes no routes/firewall; this does not make arbitrary operator firewall changes safe.

Use `sudo sh scripts/uninstall.sh --apply` to stop the owned service and remove only exact owned files after hash verification. Backups, state and the service account remain. Private keys can remain inside protected backups; operator retention and secure deletion are separate tasks. No full directory deletion is performed.

The installer is not an upgrade/migration tool for the pre-existing `gaming-tunnel` deployment. Follow that tool's independent ownership and rollback instructions.
