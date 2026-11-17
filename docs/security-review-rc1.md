# Automated checks and review limits

The engine binary was rebuilt from pinned, dependency-patched upstream source.
An offline rebuild in a Linux network namespace produced the same SHA256
`606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf`.
The full bundle includes that binary, upstream GPL license and the corresponding
source archive with its module cache and offline build instructions.

The core rc1 binary and engine scans found no known reachable vulnerabilities
against the recorded official Go vulnerability database snapshot. See the JSON
reports for database commit, tool version, exact binary hash and scope. This is
neither an independent security audit nor a guarantee against unknown defects.

Bandit reports are retained with findings rather than suppressed. The medium
B103 finding is the native installer's root-owned `/etc/nextgen-tunnel` directory
mode 0750: traversal is intentional for the dedicated service group, while
private files remain 0600. There is no world access. B104 flags the carrier
listener's deliberate `0.0.0.0` bind: remote peers need to reach this authenticated
TLS listener. Its forwarding policy permits only the selected loopback WireGuard
port and rejects other destinations; the initiating inbound binds loopback.
Low findings concern
subprocess imports, argument-array execution and executable lookup. Commands do
not use a shell; namespace names, paths, ownership and binary digests are checked.
Installation assumes a trusted root operator and system executable search path.

The integrated engine runs with a dynamic user and only NET_BIND_SERVICE.
Systemd supplies private credentials. Site namespace creation and recovery use
bounded privileged services. The installer journals mutations, refuses unmanaged
targets and modified owned files, and supports rollback and recovery. Backups
contain private material and intentionally remain root-only after uninstall.

No real passwords, deployment private keys or packet captures belong in release
bundles. Public upstream source contains upstream test fixtures; these are not
deployment credentials. Bundle verification checks member paths, manifest
coverage and hashes. Verify the external archive checksum before extracting.
