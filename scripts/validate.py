#!/usr/bin/env python3
"""Run local validation and preserve commands, results and honest blockers."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--shell", help="GNU Bash executable for parse-only checks")
    parser.add_argument("--database-repo", type=Path, help="official golang/vulndb checkout for offline scanning")
    parser.add_argument("--output", type=Path, default=ROOT / "docs/evidence/validation.json")
    args = parser.parse_args()
    go = str(Path(args.go).resolve()) if Path(args.go).exists() else args.go
    report = {"schema_version": 1, "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "checks": []}
    def check(name, command, classification="required", env=None, timeout=180):
        start = time.monotonic()
        try:
            p = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=timeout, env=env)
            record = dict(name=name, command=command, returncode=p.returncode, stdout=p.stdout, stderr=p.stderr,
                          classification=classification, elapsed_seconds=time.monotonic() - start)
        except (OSError, subprocess.TimeoutExpired) as exc:
            record = dict(name=name, command=command, returncode=None, error=str(exc), classification=classification,
                          elapsed_seconds=time.monotonic() - start)
        # Strip local tool installation prefixes while keeping exact command args.
        record["command"] = [Path(command[0]).name] + command[1:]
        report["checks"].append(record)
        print(name, "PASS" if record["returncode"] == 0 else "BLOCKED/FAIL", flush=True)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return record
    check("toolchain", [go, "version"])
    check("module_integrity", [go, "mod", "verify"])
    check("go_tests", [go, "test", "-count=1", "-json", "./..."])
    check("vet", [go, "vet", "./..."])
    check("frame_fuzz", [go, "test", "./internal/transport", "-run", "^$", "-fuzz", "FuzzReadFrame", "-fuzztime=5s", "-parallel=2"])
    check("race", [go, "test", "-race", "./..."], "environment_gate")
    check("python_tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"])
    paths = ["agent.py", "model.py", "tunnelctl.py"] + [str(p.relative_to(ROOT)) for p in (ROOT / "scripts").glob("*.py")]
    check("python_compile", [sys.executable, "-m", "py_compile", *paths])
    if args.shell:
        check("shell_syntax", [sys.executable, "scripts/check_shell.py", "--shell", args.shell])
    (ROOT / "dist").mkdir(exist_ok=True)
    host_name = "nextgen-tunnel.exe" if os.name == "nt" else "nextgen-tunnel"
    check("host_build", [go, "build", "-trimpath", "-o", "dist/" + host_name, "./cmd/nextgen-tunnel"])
    for arch in ("amd64", "arm64"):
        env = dict(os.environ, GOOS="linux", GOARCH=arch, CGO_ENABLED="0")
        check("linux_" + arch + "_build", [go, "build", "-trimpath", "-o", "dist/nextgen-tunnel-linux-" + arch, "./cmd/nextgen-tunnel"], env=env)
    if args.database_repo:
        check("vulnerabilities", [sys.executable,"scripts/security_scan.py","--go",go,"--database-repo",str(args.database_repo.resolve()),"--output",str(args.output.with_name('security-scan.json'))], "security_gate",timeout=300)
    else:
        check("vulnerabilities", [go, "run", "golang.org/x/vuln/cmd/govulncheck@v1.9.0", "./..."], "security_gate")
    report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report["required_checks_passed"] = all(c["returncode"] == 0 for c in report["checks"] if c["classification"] == "required")
    report["all_gates_passed"] = all(c["returncode"] == 0 for c in report["checks"])
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not report["required_checks_passed"]:
        raise SystemExit(1)

if __name__ == "__main__": main()
