#!/usr/bin/env python3
"""Reproducible, bounded loopback lab. No privileged or external network changes.

Uses real processes, certificates, TLS/QUIC sockets, TCP/UDP payloads and a direct
baseline. This is a functional lab and microbenchmark, not an Iran DPI benchmark.
"""
import argparse
import concurrent.futures
import contextlib
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import statistics
import subprocess
import tempfile
import threading
import time
from process_metrics import sample as process_sample

def port(network):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if network == "tcp" else socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def tunnel_ports(count):
    # Hold both protocols while choosing ports, so primary and backup cannot
    # accidentally use the same freshly released ephemeral port.
    with contextlib.ExitStack() as stack:
        values = []
        for _ in range(count):
            for attempt in range(30):
                tcp = socket.socket(); tcp.bind(("127.0.0.1",0)); number=tcp.getsockname()[1]
                udp = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
                try: udp.bind(("127.0.0.1",number))
                except OSError: tcp.close();udp.close();continue
                stack.enter_context(tcp);stack.enter_context(udp);values.append(number);break
            else: raise RuntimeError("could not reserve disjoint TCP/UDP lab ports")
        return values

def receive(s, n):
    result = bytearray()
    while len(result) < n:
        chunk = s.recv(n - len(result))
        if not chunk:
            raise RuntimeError("unexpected EOF")
        result.extend(chunk)
    return bytes(result)

def percentile(values, p):
    values = sorted(values)
    if not values:
        return None
    return values[min(len(values) - 1, max(0, int(len(values) * p + .999999) - 1))]

def tcp_measure(address, seconds):
    payload = os.urandom(32768)
    total = 0
    start = time.perf_counter()
    with socket.create_connection(address, timeout=5) as s:
        while time.perf_counter() - start < seconds:
            s.sendall(payload)
            if receive(s, len(payload)) != payload:
                raise RuntimeError("TCP data corruption")
            total += len(payload)
    elapsed = time.perf_counter() - start
    return dict(payload_bytes=total, elapsed_seconds=elapsed, echo_payload_mbit_s=total * 8 / elapsed / 1e6)

def udp_measure(address, samples):
    rtts, lost, reordered = [], 0, 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(.5)
        s.connect(address)
        for i in range(samples):
            payload = i.to_bytes(8, "big") + os.urandom(152)
            start = time.perf_counter_ns()
            s.send(payload)
            try:
                reply = s.recv(65535)
                if reply != payload:
                    reordered += 1
                else:
                    rtts.append((time.perf_counter_ns() - start) / 1e6)
            except socket.timeout:
                lost += 1
            time.sleep(.005)
    return dict(sent=samples, received=len(rtts), timed_out=lost, unexpected_or_reordered=reordered,
                loss_percent=100 * (samples - len(rtts)) / samples,
                rtt_average_ms=statistics.mean(rtts) if rtts else None,
                rtt_p50_ms=percentile(rtts, .5), rtt_p95_ms=percentile(rtts, .95), rtt_p99_ms=percentile(rtts, .99),
                adjacent_rtt_difference_mean_ms=statistics.mean(abs(a - b) for a, b in zip(rtts, rtts[1:])) if len(rtts) > 1 else None)

def stability(tcp_address, udp_address, seconds):
    start = time.monotonic(); count = 0; lost = 0; rtts = []
    with socket.create_connection(tcp_address, timeout=5) as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.connect(udp_address); udp.settimeout(1)
        while time.monotonic() - start < seconds:
            data = count.to_bytes(8, "big") + os.urandom(1016)
            tcp.sendall(data)
            if receive(tcp, len(data)) != data: raise RuntimeError("stability TCP corruption")
            before = time.perf_counter_ns(); udp.send(data[:160])
            try:
                if udp.recv(65535) != data[:160]: raise RuntimeError("stability UDP mismatch")
                rtts.append((time.perf_counter_ns() - before) / 1e6)
            except socket.timeout: lost += 1
            count += 1; time.sleep(.1)
    return dict(requested_seconds=seconds, elapsed_seconds=time.monotonic()-start, tcp_exchanges=count,
                udp_sent=count, udp_received=len(rtts), udp_timeouts=lost, rtt_p95_ms=percentile(rtts,.95),
                phase_start_monotonic=start, phase_end_monotonic=time.monotonic())

@contextlib.contextmanager
def echoes():
    stop = threading.Event()
    tcp = socket.socket(); tcp.bind(("127.0.0.1", 0)); tcp.listen(); tcp.settimeout(.2)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("127.0.0.1", 0)); udp.settimeout(.2)
    children, sockets = [], []
    def echo(c):
        c.settimeout(.2)
        with c:
            while not stop.is_set():
                try:
                    b = c.recv(65535)
                    if not b:
                        return
                    c.sendall(b)
                except socket.timeout:
                    continue
                except OSError:
                    return
    def accept():
        while not stop.is_set():
            try:
                c, _ = tcp.accept(); sockets.append(c)
                th = threading.Thread(target=echo, args=(c,), daemon=True); children.append(th); th.start()
            except socket.timeout:
                continue
            except OSError:
                return
    def datagrams():
        while not stop.is_set():
            try:
                b, a = udp.recvfrom(65535); udp.sendto(b, a)
            except socket.timeout:
                continue
            except OSError:
                return
    threads = [threading.Thread(target=accept), threading.Thread(target=datagrams)]
    for th in threads: th.start()
    try:
        yield tcp.getsockname(), udp.getsockname()
    finally:
        stop.set(); tcp.close(); udp.close()
        for c in sockets: c.close()
        for th in threads + children: th.join(timeout=2)

def wait_ready(binary, cfg, process):
    end = time.monotonic() + 15
    while time.monotonic() < end:
        if process.poll() is not None:
            raise RuntimeError("client exited; see process log")
        p = subprocess.run([str(binary), "status", "-config", str(cfg)], capture_output=True, timeout=3)
        if p.returncode == 0:
            return json.loads(p.stdout)
        time.sleep(.2)
    raise RuntimeError("no healthy transport before readiness deadline")

@contextlib.contextmanager
def process_lifetime(processes, handles):
    try:
        yield
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait()
        for handle in handles:
            handle.close()

@contextlib.contextmanager
def diagnostics(root, report):
    try:
        yield
    finally:
        report["process_logs"] = {p.name: p.read_text(errors="replace") for p in root.glob("*.log")}
        report["last_status"] = {}
        for path in root.glob("*-status.json"):
            try: report["last_status"][path.name] = json.loads(path.read_text())
            except (OSError, ValueError): pass

@contextlib.contextmanager
def resource_monitor(named_processes, report):
    stop = threading.Event()
    report["resource_samples"] = []
    report["resource_sampling_errors"] = []
    def monitor():
        previous = {}
        while not stop.wait(.5):
            now = time.monotonic()
            row = {"monotonic_seconds": now, "processes": {}}
            for name, proc in list(named_processes):
                if proc.poll() is not None: continue
                try:
                    value = process_sample(proc.pid)
                    if proc.pid in previous:
                        last_time, last_cpu = previous[proc.pid]
                        value["cpu_percent_one_core"] = 100 * (value["cpu_seconds"] - last_cpu) / (now - last_time)
                    previous[proc.pid] = now, value["cpu_seconds"]
                    row["processes"][name] = value
                except (OSError, ValueError, NotImplementedError) as exc:
                    message = f"{name}: {exc}"
                    if message not in report["resource_sampling_errors"]:
                        report["resource_sampling_errors"].append(message)
            report["resource_samples"].append(row)
    thread = threading.Thread(target=monitor, daemon=True); thread.start()
    try:
        yield
    finally:
        stop.set(); thread.join(timeout=3)
        report["cpu_and_rss"] = "sampled every 0.5s; CPU100%=one logical core; see raw samples and sampling errors"

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=3)
    parser.add_argument("--samples", type=int, default=100)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--soak-seconds", type=int, default=0)
    args = parser.parse_args()
    if not 1 <= args.seconds <= 30 or not 10 <= args.samples <= 1000 or not 1 <= args.repetitions <= 10:
        parser.error("bounded lab: seconds1..30, samples10..1000, repetitions1..10")
    if not 0 <= args.soak_seconds <= 600: parser.error("soak-seconds must be 0..600")
    binary = args.binary.resolve()
    report = dict(schema_version=1, started_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  platform=platform.platform(), cpu_count=os.cpu_count(), binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  scope="loopback only; payload echo throughput counts one direction; actual network carries request and response",
                  iran_dpi="Not Verified", cpu_and_rss="Not measured", results=[], errors=[])
    processes, handles, named_processes = [], [], []
    try:
        with tempfile.TemporaryDirectory(prefix="nextgen-lab-") as temp, echoes() as (tcp, udp), process_lifetime(processes, handles), resource_monitor(named_processes, report), diagnostics(Path(temp), report):
            root = Path(temp); pki = root / "pki"
            subprocess.run([str(binary), "pki", "-dir", str(pki)], check=True, timeout=10)
            tls = dict(ca=str(pki / "ca.crt"), cert=str(pki / "server.crt"), key=str(pki / "server.key"), client_name="entry")
            server_port, backup_port = tunnel_ports(2)
            report["server_ports"] = {"primary":server_port,"backup":backup_port}
            common = dict(max_sessions=64, idle_seconds=5, probe_seconds=1)
            services = {"tcp-echo": dict(protocol="tcp", target=f"{tcp[0]}:{tcp[1]}"), "udp-echo": dict(protocol="udp", target=f"{udp[0]}:{udp[1]}")}
            def launch(name, cfg):
                path = root / (name + ".json"); path.write_text(json.dumps(cfg))
                log = open(root / (name + ".log"), "wb"); handles.append(log)
                proc = subprocess.Popen([str(binary), "run", "-config", str(path)], stdout=log, stderr=log)
                processes.append(proc); named_processes.append((name, proc)); return proc, path
            server, _ = launch("server", dict(common, role="server", listen=f"127.0.0.1:{server_port}", tls=tls, services=services))
            backup, _ = launch("backup", dict(common, role="server", listen=f"127.0.0.1:{backup_port}", tls=tls, services=services))
            client_tls = dict(tls, cert=str(pki / "client.crt"), key=str(pki / "client.key"), server_name="tunnel.internal")
            local_tcp, local_udp = port("tcp"), port("udp")
            forwards = [dict(service="tcp-echo", protocol="tcp", listen=f"127.0.0.1:{local_tcp}"), dict(service="udp-echo", protocol="udp", listen=f"127.0.0.1:{local_udp}")]
            paths = {}
            for proto in ("tls", "quic"):
                cfg = dict(common, role="client", tls=client_tls, forwards=forwards, endpoints=[dict(name=proto, protocol=proto, address=f"127.0.0.1:{server_port}")], status_file=str(root / (proto + "-status.json")))
                proc, path = launch(proto, cfg); wait_ready(binary, path, proc)
                if server.poll() is not None or backup.poll() is not None:
                    raise RuntimeError("a server exited before benchmark readiness")
                paths[proto] = cfg
                for rep in range(args.repetitions):
                    # Alternate order to reduce systematic warm-up bias.
                    for label in (["direct", proto] if rep % 2 == 0 else [proto, "direct"]):
                        ta, ua = (tcp, udp) if label == "direct" else (("127.0.0.1", local_tcp), ("127.0.0.1", local_udp))
                        phase_start = time.monotonic()
                        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                            single = tcp_measure(ta, args.seconds)
                            multi = list(pool.map(lambda _: tcp_measure(ta, args.seconds), range(4)))
                        udp_result = udp_measure(ua, args.samples)
                        report["results"].append(dict(transport=label, paired_with=proto, repetition=rep, tcp_single=single,
                                                       tcp_four_connections=multi, udp=udp_result, phase_start_monotonic=phase_start, phase_end_monotonic=time.monotonic()))
                proc.terminate(); proc.wait(timeout=10)
            cfg = dict(paths["quic"], endpoints=[dict(name="primary-quic", protocol="quic", address=f"127.0.0.1:{server_port}"), dict(name="backup-tls", protocol="tls", address=f"127.0.0.1:{backup_port}")], status_file=str(root / "failover-status.json"))
            proc, path = launch("failover", cfg); initial = wait_ready(binary, path, proc)
            # Both paths must pass two probes before killing the actual primary.
            deadline = time.monotonic() + 10
            while not all(s["healthy"] for s in initial["transports"]):
                if time.monotonic() > deadline: raise RuntimeError("backup never became healthy")
                time.sleep(.3); initial = wait_ready(binary, path, proc)
            if initial["selected"] != "primary-quic":
                # Startup races are valid: select primary through a fresh process
                # only if it becomes ready first. Do not fabricate an outage test.
                report["failover"] = {"verified": False, "reason": "backup selected first at startup", "initial": initial}
            else:
                start = time.monotonic(); server.terminate(); server.wait(timeout=10)
                end = time.monotonic() + 35
                while time.monotonic() < end:
                    if proc.poll() is not None or backup.poll() is not None:
                        raise RuntimeError("client or backup exited during failover; see diagnostics")
                    try:
                        status = json.loads(Path(cfg["status_file"]).read_text())
                        if status["selected"] == "backup-tls": break
                    except (OSError, ValueError): pass
                    time.sleep(.25)
                else: raise RuntimeError("failover deadline exceeded")
                detection_seconds = time.monotonic() - start
                result = tcp_measure(("127.0.0.1", local_tcp), 1)
                udp_result = udp_measure(("127.0.0.1", local_udp), 20)
                report["failover"] = dict(verified=True, detection_seconds=detection_seconds, tcp_after_outage=result, udp_after_outage=udp_result,
                                          session_migration=False)
                restarted, _ = launch("restarted-primary", dict(common, role="server", listen=f"127.0.0.1:{server_port}", tls=tls, services=services))
                recovery_deadline = time.monotonic() + 35
                while time.monotonic() < recovery_deadline:
                    status = json.loads(Path(cfg["status_file"]).read_text())
                    if status["transports"][0]["healthy"]: break
                    time.sleep(.25)
                else: raise RuntimeError("restarted primary did not recover")
                if status["selected"] != "backup-tls": raise RuntimeError("unexpected failback while backup healthy")
                report["recovery"] = dict(primary_recovered=True, healthy_backup_retained=True)
                if args.soak_seconds:
                    report["stability"] = stability(("127.0.0.1", local_tcp), ("127.0.0.1", local_udp), args.soak_seconds)
                start = time.monotonic(); backup.terminate(); backup.wait(timeout=10)
                return_deadline = time.monotonic() + 35
                while time.monotonic() < return_deadline:
                    status = json.loads(Path(cfg["status_file"]).read_text())
                    if status["selected"] == "primary-quic": break
                    time.sleep(.25)
                else: raise RuntimeError("no return to recovered primary after backup outage")
                report["recovery"].update(return_after_backup_outage_seconds=time.monotonic()-start,
                                           tcp_on_recovered_primary=tcp_measure(("127.0.0.1", local_tcp),1),
                                           udp_on_recovered_primary=udp_measure(("127.0.0.1", local_udp),20))
            # Copy logs only; the temporary directory, certificate keys and configs
            # are never copied into the report directory.
            args.output.parent.mkdir(parents=True, exist_ok=True)
            logs = {f.name: f.read_text(errors="replace") for f in root.glob("*.log")}
            report["process_logs"] = logs
    except Exception as exc:
        report["errors"].append(str(exc))
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=10)
                except subprocess.TimeoutExpired: proc.kill(); proc.wait()
        for log in handles: log.close()
        report["finished_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps({"output": str(args.output), "errors": report["errors"], "runs": len(report["results"])}))
    if report["errors"]: raise SystemExit(1)

if __name__ == "__main__": main()
