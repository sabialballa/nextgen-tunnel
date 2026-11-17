"""Validated public deployment profile. No SSH passwords or private keys belong here."""
import ipaddress
import re

PORTS = (500, 4500, 1701, 46954, 48320, 34569)
DEFAULTS = dict(interface="wg-game", mtu=1360, rate_mbit=120, rtt_ms=100,
                overhead=100, receive_kib=8192, wg_port=51888,
                loopback_port=51889, carrier_id=443,
                link_subnet="10.77.240.0/30", service_subnet="10.77.242.0/30",
                ppp_subnet="192.168.42.0/24", l2tp_mtu=1240, l2tp_mss=1200)

def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer in {low}..{high}")
    return value

def validate(config):
    if not isinstance(config, dict):
        raise ValueError("configuration must be an object")
    result = dict(DEFAULTS)
    result.update(config.get("tunnel", {}))
    for name in ("entry", "exit"):
        ep = config[name]
        ipaddress.IPv4Address(ep["public_ip"])
        host = ep.get("ssh_host", ep["public_ip"])
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", host):
            raise ValueError("SSH host must be an IPv4 address, DNS name or SSH alias")
        if ep.get("user", "root") != "root":
            raise ValueError("use a root SSH account with key authentication")
        integer(ep.get("ssh_port", 22), 1, 65535, "ssh_port")
    if config["entry"]["public_ip"] == config["exit"]["public_ip"]:
        raise ValueError("entry and exit must be different hosts")
    if not re.fullmatch(r"wg-[A-Za-z0-9_-]{1,11}", result["interface"]):
        raise ValueError("use a dedicated wg- interface name of at most 14 characters")
    for key, low, high in (("mtu", 1280, 1360), ("rate_mbit", 1, 10000),
                          ("rtt_ms", 10, 2000), ("overhead", 0, 256),
                          ("receive_kib", 1024, 10240), ("wg_port", 1024, 65535),
                          ("loopback_port", 1024, 65535), ("carrier_id", 1, 65535),
                          ("l2tp_mtu", 1000, 1400), ("l2tp_mss", 960, 1360)):
        integer(result[key], low, high, key)
    if result["l2tp_mss"] > result["l2tp_mtu"] - 40:
        raise ValueError("L2TP MSS must not exceed MTU minus 40")
    if result["l2tp_mtu"] + 120 > result["mtu"]:
        raise ValueError("reserve at least 120 bytes for L2TP/IPsec encapsulation")
    subnets = []
    for key in ("link_subnet", "service_subnet"):
        net = ipaddress.IPv4Network(result[key], strict=True)
        if net.prefixlen != 30 or not any(net.subnet_of(ipaddress.IPv4Network(n)) for n in ("10.0.0.0/8","172.16.0.0/12","192.168.0.0/16")):
            raise ValueError(f"{key} must be a private /30")
        subnets.append(net)
    ppp = ipaddress.IPv4Network(result["ppp_subnet"], strict=True)
    if subnets[0].overlaps(subnets[1]) or any(n.overlaps(ppp) for n in subnets):
        raise ValueError("link, service and PPP subnets must not overlap")
    ports = (result["wg_port"], result["loopback_port"], result["carrier_id"])
    if len(set(ports)) != 3 or any(p in PORTS for p in ports):
        raise ValueError("carrier ports/identifier must be distinct from VPN ports")
    return result

def role_plan(config, role, public_keys, secret, vpn_ports):
    p = validate(config)
    if role not in ("entry", "exit"):
        raise ValueError("invalid role")
    for key in public_keys.values():
        if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", key):
            raise ValueError("invalid WireGuard public key")
    if not re.fullmatch(r"[0-9a-f]{64}", secret):
        raise ValueError("carrier key must be 32 random bytes encoded as hex")
    i = 0 if role == "entry" else 1
    peer = "exit" if i == 0 else "entry"
    for proto, ports in vpn_ports.items():
        if proto not in ("tcp", "udp") or not isinstance(ports, list):
            raise ValueError("invalid VPN port mapping")
        for port in ports:
            integer(port, 1, 65535, "VPN port")
            if port not in PORTS:
                raise ValueError("VPN mapping outside the supported port allowlist")
    link = list(ipaddress.IPv4Network(p["link_subnet"]).hosts())
    service = list(ipaddress.IPv4Network(p["service_subnet"]).hosts())
    p.update(role=role, public_ip=config[role]["public_ip"],
             peer_public_ip=config[peer]["public_ip"], link_local=str(link[i]),
             link_peer=str(link[1-i]), service_local=str(service[i]),
             service_peer=str(service[1-i]), peer_key=public_keys[peer],
             carrier_key=secret, vpn_ports=vpn_ports)
    return p
