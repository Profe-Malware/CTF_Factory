"""chumbucket.network - split module (code verbatim from the monolith)."""
import ipaddress
import random
import time
from dataclasses import dataclass
from scapy.all import (Ether)




@dataclass
class NoiseConfig:
    subnet: str = "10.0.0.0/24"
    start_time: float = 1700000000.0
    jitter: float = 0.35          # session spacing (seconds), scaled
    seed: int | None = None
    normalize: bool = False       # even out timestamps for a "clean" capture
    n_clients: int = 6            # how many distinct client hosts on the LAN


def _rand_ip(net: ipaddress.IPv4Network, rng: random.Random) -> str:
    hosts = int(net.network_address) + 1
    last = int(net.broadcast_address) - 1
    return str(ipaddress.IPv4Address(rng.randint(hosts, last)))


_WEB_HOSTS = [
    ("www.example.com", "93.184.216.34"),
    ("api.weather.io", "104.18.32.7"),
    ("cdn.jsdelivr.net", "151.101.1.229"),
    ("update.microsoft.com", "23.45.112.61"),
    ("fonts.gstatic.com", "142.250.80.3"),
    ("telemetry.corp.local", "10.0.0.20"),
    ("intranet.corp.local", "10.0.0.21"),
]


def _rand_mac(rng: random.Random) -> str:
    # locally-administered, unicast; vendor-ish OUIs
    oui = rng.choice([(0x00, 0x1a, 0x2b), (0x3c, 0x5a, 0xb4),
                      (0xf0, 0x9f, 0xc2), (0x00, 0x0c, 0x29),
                      (0xac, 0xde, 0x48)])
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        oui[0], oui[1], oui[2],
        rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))


@dataclass
class Host:
    ip: str
    mac: str
    role: str
    name: str = ""


@dataclass
class Network:
    gateway: Host
    dns: Host
    clients: list
    servers: dict          # hostname -> Host
    subnet: ipaddress.IPv4Network

    def mac_for(self, ip: str) -> str:
        for h in [self.gateway, self.dns, *self.clients, *self.servers.values()]:
            if h.ip == ip:
                return h.mac
        # in-subnet but unknown -> deterministic mac; external -> gateway (routed)
        addr = ipaddress.IPv4Address(ip)
        if addr in self.subnet:
            seed = int(addr) & 0xFFFFFF
            return "02:%02x:%02x:%02x:%02x:%02x" % (
                (seed >> 16) & 0xFF, (seed >> 8) & 0xFF, seed & 0xFF,
                (int(addr) >> 8) & 0xFF, int(addr) & 0xFF)
        return self.gateway.mac


def build_network(cfg: NoiseConfig, rng: random.Random) -> Network:
    net = ipaddress.IPv4Network(cfg.subnet)
    base = int(net.network_address)
    gateway = Host(str(ipaddress.IPv4Address(base + 1)), _rand_mac(rng), "gateway", "gw")
    dns = Host(str(ipaddress.IPv4Address(base + 53)), _rand_mac(rng), "dns", "resolver")
    clients = [Host(str(ipaddress.IPv4Address(base + 100 + i)), _rand_mac(rng),
                    "client", f"host-{i+1:02d}") for i in range(cfg.n_clients)]
    servers = {}
    for name, ip in _WEB_HOSTS:
        addr = ipaddress.IPv4Address(ip)
        mac = _rand_mac(rng) if addr in net else gateway.mac  # external via gw
        servers[name] = Host(ip, mac, "server", name)
    return Network(gateway, dns, clients, servers, net)


def _emit(pkts, frame, clock, rng, delta):
    clock[0] += delta
    frame.time = clock[0]
    pkts.append(frame)


def _eth(net: Network, src_ip: str, dst_ip: str):
    return Ether(src=net.mac_for(src_ip), dst=net.mac_for(dst_ip))


def _mac_bytes(mac: str) -> bytes:
    return bytes(int(b, 16) for b in mac.split(":"))
