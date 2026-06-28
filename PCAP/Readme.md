# ChumBucket

**A network-forensics CTF challenge forge.**

ChumBucket chums the water with realistic background traffic and decoy flags, then hides the real catch inside a `.pcap` for your players to fish out. It generates capture files for blue-team / DFIR challenges — controlled volumes of plausible traffic per protocol, a flag hidden by one of several techniques (or buried inside a simulated attack), and an answer key that documents the exact solve path.

> ChumBucket produces capture **files** for analysis puzzles. It does not send anything on a network.

---

## Features

- **Realistic traffic** — full TCP handshakes, HTTP request/response with real headers and bodies, TLS-looking sessions, DNS query/answer pairs, ICMP echo/reply, ARP, and DHCP, all between a consistent set of hosts (clients, gateway, resolver, servers) with proper MACs and sequence numbers.
- **Controlled volume** — set how many sessions of each protocol to generate.
- **Hidden-flag methods** — DNS exfil (subdomain labels), TCP/ICMP split-and-reassemble, or an HTTP session cookie.
- **Attack scenarios** — plant a recognizable attack signature that *is* the flag carrier: `kerberoast`, `ftp-creds`, `telnet-creds`, `http-basic`, `arp-spoof`, `port-scan`, `brute-force`, `c2-beacon`.
- **Layered obfuscation** — Base32 / Base64 / Hex encoding plus an optional XOR layer, with decoy red-herring flags.
- **Answer key** — every run writes a sidecar `.txt` with the intended solve path, a ready-to-use CyberChef recipe, and the exact frame numbers of the flag-carrier packets.
- **Self-check** — after generating, ChumBucket re-solves its own capture and confirms the flag is recoverable, so you never ship an unsolvable challenge.
- **Reproducible** — pass a `--seed` to regenerate the same challenge every time.

## Requirements

- Python 3.10+
- [`scapy`](https://scapy.net/) (required)
- [`rich`](https://github.com/Textualize/rich) (optional — enables the styled banner and menu; the tool degrades to plain text without it)

```bash
pip install scapy rich
```

A UTF-8 terminal is recommended for the launch banner (Windows Terminal or PowerShell 7).

## Usage

Run with no arguments for the interactive builder:

```bash
python ChumBucket.py
```

Or drive it with flags for scripting / batch generation:

```bash
# DNS-exfil challenge, base32 + XOR, reproducible
python ChumBucket.py --method dns --encode base32 --xor s3cret --flag "you_found_me" --seed 1337 -o round1

# Kerberoasting scenario
python ChumBucket.py --scenario kerberoast --flag "spn_hunter" -o ad_challenge

# C2 beaconing scenario with custom traffic volume
python ChumBucket.py --scenario c2-beacon --http 30 --dns 40 --decoys 5 -o beacon_hunt
```

You only supply a name for `-o`; the `.pcap` extension (and the `<name>_answer.txt` key) are added automatically.

See all options with:

```bash
python ChumBucket.py --help
```

## Output

Each run produces two files:

- `<name>.pcap` — the challenge capture, ready to hand to players
- `<name>_answer.txt` — the answer key (flag, solve path, CyberChef recipe, carrier frame numbers)

## Notes

- Protocol payloads (TLS, Kerberos, ARP padding) are **recognizable and solvable** rather than byte-perfect — ideal for forensics puzzles, but not intended to pass strict protocol validation.
- These are challenge **fixtures**: any "encrypted" or credential material is synthetic.

## License

_Add your license here (e.g. MIT)._
