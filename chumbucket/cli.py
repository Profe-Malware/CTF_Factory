"""chumbucket.cli - split module (code verbatim from the monolith)."""
import argparse
import base64
import random
import sys
import os
import time
import copy
import re
from dataclasses import field
from scapy.all import (TCP, UDP, ICMP, DNS, ARP, DHCP, wrpcap)

from .ui import (DEFAULT_FLAG_PREFIX, _HAS_RICH, _console, ask, ask_choice, ask_int, ask_yesno, format_flag, print_banner, say)
from .encoding import (effective_encoding)
from .scenarios import (_SCENARIOS)
from .output import (build_challenge, force_ext, self_check, write_answer_key)


def interactive_config(args):
    """Walk the author through every decision, mutating `args` in place.
    Returns the populated args namespace."""
    say("\nInteractive challenge builder - press Enter to accept the [default].\n",
        "subtitle")

    # --- flag ---
    say("STEP 1 / 5  ::  The flag", "menu_title")
    fmt = ask_choice("Flag format", [
        ("CTF{FLAG}",     "classic CTF{...}"),
        ("flag{FLAG}",    "lowercase flag{...}"),
        ("FLAG{FLAG}",    "uppercase FLAG{...}"),
        ("custom",        "type your own wrapper"),
    ])
    if fmt == "custom":
        say("  Use the literal word FLAG as the placeholder, e.g. myctf-FLAG-end", "coming_soon")
        args.wrapper = ask("Wrapper template", "CTF{FLAG}") or "CTF{FLAG}"
        if "FLAG" not in args.wrapper:
            args.wrapper += "{FLAG}"
    else:
        args.wrapper = fmt
    inner = ask("Flag text (inside the wrapper)", "r34ssembly_1s_fun")
    args.flag = inner
    say(f"  -> flag will be: {format_flag(args.wrapper, inner)}", "success")

    # --- method / scenario ---
    say("\nSTEP 2 / 5  ::  Hiding technique or attack scenario", "menu_title")
    choice = ask_choice("How should the flag be hidden?", [
        ("dns",          "scatter encoded flag across DNS subdomain labels (exfil trope)"),
        ("split-tcp",    "split across TCP payloads; player reassembles by index"),
        ("split-icmp",   "split across ICMP echo payloads; player reassembles"),
        ("http",         "bury in an HTTP session cookie; found via stream follow"),
        ("kerberoast",   "SCENARIO: Kerberoasting burst; flag in a service SPN"),
        ("ftp-creds",    "SCENARIO: plaintext FTP login; flag is the password"),
        ("telnet-creds", "SCENARIO: plaintext Telnet login; flag is the password"),
        ("http-basic",   "SCENARIO: HTTP Basic auth; flag in base64 user:pass"),
        ("arp-spoof",    "SCENARIO: ARP poisoning; flag in the gratuitous-ARP padding"),
        ("port-scan",    "SCENARIO: SYN sweep; flag in the open port's banner"),
        ("brute-force",  "SCENARIO: failed logins then success; flag is cracked pw"),
        ("c2-beacon",    "SCENARIO: fixed-interval C2 callbacks; flag in a beacon"),
        ("rogue-dhcp",   "SCENARIO: rogue DHCP offer; flag in the boot-file field"),
        ("ssdp-upnp",    "SCENARIO: SSDP/UPnP abuse; flag in a NOTIFY LOCATION URL"),
        ("doh-beacon",   "SCENARIO: DNS-over-HTTPS beacon; flag in the TLS SNI label"),
        ("dga-beacon",   "SCENARIO: DGA domain burst; flag is one query's label"),
        ("malware-chain","SCENARIO: redirect->dropper->payload; flag in the dropper"),
        ("ransomware-note","SCENARIO: ransom note; flag is the 'Personal ID'"),
        ("pastebin-exfil","SCENARIO: dead-drop paste exfil; flag split across POSTs"),
    ])
    if choice in _SCENARIOS:
        args.scenario = choice
        say(f"  -> scenario '{choice}' will plant a detectable attack signature.",
            "warning")
    else:
        args.scenario = "none"
        args.method = choice

    # --- encoding ---
    say("\nSTEP 3 / 5  ::  Encoding & obfuscation", "menu_title")
    args.encode = ask_choice("Encoding applied before hiding?", [
        ("base32", "DNS-label safe; good default"),
        ("base58", "compact alphanumeric; no +/= symbols"),
        ("base64", "compact, recognizable"),
        ("urlencode", "percent-encoded %XX; classic web look"),
        ("hex",    "simplest to spot/decode"),
        ("none",   "plaintext (easy mode)"),
    ])
    say("  (An XOR layer scrambles the flag a second time so it can't be read even",
        "coming_soon")
    say("   if someone spots the encoded text - e.g. by running `strings` on the file.)",
        "coming_soon")
    if ask_yesno("Add a second XOR layer for extra obfuscation?", False):
        args.xor = ask("XOR key", "sekret")
    else:
        args.xor = ""

    # --- noise volumes ---
    say("\nSTEP 4 / 5  ::  Background traffic (sessions per protocol)", "menu_title")
    say("  Each session expands into several real packets (handshake, data, acks).",
        "coming_soon")
    args.http  = ask_int("  HTTP sessions",  15)
    args.https = ask_int("  HTTPS sessions", 12)
    args.dns   = ask_int("  DNS exchanges",  20)
    args.tcp   = ask_int("  Other TCP service sessions", 12)
    args.udp   = ask_int("  UDP/DNS chatter", 10)
    args.icmp  = ask_int("  ICMP pings",      8)
    args.arp   = ask_int("  ARP exchanges",   10)
    args.dhcp  = ask_int("  DHCP handshakes", 2)
    args.clients = ask_int("  How many distinct hosts/IPs to generate on the LAN", 6)
    args.decoys = ask_int("  Decoy/red-herring fake flags", 3)
    if args.decoys > 0:
        args.decoy_theme = ask_choice("  Red-herring flavor", [
            ("spongebob", "Bikini Bottom mashups (default)"),
            ("cyber",     "realistic security jargon + fake CVEs"),
            ("mixed",     "both spongebob and cyber"),
            ("custom",    "your own word list"),
        ])
        if args.decoy_theme == "custom":
            raw = ask("  Custom words (comma-separated)", "")
            args.decoy_words = [w.strip() for w in raw.split(",") if w.strip()]
        else:
            args.decoy_words = []
    else:
        args.decoy_theme, args.decoy_words = "spongebob", []
    say("  (Normalized timing spaces every packet evenly - tidier, but less",
        "coming_soon")
    say("   realistic. Leave off to keep natural, random gaps like real traffic.)",
        "coming_soon")
    args.normalize = ask_yesno("  Normalize timing (even spacing)?", False)

    # --- output ---
    say("\nSTEP 5 / 5  ::  Output & reproducibility", "menu_title")
    seed_raw = ask("Seed (blank = random each run)", "")
    args.seed = int(seed_raw) if seed_raw.strip().lstrip("-").isdigit() else None
    say("  (just a name - .pcap / .txt are added automatically)", "coming_soon")
    args.out = ask("Output pcap name", "challenge")
    args.answer_key = ask("Answer-key name (blank = <out>_answer)", "")

    # --- summary / confirm ---
    say("\n" + "-" * 50, "border")
    say("Ready to generate:", "subtitle")
    say(f"  flag      : {format_flag(args.wrapper, args.flag)}", "meta")
    challenge = args.scenario if args.scenario != "none" else args.method
    say(f"  challenge : {challenge}", "meta")
    say(f"  encoding  : {args.encode}" + (" + XOR" if args.xor else ""), "meta")
    sessions = (args.http + args.https + args.dns + args.tcp + args.udp +
                args.icmp + args.arp + args.dhcp)
    say(f"  traffic   : ~{sessions} sessions across {args.clients} hosts + carrier", "meta")
    say(f"  timing    : {'normalized' if args.normalize else 'realistic jitter'}", "meta")
    say(f"  output    : {args.out}.pcap (+ answer key)", "meta")
    say("-" * 50, "border")
    if not ask_yesno("\nGenerate now?", True):
        say("Aborted.", "warning")
        sys.exit(0)
    return args


def main():
    ap = argparse.ArgumentParser(
        description="Generate a realistic network-forensics CTF pcap with a hidden flag.")
    # flag
    ap.add_argument("--flag", default="r34ssembly_1s_fun",
                    help="inner flag text (without the wrapper)")
    ap.add_argument("--wrapper", default=f"{DEFAULT_FLAG_PREFIX}{{FLAG}}",
                    help="flag wrapper; the literal 'FLAG' is replaced by --flag")
    # hiding
    ap.add_argument("--method", default="dns",
                    choices=["dns", "split-tcp", "split-icmp", "http"],
                    help="how the flag is hidden (ignored if --scenario is set)")
    ap.add_argument("--scenario", default="none",
                    choices=["none", "kerberoast", "ftp-creds", "telnet-creds",
                             "http-basic", "arp-spoof", "port-scan", "brute-force",
                             "c2-beacon", "rogue-dhcp", "ssdp-upnp", "doh-beacon",
                             "dga-beacon", "malware-chain", "ransomware-note",
                             "pastebin-exfil"],
                    help="plant an attack signature that also carries the flag")
    ap.add_argument("--encode", default="base32",
                    choices=["none", "hex", "base64", "base32", "base58", "urlencode"],
                    help="encoding applied before hiding")
    ap.add_argument("--xor", default="",
                    help="optional XOR key applied before encoding (meatier)")
    ap.add_argument("--decoys", type=int, default=3,
                        help="number of red-herring fake flags to plant")
    ap.add_argument("--decoy-theme", default="spongebob",
                        choices=["spongebob", "cyber", "mixed", "custom"],
                        help="flavor of the fake red-herring flags")
    ap.add_argument("--decoy-words", default="",
                        help="comma-separated words for --decoy-theme custom "
                            "(supplying these auto-selects the custom theme)")
    # noise volumes (sessions; each expands to several packets)
    ap.add_argument("--tcp", type=int, default=12, help="generic TCP service sessions")
    ap.add_argument("--udp", type=int, default=10, help="(maps to DNS service chatter)")
    ap.add_argument("--dns", type=int, default=20, help="DNS query/response exchanges")
    ap.add_argument("--icmp", type=int, default=8, help="ICMP echo/reply pings")
    ap.add_argument("--http", type=int, default=15, help="HTTP request/response sessions")
    ap.add_argument("--https", type=int, default=12, help="TLS-looking HTTPS sessions")
    ap.add_argument("--arp", type=int, default=10, help="ARP who-has/is-at exchanges")
    ap.add_argument("--dhcp", type=int, default=2, help="DHCP DORA handshakes")
    ap.add_argument("--clients", type=int, default=6,
                    help="number of distinct client hosts on the LAN")
    # realism / timing
    ap.add_argument("--subnet", default="10.0.0.0/24")
    ap.add_argument("--jitter", type=float, default=0.35,
                    help="mean idle gap between sessions (seconds)")
    ap.add_argument("--normalize", action="store_true",
                    help="re-space all timestamps evenly for a tidy capture")
    ap.add_argument("--seed", type=int, default=None,
                    help="RNG seed for reproducible challenges")
    # output
    ap.add_argument("-o", "--out", default="challenge",
                    help="output pcap name; .pcap is added automatically")
    ap.add_argument("--answer-key", default="",
                    help="answer-key name; defaults to <out>_answer.txt")
    ap.add_argument("--outdir", default="ChumOutput",
                    help="parent folder for generated challenges (default: ChumOutput)")
    ap.add_argument("--no-subfolder", action="store_true",
                    help="write files to the current directory instead of ChumOutput/<name>/")
    ap.add_argument("--no-check", action="store_true",
                    help="skip the post-generation solvability self-check")
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("-i", "--interactive", action="store_true",
                    help="force the interactive menu even if other flags are given")
    args = ap.parse_args()

    # normalize decoy words; supplying words auto-selects the custom theme
    args.decoy_words = [w.strip() for w in args.decoy_words.split(",") if w.strip()]
    if args.decoy_words and args.decoy_theme == "spongebob":
        args.decoy_theme = "custom"

    # Bare launch (no args) or explicit -i -> interactive menu.
    go_interactive = args.interactive or len(sys.argv) == 1

    if not args.quiet:
        print_banner()

    if not go_interactive:
        generate_once(args)
        return

    # Interactive: keep offering new challenges until the user exits.
    import copy
    base = args
    while True:
        run_args = copy.copy(base)
        run_args = interactive_config(run_args)
        generate_once(run_args)
        if not ask_yesno("\nGenerate another challenge?", True):
            say("\nThanks for chumming the water. See you next tide. \U0001F41F",
                "subtitle")
            break


def generate_once(args):
    """Run a single generation: resolve paths, build, write, self-check, report,
    and print how long it took. Shows a progress bar / heads-up for big captures."""
    import os, time
    t0 = time.perf_counter()

    # force standard extensions; user only supplies a name
    args.out = force_ext(args.out, ".pcap")
    if not args.answer_key:
        args.answer_key = os.path.splitext(args.out)[0] + "_answer.txt"
    else:
        args.answer_key = force_ext(args.answer_key, ".txt")

    # organize everything under ChumOutput/<challenge-name>/ unless the user
    # already gave an explicit path with directories in it
    base = os.path.splitext(os.path.basename(args.out))[0]
    if not args.no_subfolder and os.path.dirname(args.out) in ("", "."):
        out_dir = os.path.join(args.outdir, base)
        os.makedirs(out_dir, exist_ok=True)
        args.out = os.path.join(out_dir, os.path.basename(args.out))
        args.answer_key = os.path.join(out_dir, os.path.basename(args.answer_key))

    # estimate workload and warn for big captures. Packets-per-session differ a
    # lot by protocol (an HTTP page load is ~20+ packets; an ARP exchange is 2).
    _PER = {"arp": 2, "dhcp": 4, "dns": 2, "udp": 2, "icmp": 6,
            "tcp": 10, "https": 13, "http": 22}
    total_sessions = sum(getattr(args, k) for k in
                         ("arp", "dhcp", "tcp", "udp", "dns", "icmp", "http", "https"))
    est_packets = sum(getattr(args, k) * w for k, w in _PER.items()) + args.decoys + 40
    if not args.quiet and est_packets > 75000:
        eta = est_packets / 1500.0   # ~packets/sec on a typical machine
        mins = f"~{eta/60:.1f} min" if eta > 90 else f"~{eta:.0f}s"
        say(f"[!] Heads-up: ~{est_packets:,} packets projected ({mins} to build). "
            f"Large captures are slow to build and write - this is normal, hang tight.",
            "warning")

    # build (with progress bar when rich is available and we're not quiet)
    if _HAS_RICH and not args.quiet and total_sessions > 0:
        from rich.progress import (Progress, SpinnerColumn, BarColumn, TextColumn,
                                   TimeElapsedColumn, MofNCompleteColumn)
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), MofNCompleteColumn(), TimeElapsedColumn(),
                      console=_console, transient=True) as prog:
            task = prog.add_task("Chumming the water", total=total_sessions)
            pkts, solution, net, located = build_challenge(
                args, progress=lambda n: prog.advance(task, n))
            prog.update(task, description="Writing pcap", completed=total_sessions)
            wrpcap(args.out, pkts)
            prog.update(task, description="Verifying")
            ok = None if args.no_check else self_check(pkts, args)
        write_answer_key(args.answer_key, args, solution, len(pkts), located)
    else:
        pkts, solution, net, located = build_challenge(args)
        wrpcap(args.out, pkts)
        write_answer_key(args.answer_key, args, solution, len(pkts), located)
        ok = None if args.no_check else self_check(pkts, args)

    elapsed = time.perf_counter() - t0

    if not args.quiet:
        _eff, _note = effective_encoding(args)
        if _note:
            say(f"[!] Encoding note: {_note}", "warning")
        say(f"[+] Wrote {len(pkts):,} packets to {args.out}", "success")
        say(f"[+] Answer key -> {args.answer_key}", "success")
        say(f"[+] Hosts on LAN: {len(net.clients)} clients + gateway + resolver "
            f"+ {len(net.servers)} servers", "meta")
        say(f"[+] Flag: {format_flag(args.wrapper, args.flag)}", "highlight")
        if ok is True:
            say("[+] Self-check: flag is recoverable from the capture. OK", "success")
        elif ok is False:
            say("[!] Self-check: could NOT recover the flag - review settings!", "error")
        if located:
            say("[+] Flag carrier frame(s): "
                + ", ".join(str(m["frame"]) for m in located), "meta")
        say("[+] Solve path:", "menu_title")
        for i, s in enumerate(solution, 1):
            say(f"      {i}. {s}", "menu_item")
        say(f"[+] Completed in {elapsed:.2f}s "
            f"({len(pkts)/max(elapsed,0.001):,.0f} packets/s)", "success")
