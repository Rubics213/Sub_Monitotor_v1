#!/usr/bin/env python3
"""Citymesh RVDP discovery stage: scope engine + BBOT runner in one file.

Single-file build. The scope model, the BBOT preset and the runner are all
embedded, so this script has no sibling imports and no required external
dependencies (an external scope file can still be supplied with --scope-config).

Subcommands
  selftest              assert the embedded scope model and preset (CI gate)
  check ENTRY           verdict for one host, IP or URL
  blacklist [-o FILE]   emit BBOT-compatible blacklist entries
  filter -i FILE        keep only in-scope entries from a host/URL list
  dump                  print the resolved scope model as JSON
  run                   discover (BBOT) then verify scope, write artifacts

Exit codes
  0  success / everything kept
  1  selftest failure
  2  usage or config error
  3  filtered everything out of a non-empty input (fail-closed signal)
  4  refusing to run without the program-required identifying header

Compliance notes that are load-bearing:
* The program requires an identifying User-Agent and X-Intigriti-Username on
  every request. BBOT's `-H` flag OVERWRITES on repetition, so both headers
  are passed as key=value pairs after ONE -H. Two separate -H flags silently
  drop the first header (verified against bbot 3.0.2).
* Active/intrusive modules are excluded by the preset AND again on the
  command line, so editing the preset cannot enable brute force or
  exploitation.
* The blacklist handed to BBOT is derived from the same ip_verdict() the
  filter uses, so discovery and verification cannot disagree about scope.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse

# Refuse to enumerate a carve-out computation over more addresses than this, so
# a bad scope edit cannot hang an unattended job.
MAX_ENUM_ADDRESSES = 200_000

# --------------------------------------------------------------------------- #
# Embedded scope model (the single source of truth for this file)
# --------------------------------------------------------------------------- #
EMBEDDED_SCOPE = {
    "version": 1,
    "program": "Citymesh RVDP (Intigriti)",
    "rate_limit": {
        "program_cap_rps": 20,
        "pipeline_rps": 15,
    },
    "targets": {
        "domains": [
            "citymesh.com", "citymesh.be", "citymesh.eu", "citymesh.guide",
            "citymesh.net", "citymesh.fr", "citymesh.nl", "citymesh.io",
            "citymesh-connect.be", "citymesh-connect.com",
            "citymeshconnect.be", "citymeshconnect.com",
            "ctmsh.co", "connectingsenses.be", "connectingsenses.com",
            "connectow.be", "connectow.eu",
            "engiem2m.be", "engiem2m.com",
            "edpnet.net", "edpnet.com", "edpnet.nl", "edpnet.be",
            "gowifi.be", "myiot.be",
            "ncentric.be", "ncentric.cloud", "ncentric.com",
            "ptxbac.be", "ps-radiocom.be", "ps-radiocom.com",
            "safety-drones.be", "safety-drones.com", "safetydrones.be",
            "sigfox.nl", "towereye.be", "towereye.eu",
            "wifilab.be", "wflb.be", "wifinmbssncb.be",
            "antwerpfreewifi.be", "biotechnology-citymesh.com",
        ],
        "urls": [
            "https://livechat.citymesh.com/",
            "https://auth.citymesh.com/",
            "https://extra.citymesh.com/",
            "https://fleet.citymeshconnect.com/",
            "https://my.citymesh.com/",
            "https://cabmanager.citymesh.com/",
            "https://dialhome.ncentric.be/",
            "https://auth.wifilab.be/",
            "https://extra.edpnet.net/",
            "https://api-gateway.citymesh.com/",
            "https://cc.safety-drones.com/",
        ],
        "ip_ranges": [
            "212.71.0.0/24", "212.71.1.0/24", "212.71.2.0/24",
            "212.71.3.0/24", "212.71.4.0/24", "212.71.5.0/24",
            "212.71.8.0/24", "212.71.11.0/24",
            "31.31.128.0/24", "31.31.140.0/24", "31.31.141.0/24",
            "31.31.143.0/24", "31.31.143.0/25",
            "31.31.150.0/24", "31.31.158.0/24", "31.31.159.0/24",
            "45.11.166.40/29",
            "79.132.241.0/24",
            "85.234.192.0/24", "85.234.203.0/24", "85.234.204.0/24",
            "85.234.205.0/24",
            "193.110.255.128/28",
            "213.211.130.0/24", "213.211.138.0/24", "213.211.188.0/24",
            "213.219.128.0/24", "213.219.132.0/24",
        ],
    },
    "exclude": {
        "hostnames": [
            "static.edpnet.net",
            "dyn.edpnet.net",
            "citymesh.recruitee.com",
            "digi-mobile.be",
            "insky.be",
        ],
        "cidrs": [
            "31.31.128.64/26", "31.31.128.128/26", "31.31.128.192/27",
            "31.31.130.0/23", "31.31.132.0/24", "31.31.134.0/23",
            "31.31.136.0/21", "31.31.139.0/24", "31.31.141.0/26",
        ],
        "hard_deny_ranges": [
            "31.31.140.0-31.31.140.87",
            "31.31.140.92-31.31.140.254",
            "31.31.143.0-31.31.143.71",
        ],
    },
    "include_overrides": {
        "cidrs": [
            "31.31.128.0/24", "31.31.140.0/24", "31.31.141.0/24",
            "31.31.143.0/24", "31.31.143.0/25",
            "31.31.150.0/24", "31.31.158.0/24", "31.31.159.0/24",
            "45.11.166.40/29",
            "79.132.241.0/24",
            "85.234.192.0/24", "85.234.203.0/24", "85.234.204.0/24",
            "85.234.205.0/24",
            "193.110.255.128/28",
            "212.71.0.0/24", "212.71.1.0/24", "212.71.2.0/24",
            "212.71.3.0/24", "212.71.4.0/24", "212.71.5.0/24",
            "212.71.8.0/24", "212.71.11.0/24",
            "213.211.130.0/24", "213.211.138.0/24", "213.211.188.0/24",
            "213.219.128.0/24", "213.219.132.0/24",
        ],
    },
}

# --------------------------------------------------------------------------- #
# Embedded BBOT preset (written to the results directory at run time)
# --------------------------------------------------------------------------- #
EMBEDDED_PRESET = """description: >-
  Citymesh RVDP recon preset (BBOT). Scope and blacklist are generated by
  bbot_monitor.py; this preset only fixes module selection, rate caps and
  output modules.
flags:
  - subdomain-enum
require_flags:
  - passive
exclude_modules:
  # Active/intrusive: default credentials, brute force, fuzzing, exploitation.
  - nuclei
  - lightfuzz
  - medusa
  - legba
  - telerik
  - dotnetnuke
  - waf_bypass
  - bypass403
  - generic_ssrf
  - baddns
  - baddns_direct
  - baddns_zone
  - portscan
  - webbrute
  - webbrute_shortnames
  - paramminer_cookies
  - paramminer_getparams
  - paramminer_headers
  - iis_shortnames
  - hunt
  # DNS brute force. `require_flags: passive` already prevents this, but the
  # exclusion is repeated so a flag edit cannot silently turn it back on.
  - dnsbrute
  - dnsbrute_mutations
  # Outbound downloads / third-party API pulls that add noise or latency.
  - postman_download
  - docker_pull
  - filedownload
  - apkpure
  - google_playstore
  - jadx
  - gowitness
config:
  # Program cap is 20 req/s; run at 15 to leave headroom.
  web:
    http_rate_limit: 15
    http_timeout: 10
    http_retries: 1
    spider_depth: 1
    spider_distance: 0
    spider_links_per_page: 25
  dns:
    threads: 15
    brute_threads: 50
  scope:
    search_distance: 0
    report_distance: 0
  deps:
    behavior: ignore_failed
output_modules:
  - subdomains
  - json
  - asset_inventory
  - txt
"""

# Modules that must never run, regardless of what the preset says.
FORBIDDEN_MODULES = [
    "nuclei", "lightfuzz", "medusa", "legba", "telerik", "dotnetnuke",
    "waf_bypass", "bypass403", "generic_ssrf",
    "baddns", "baddns_direct", "baddns_zone",
    "portscan", "webbrute", "webbrute_shortnames",
    "paramminer_cookies", "paramminer_getparams", "paramminer_headers",
    "iis_shortnames", "hunt",
    "dnsbrute", "dnsbrute_mutations",
]

# BBOT scope descriptions that mean "this event is inside the scanned scope".
IN_SCOPE_DESCRIPTIONS = {"in-scope", "affiliate", "distance-1"}

# --------------------------------------------------------------------------- #
# scope: config loading
# --------------------------------------------------------------------------- #
def load_config(path: str | None) -> dict:
    """Embedded model by default; an external YAML file when --scope-config is given."""
    if not path:
        return EMBEDDED_SCOPE
    import yaml  # local import so the embedded path needs no dependency
    with open(path, encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}
    for key in ("targets", "exclude"):
        if key not in cfg:
            raise ValueError(f"scope config missing required top-level key: {key}")
    return cfg


def _nets(values) -> list:
    return [ipaddress.ip_network(str(v), strict=False) for v in (values or [])]


def _range_pairs(values) -> list:
    out = []
    for raw in values or []:
        text = str(raw).strip()
        if "-" in text:
            lo, hi = (p.strip() for p in text.split("-", 1))
            out.append((ipaddress.ip_address(lo), ipaddress.ip_address(hi)))
        else:
            net = ipaddress.ip_network(text, strict=False)
            out.append((net.network_address, net.broadcast_address))
    return out


# --------------------------------------------------------------------------- #
# scope: decision engine
# --------------------------------------------------------------------------- #
class Scope:
    """Most-specific-match wins, hard-deny ranges always win, default allow."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.domains = [str(d).strip().lower().lstrip(".") for d in cfg["targets"].get("domains", [])]
        self.urls = [str(u) for u in cfg["targets"].get("urls", [])]
        self.exclude_hosts = [str(h).strip().lower().lstrip(".") for h in cfg["exclude"].get("hostnames", [])]
        self.exclusions = _nets(cfg["exclude"].get("cidrs"))
        self.includes = _nets(cfg.get("include_overrides", {}).get("cidrs"))
        # A bare IP entry must fall inside a published in-scope range; the
        # default-allow rule exists only for CDN edge addresses reached through
        # a hostname that is itself in a target domain.
        self.declared_ranges = _nets(cfg["targets"].get("ip_ranges")) + self.includes
        self.hard_deny = _range_pairs(cfg["exclude"].get("hard_deny_ranges"))
        self.rules = [(n, False) for n in self.exclusions] + [(n, True) for n in self.includes]

    # -- hostname rules ---------------------------------------------------- #
    def hostname_excluded(self, hostname: str) -> str | None:
        host = hostname.strip().lower().rstrip(".")
        for ex in self.exclude_hosts:
            if host == ex or host.endswith("." + ex):
                return ex
        return None

    def hostname_in_scope(self, hostname: str) -> bool:
        host = hostname.strip().lower().rstrip(".")
        return any(host == d or host.endswith("." + d) for d in self.domains)

    # -- IP rules ---------------------------------------------------------- #
    def ip_verdict(self, ip) -> tuple[bool, str]:
        """Return (in_scope, reason) for one address."""
        addr = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(ip)

        # Hard-deny carve-outs are not CIDR-aligned, so they are checked
        # directly and beat every network rule.
        for lo, hi in self.hard_deny:
            if lo.version == addr.version and lo <= addr <= hi:
                return False, f"{addr} in hard-deny range {lo}-{hi}"

        best = None
        for net, allow in self.rules:
            if net.version == addr.version and addr in net:
                if best is None or net.prefixlen > best[0]:
                    best = (net.prefixlen, allow, net)

        if best is None:
            # Never drop a host because an unlisted CDN edge IP answered for it.
            # Hostname membership is checked separately.
            return True, f"{addr} matched no rule (default allow)"

        if not best[1]:
            return False, f"{addr} excluded by {best[2]}"
        return True, f"{addr} allowed by {best[2]}"

    def ip_declared(self, ip) -> bool:
        """True when the address sits inside a range the program publishes as in scope."""
        addr = ip if isinstance(ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(ip)
        return any(net.version == addr.version and addr in net for net in self.declared_ranges)

    # -- effective out-of-scope set (BBOT blacklist) ----------------------- #
    def effective_exclude_networks(self) -> list:
        """Every address this engine rejects, collapsed back to CIDRs.

        Derived from ip_verdict() rather than re-implementing precedence, so the
        blacklist and the filter can never disagree.
        """
        candidates: set = set()
        for net in self.exclusions:
            count = net.num_addresses
            if count > MAX_ENUM_ADDRESSES:
                raise ValueError(f"exclusion {net} is too large to enumerate ({count} addresses)")
            candidates.update(net)
        for lo, hi in self.hard_deny:
            for net in ipaddress.summarize_address_range(lo, hi):
                candidates.update(net)

        blocked = [a for a in candidates if not self.ip_verdict(a)[0]]
        if not blocked:
            return []
        return list(ipaddress.collapse_addresses(sorted(blocked)))

    def blacklist_entries(self) -> list[str]:
        entries = [str(n) for n in self.effective_exclude_networks()]
        entries += self.exclude_hosts
        return entries

    def targets(self) -> list[str]:
        return [str(d).strip() for d in self.cfg["targets"].get("domains", []) if str(d).strip()]


# --------------------------------------------------------------------------- #
# scope: entry handling
# --------------------------------------------------------------------------- #
def host_of(entry: str) -> str:
    """Extract a resolvable hostname from a URL/host:port line or a bare host."""
    text = entry.strip()
    if not text:
        return ""
    if "://" in text:
        netloc = urllib.parse.urlparse(text).netloc
    else:
        netloc = text.split("/", 1)[0]
    netloc = netloc.rsplit("@", 1)[-1]
    if netloc.startswith("[") and "]" in netloc:  # IPv6 literal
        return netloc[1:netloc.index("]")].lower()
    return netloc.split(":", 1)[0].lower()


def resolve(host: str) -> list:
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return []
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0]))
        except ValueError:
            continue
    return sorted(set(out))


def verdict_for_entry(scope: Scope, entry: str, do_resolve: bool = True) -> tuple[bool, str]:
    host = host_of(entry)
    if not host:
        return False, "no hostname parsed"

    excluded = scope.hostname_excluded(host)
    if excluded:
        return False, f"hostname matches excluded entry '{excluded}'"

    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None

    if addr is not None:
        ok, why = scope.ip_verdict(addr)
        if not ok:
            return False, why
        if not scope.ip_declared(addr):
            return False, f"{addr} is not inside any in-scope IP range"
        return True, why

    if not scope.hostname_in_scope(host):
        return False, "hostname outside target domains"

    if not do_resolve:
        return True, "in target domain"

    ips = resolve(host)
    if not ips:
        return False, "unresolved - recorded but not scanned"

    for ip in ips:
        ok, why = scope.ip_verdict(ip)
        if not ok:
            return False, why
    return True, ",".join(str(i) for i in ips)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(f"[bbot-monitor] {msg}", flush=True)


def read_lines(path: str) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return []


def write_lines(path: str, rows) -> None:
    rows = list(rows)
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("".join(f"{r}\n" for r in rows))


# --------------------------------------------------------------------------- #
# BBOT integration
# --------------------------------------------------------------------------- #
def materialise_preset(results_dir: str, preset_path: str | None) -> str:
    """Use --preset when given, otherwise write the embedded preset next to results."""
    path = os.path.join(results_dir, "bbot-preset.yml")
    if preset_path:
        if not os.path.isfile(preset_path):
            raise ValueError(f"preset not found: {preset_path}")
        return os.path.abspath(preset_path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(EMBEDDED_PRESET)
    return path


def build_command(args, targets_file: str, blacklist_file: str, preset_file: str) -> list[str]:
    """Assemble the BBOT argv. One -H carrying both identifying headers."""
    headers = [f"User-Agent={args.user_agent}", f"X-Intigriti-Username={args.handle}"]
    cmd = [
        args.bbot,
        "-t", targets_file,
        "-b", blacklist_file,
        "-p", preset_file,
        "-o", args.output_dir,
        "-n", args.scan_name,
        "-em", *FORBIDDEN_MODULES,
        "-c", f"web.http_rate_limit={args.rps}",
        "-H", *headers,
        "--ignore-failed-deps",
        "--no-color",
    ]
    if args.silent:
        cmd.append("-S")
    return cmd


def run_subprocess(cmd: list[str], log_path: str) -> int:
    log(f"exec: {' '.join(cmd)}")
    with open(log_path, "w", encoding="utf-8") as fh:
        proc = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, text=True)
    return proc.returncode


def resolve_scan_dir(bbot_out: str, scan_name: str) -> str | None:
    """BBOT suffixes the scan name when the directory already exists."""
    exact = os.path.join(bbot_out, scan_name)
    if os.path.isdir(exact):
        return exact
    candidates = [d for d in sorted(os.listdir(bbot_out)) if os.path.isdir(os.path.join(bbot_out, d))]
    if not candidates:
        return None
    newest = max(candidates, key=lambda d: os.path.getmtime(os.path.join(bbot_out, d)))
    return os.path.join(bbot_out, newest)


def normalise_outputs(scan_dir: str, results_dir: str) -> dict:
    """Translate BBOT's scan directory into the pipeline's flat artifacts."""
    stats: dict = {}
    subdomains = sorted(set(read_lines(os.path.join(scan_dir, "subdomains.txt"))))
    write_lines(os.path.join(results_dir, "bbot_subdomains.txt"), subdomains)
    stats["subdomains"] = len(subdomains)

    urls, findings, technologies, open_ports = [], [], [], []
    for line in read_lines(os.path.join(scan_dir, "output.json")):
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        if event.get("scope_description") not in IN_SCOPE_DESCRIPTIONS:
            continue

        etype = event.get("type")
        if etype == "URL":
            data = event.get("data") or event.get("url")
            if data and event.get("host"):
                urls.append(str(data))
        elif etype == "TECHNOLOGY":
            data = event.get("data_json") or {}
            tech = data.get("technology") if isinstance(data, dict) else None
            host = event.get("host")
            if tech and host:
                technologies.append(f"{host}\t{tech}")
        elif etype == "OPEN_TCP_PORT":
            data = event.get("data")
            if data:
                open_ports.append(str(data))
        elif etype == "FINDING":
            data = event.get("data_json") or {}
            if not isinstance(data, dict):
                continue
            findings.append({
                "host": event.get("host"),
                "name": data.get("name"),
                "severity": str(data.get("severity", "INFO")).upper(),
                "confidence": str(data.get("confidence", "")).upper(),
                "description": data.get("description"),
                "module": event.get("module"),
                "discovery_context": event.get("discovery_context"),
            })

    write_lines(os.path.join(results_dir, "bbot_urls.txt"), sorted(set(urls)))
    write_lines(os.path.join(results_dir, "bbot_technologies.txt"), sorted(set(technologies)))
    write_lines(os.path.join(results_dir, "bbot_open_ports.txt"), sorted(set(open_ports)))
    with open(os.path.join(results_dir, "bbot_findings.json"), "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, sort_keys=True)

    # Human-readable feed. Severity/confidence tags are carried through so
    # speculative passive findings are never mistaken for confirmed ones.
    readable = [
        f"{f.get('host')} [{f.get('severity')}/{f.get('confidence') or 'n/a'}] "
        f"{f.get('name')} ({f.get('module')})"
        for f in findings
    ]
    write_lines(os.path.join(results_dir, "bbot_findings.txt"), sorted(set(readable)))
    stats["urls"] = len(set(urls))
    stats["technologies"] = len(set(technologies))
    stats["open_ports"] = len(set(open_ports))
    stats["findings"] = len(findings)
    return stats


# --------------------------------------------------------------------------- #
# subcommands
# --------------------------------------------------------------------------- #
def cmd_blacklist(args) -> int:
    scope = Scope(load_config(args.scope_config))
    entries = scope.blacklist_entries()
    text = "\n".join(entries) + ("\n" if entries else "")
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
    if args.print:
        sys.stdout.write(text)
    print(f"[scope] wrote {len(entries)} blacklist entr(y/ies) to {args.output or 'stdout'}", file=sys.stderr)
    return 0


def cmd_filter(args) -> int:
    scope = Scope(load_config(args.scope_config))
    lines = read_lines(args.input)
    keep, drop = [], []
    for line in lines:
        ok, why = verdict_for_entry(scope, line, do_resolve=not args.no_resolve)
        (keep if ok else drop).append((line, why))
    if args.output:
        write_lines(args.output, (h for h, _ in keep))
    if args.dropped:
        write_lines(args.dropped, (f"{h}  [{why}]" for h, why in drop))
    if args.report:
        write_lines(args.report, (f"{h}  [{why}]" for h, why in keep))
    unresolved = [d for d in drop if "unresolved" in d[1]]
    print(f"[scope] kept {len(keep)}, dropped {len(drop)} of {len(lines)} "
          f"({len(unresolved)} unresolved)")
    for entry, why in drop:
        print(f"  DROP {entry}  [{why}]")

    # Fail closed, but distinguish the two causes:
    #  * every resolvable entry rejected -> the scope model or target list is
    #    wrong, so stop and let a human look.
    #  * everything merely unresolved -> DNS problem, not a scope statement.
    if lines and not keep:
        actionable = [d for d in drop if "unresolved" not in d[1]]
        if actionable:
            print("[scope] ERROR: every resolvable entry was filtered out - "
                  "check the scope model", file=sys.stderr)
            return 3
        print("[scope] WARNING: every entry failed to resolve; continuing with an empty "
              "in-scope set (DNS problem, not a scope decision)", file=sys.stderr)
        return 0
    return 0


def cmd_check(args) -> int:
    scope = Scope(load_config(args.scope_config))
    ok, why = verdict_for_entry(scope, args.entry, do_resolve=not args.no_resolve)
    print(f"{'IN SCOPE' if ok else 'OUT OF SCOPE'}: {args.entry}  [{why}]")
    return 0 if ok else 1


def cmd_dump(args) -> int:
    scope = Scope(load_config(args.scope_config))
    print(json.dumps({
        "program": scope.cfg.get("program"),
        "domains": len(scope.domains),
        "urls": len(scope.urls),
        "ip_ranges": len(scope.cfg["targets"].get("ip_ranges", [])),
        "exclude_hostnames": scope.exclude_hosts,
        "effective_exclude_cidrs": [str(n) for n in scope.effective_exclude_networks()],
        "blacklist_entries": scope.blacklist_entries(),
    }, indent=2))
    return 0


def cmd_selftest(args) -> int:
    """Assert the embedded scope model and preset still match the program page."""
    scope = Scope(load_config(args.scope_config))
    failures = []

    ip_checks = [
        ("31.31.140.10", False, "hard-deny 31.31.140.0-87"),
        ("31.31.140.50", False, "hard-deny 31.31.140.0-87"),
        ("31.31.140.88", True, "gap between hard-deny ranges, /24 in scope"),
        ("31.31.140.90", True, "in-scope window 31.31.140.88-91"),
        ("31.31.140.91", True, "last address of the in-scope window"),
        ("31.31.140.93", False, "hard-deny 31.31.140.92-254"),
        ("31.31.140.255", True, "255 is outside the hard-deny stop at .254"),
        ("31.31.143.10", False, "hard-deny 31.31.143.0-71"),
        ("31.31.143.72", True, "above the hard-deny range in 31.31.143.0/24"),
        ("31.31.143.200", True, "above the hard-deny range"),
        ("31.31.136.5", False, "inside excluded /21, no override"),
        ("31.31.138.5", False, "inside excluded /21, no override"),
        ("31.31.139.5", False, "excluded /24 inside the /21"),
        ("31.31.142.5", False, "excluded /21 remainder, no override"),
        ("31.31.141.5", False, "excluded /26 beats the in-scope /24"),
        ("31.31.141.100", True, "in-scope remainder of 31.31.141.0/24"),
        ("31.31.128.10", True, "in-scope /24"),
        ("31.31.128.70", False, "excluded /26 inside the in-scope /24"),
        ("31.31.130.5", False, "excluded /23"),
        ("212.71.0.10", True, "in-scope /24"),
        ("45.11.166.42", True, "in-scope /29"),
        ("193.110.255.130", True, "in-scope /28"),
        ("193.110.255.140", True, "default allow past the /28"),
        ("8.8.8.8", True, "default allow (CDN edge protection)"),
    ]
    for entry, expected, note in ip_checks:
        ok, why = scope.ip_verdict(ipaddress.ip_address(entry))
        if ok != expected:
            failures.append(f"{entry}: expected in_scope={expected}, got {ok} [{why}] ({note})")

    # Bare IPs outside every declared range must be rejected as entries even
    # though ip_verdict() default-allows them.
    entry_checks = [
        ("46.4.1.1", False, "not in any declared in-scope range"),
        ("8.8.8.8", False, "not in any declared in-scope range"),
        ("212.71.0.10", True, "inside declared 212.71.0.0/24"),
        ("45.11.166.42", True, "inside declared 45.11.166.40/29"),
    ]
    for entry, expected, note in entry_checks:
        ok, why = verdict_for_entry(scope, entry, do_resolve=False)
        if ok != expected:
            failures.append(f"entry {entry}: expected in_scope={expected}, got {ok} [{why}] ({note})")

    host_checks = [
        ("digi-mobile.be", False),
        ("www.digi-mobile.be", False),
        ("foo.static.edpnet.net", False),
        ("static.edpnet.net", False),
        ("a.dyn.edpnet.net", False),
        ("citymesh.com", True),
        ("a.citymesh.com", True),
        ("notcitymesh.com", False),
        ("citymesh.com.evil.tld", False),
    ]
    for host, expected in host_checks:
        ok, why = verdict_for_entry(scope, host, do_resolve=False)
        if ok != expected:
            failures.append(f"{host}: expected in_scope={expected}, got {ok} [{why}]")

    # Blacklist shape: carved-out ranges present, in-scope ranges absent.
    blocked = {str(n) for n in scope.effective_exclude_networks()}
    for must in ("31.31.136.0/22", "31.31.142.0/24", "31.31.130.0/23", "31.31.128.64/26"):
        if must not in blocked:
            failures.append(f"blacklist is missing {must}")
    for must_not in ("31.31.141.0/24", "31.31.140.0/24", "31.31.128.0/24", "212.71.0.0/24"):
        if must_not in blocked:
            failures.append(f"blacklist wrongly contains {must_not}")

    # Every blacklisted network must itself be rejected by the engine.
    for net in scope.effective_exclude_networks():
        for addr in (net.network_address, net.broadcast_address):
            if scope.ip_verdict(addr)[0]:
                failures.append(f"blacklist contains {net} but {addr} is in scope")

    # Preset safety: every forbidden module excluded, passive required, and the
    # argv carries both identifying headers on a single -H.
    try:
        import yaml
        preset = yaml.safe_load(EMBEDDED_PRESET) or {}
        excluded = set(preset.get("exclude_modules") or [])
        missing = [m for m in FORBIDDEN_MODULES if m not in excluded]
        if missing:
            failures.append(f"embedded preset does not exclude: {missing}")
        if "passive" not in (preset.get("require_flags") or []):
            failures.append("embedded preset does not require the passive flag")
    except ImportError:
        print("[scope] note: pyyaml missing, skipping preset assertions", file=sys.stderr)

    class _A:
        bbot = "bbot"
        output_dir = "/tmp"
        scan_name = "citymesh"
        rps = 15
        user_agent = "Intigriti-VDP-SubdomainMonitor/1.0"
        handle = "handle"
        silent = False

    argv = build_command(_A(), "t.txt", "b.txt", "p.yml")
    if argv.count("-H") != 1:
        failures.append(f"argv must carry exactly one -H, found {argv.count('-H')}")
    else:
        tail = argv[argv.index("-H") + 1:]
        pairs = []
        for token in tail:
            if token.startswith("-"):
                break
            pairs.append(token)
        if not any(p.startswith("User-Agent=") for p in pairs) or not any(p.startswith("X-Intigriti-Username=") for p in pairs):
            failures.append(f"-H does not carry both identifying headers: {pairs}")
    if "-em" not in argv:
        failures.append("argv does not pin the module exclusion list")

    if failures:
        print("[scope] SELFTEST FAILED", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"[scope] selftest passed ({len(ip_checks)} IP, {len(host_checks)} hostname, "
          f"{len(blocked)} blacklist-net, {len(entry_checks)} entry, argv + preset assertions)")
    return 0


def cmd_run(args) -> int:
    """Full discovery stage: targets -> blacklist -> BBOT -> normalise -> verify scope."""
    scope = Scope(load_config(args.scope_config))

    if not args.handle:
        if args.require_handle:
            print("[bbot-monitor] FATAL: INTIGRITI_USERNAME secret is empty; refusing to run "
                  "without the program-required identifying header.", file=sys.stderr)
            return 4
        log("WARNING: INTIGRITI_USERNAME is empty - requests will lack the required "
            "X-Intigriti-Username header. Set the repo secret before real runs.")

    results_dir = os.path.abspath(args.results_dir)
    os.makedirs(results_dir, exist_ok=True)
    args.output_dir = os.path.abspath(args.output_dir or os.path.join(results_dir, "bbot"))
    os.makedirs(args.output_dir, exist_ok=True)

    targets = scope.targets()
    if not targets:
        print("[bbot-monitor] FATAL: the scope model lists no target domains", file=sys.stderr)
        return 2
    targets_file = os.path.join(results_dir, "bbot_targets.txt")
    write_lines(targets_file, targets)
    log(f"targets: {len(targets)} domains")

    blacklist_file = os.path.join(results_dir, "bbot_blacklist.txt")
    write_lines(blacklist_file, scope.blacklist_entries())
    log(f"blacklist: {len(read_lines(blacklist_file))} entries")

    preset_file = materialise_preset(results_dir, args.preset)
    cmd = build_command(args, targets_file, blacklist_file, preset_file)
    if args.dry_run:
        print(json.dumps(cmd, indent=2))
        return 0

    log_path = os.path.join(results_dir, "bbot_run.log")
    started = time.time()
    try:
        rc = run_subprocess(cmd, log_path)
    except FileNotFoundError:
        print(f"[bbot-monitor] FATAL: '{args.bbot}' not found. Install with: pip install bbot",
              file=sys.stderr)
        return 2

    elapsed = int(time.time() - started)
    log(f"bbot exited {rc} after {elapsed}s (log: {log_path})")

    scan_dir = resolve_scan_dir(args.output_dir, args.scan_name)
    if scan_dir is None:
        print(f"[bbot-monitor] FATAL: BBOT produced no scan directory in {args.output_dir}",
              file=sys.stderr)
        return 1
    log(f"scan directory: {scan_dir}")

    stats = normalise_outputs(scan_dir, results_dir)
    log("normalised: " + ", ".join(f"{k}={v}" for k, v in sorted(stats.items())))

    # Verify discovery output against the same engine that produced the
    # blacklist. BBOT should already be clean; this proves it rather than
    # trusting it.
    kept, dropped = [], []
    for entry in read_lines(os.path.join(results_dir, "bbot_subdomains.txt")):
        ok, why = verdict_for_entry(scope, entry, do_resolve=True)
        (kept if ok else dropped).append((entry, why))
    write_lines(os.path.join(results_dir, "in_scope.txt"), (h for h, _ in kept))
    write_lines(os.path.join(results_dir, "out_of_scope.txt"), (f"{h}  [{w}]" for h, w in dropped))
    stats["verified_in_scope"] = len(kept)
    stats["verified_out_of_scope"] = len(dropped)
    log(f"scope verification: {len(kept)} kept, {len(dropped)} dropped")

    with open(os.path.join(results_dir, "bbot_summary.json"), "w", encoding="utf-8") as fh:
        json.dump({"exit_code": rc, "elapsed_seconds": elapsed, "scan_dir": scan_dir, **stats},
                  fh, indent=2)

    # Partial results beat no results: a non-zero exit is recorded and the
    # caller decides whether coverage was adequate.
    if rc != 0:
        log("WARNING: BBOT returned non-zero; using whatever output it produced")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scope-config", default=None,
                        help="optional external scope YAML; embedded model is used by default")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("selftest", help="assert the built-in scope model and preset")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("check", help="check one host, IP or URL")
    p.add_argument("entry")
    p.add_argument("--no-resolve", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("blacklist", help="emit a BBOT-compatible blacklist file")
    p.add_argument("-o", "--output")
    p.add_argument("--print", action="store_true")
    p.set_defaults(func=cmd_blacklist)

    p = sub.add_parser("filter", help="filter a host/URL list down to in-scope entries")
    p.add_argument("-i", "--input", required=True)
    p.add_argument("-o", "--output")
    p.add_argument("--dropped")
    p.add_argument("--report")
    p.add_argument("--no-resolve", action="store_true")
    p.set_defaults(func=cmd_filter)

    p = sub.add_parser("dump", help="print the resolved scope model as JSON")
    p.set_defaults(func=cmd_dump)

    p = sub.add_parser("run", help="discover with BBOT, then verify scope")
    p.add_argument("--results-dir", required=True, help="pipeline results directory")
    p.add_argument("--output-dir", help="root directory BBOT writes scans into")
    p.add_argument("--preset", help="external preset YAML (default: embedded preset)")
    p.add_argument("--bbot", default=os.environ.get("BBOT_BIN", "bbot"))
    p.add_argument("--rps", type=int, default=15, help="target-directed request cap")
    p.add_argument("--handle", default=os.environ.get("INTIGRITI_H", ""))
    p.add_argument("--user-agent",
                   default=os.environ.get("INTIGRITI_UA", "Intigriti-VDP-SubdomainMonitor/1.0"))
    p.add_argument("--scan-name", default="citymesh")
    p.add_argument("--silent", action="store_true")
    p.add_argument("--dry-run", action="store_true", help="print the BBOT argv and exit")
    p.add_argument("--require-handle", action="store_true",
                   help="fail instead of running with an empty X-Intigriti-Username")
    p.set_defaults(func=cmd_run)

    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (OSError, ValueError) as exc:
        print(f"[bbot-monitor] error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
