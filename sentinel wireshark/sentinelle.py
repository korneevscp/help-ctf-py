#!/usr/bin/env python3
"""Moteur d'analyse Sentinelle : extraction tshark et règles heuristiques."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

FIELDS = (
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "udp.srcport",
    "udp.dstport",
    "dns.qry.name",
    "dns.flags.response",
)

COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 853, 993, 995, 1900,
    3389, 5353, 5355, 8080, 8443,
}

SUSPICIOUS_PORTS = {1337, 4444, 4445, 5555, 6666, 6667, 9001, 9050, 12345, 31337}

CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 69: "TFTP", 110: "POP3", 143: "IMAP"}

SEVERITY_ORDER = {"ÉLEVÉ": 0, "MOYEN": 1, "INFO": 2}

TRUE_VALUES = {"1", "true", "True", "TRUE"}


@dataclass
class Packet:
    time: float | None
    src: str
    dst: str
    proto: str
    sport: int | None
    dport: int | None
    syn: bool = False
    ack: bool = False
    dns_query: str | None = None
    dns_response: bool = False


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    detail: str
    evidence: dict = field(default_factory=dict)


@dataclass
class Summary:
    paquets_ip: int
    flux_uniques: int
    alertes: int
    debut_utc: str | None
    fin_utc: str | None


def find_tshark(explicit: str | None = None) -> str:
    candidates = [explicit, os.environ.get("TSHARK_PATH"), shutil.which("tshark")]

    for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)")):
        if base:
            candidates.append(str(Path(base) / "Wireshark" / "tshark.exe"))

    candidates.append(r"C:\Program Files\Wireshark\tshark.exe")

    candidates.append("/Applications/Wireshark.app/Contents/MacOS/tshark")

    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return str(candidate)

    raise RuntimeError(
        "tshark introuvable. Installez Wireshark (avec tshark) ou définissez "
        "la variable d'environnement TSHARK_PATH vers tshark.exe."
    )


def run_tshark(tshark: str, capture: Path, timeout: int) -> list[str]:
    cmd = [tshark, "-r", str(capture), "-n", "-Y", "ip or ipv6", "-T", "fields",
           "-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n"]

    for name in FIELDS:
        cmd += ["-e", name]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"tshark a dépassé le délai de {timeout} s.") from exc

    except FileNotFoundError as exc:
        raise RuntimeError(f"Impossible d'exécuter tshark : {tshark}") from exc

    if proc.returncode != 0 and not proc.stdout.strip():
        message = proc.stderr.strip() or f"code retour {proc.returncode}"

        raise RuntimeError(f"tshark a échoué : {message}")

    return proc.stdout.splitlines()


def _int(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _float(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def parse_line(line: str) -> Packet | None:
    parts = line.rstrip("\r\n").split("\t")

    parts += [""] * (len(FIELDS) - len(parts))

    row = dict(zip(FIELDS, parts))

    src = row["ip.src"] or row["ipv6.src"]

    dst = row["ip.dst"] or row["ipv6.dst"]

    if not src or not dst:
        return None

    if row["tcp.srcport"] or row["tcp.dstport"]:
        proto = "tcp"

        sport = _int(row["tcp.srcport"])

        dport = _int(row["tcp.dstport"])

    elif row["udp.srcport"] or row["udp.dstport"]:
        proto = "udp"

        sport = _int(row["udp.srcport"])

        dport = _int(row["udp.dstport"])

    else:
        proto = "other"

        sport = None

        dport = None

    return Packet(
        time=_float(row["frame.time_epoch"]),
        src=src,
        dst=dst,
        proto=proto,
        sport=sport,
        dport=dport,
        syn=row["tcp.flags.syn"] in TRUE_VALUES,
        ack=row["tcp.flags.ack"] in TRUE_VALUES,
        dns_query=row["dns.qry.name"].lower().rstrip(".") or None,
        dns_response=row["dns.flags.response"] in TRUE_VALUES,
    )


def parse_lines(lines) -> list[Packet]:
    packets = []

    for line in lines:
        packet = parse_line(line)

        if packet:
            packets.append(packet)

    return packets


def _opt(args, name: str, default):
    value = getattr(args, name, None)

    return default if value is None else value


def _base_domain(name: str) -> str:
    labels = [label for label in name.split(".") if label]

    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def _sample(values, limit: int = 10) -> str:
    items = sorted(values)

    text = ", ".join(str(item) for item in items[:limit])

    return text + (" …" if len(items) > limit else "")


def detect_port_scans(packets, threshold: int) -> list[Finding]:
    vertical = defaultdict(set)

    horizontal = defaultdict(set)

    for p in packets:
        if p.dport is None:
            continue

        if p.proto == "tcp" and p.syn and not p.ack:
            vertical[(p.src, p.dst)].add(p.dport)

            horizontal[(p.src, p.dport)].add(p.dst)

    findings = []

    for (src, dst), ports in vertical.items():
        if len(ports) >= threshold:
            findings.append(Finding(
                rule="SCAN_PORTS",
                severity="ÉLEVÉ",
                title="Scan de ports vertical",
                detail=f"{src} a tenté d'ouvrir des connexions TCP vers {len(ports)} ports distincts de {dst}.",
                evidence={"source": src, "destination": dst, "ports_distincts": len(ports), "exemples": _sample(ports)},
            ))

    for (src, port), targets in horizontal.items():
        if len(targets) >= threshold:
            findings.append(Finding(
                rule="SCAN_HORIZONTAL",
                severity="MOYEN",
                title="Balayage horizontal",
                detail=f"{src} a sondé le port {port} sur {len(targets)} hôtes différents.",
                evidence={"source": src, "port": port, "hotes": len(targets), "exemples": _sample(targets, 5)},
            ))

    return findings


def detect_syn_floods(packets, threshold: int) -> list[Finding]:
    syn = Counter()

    syn_ack = Counter()

    for p in packets:
        if p.proto != "tcp" or not p.syn:
            continue

        if p.ack:
            syn_ack[(p.dst, p.src)] += 1

        else:
            syn[(p.src, p.dst)] += 1

    findings = []

    for (src, dst), count in syn.items():
        if count < threshold:
            continue

        answered = syn_ack.get((src, dst), 0)

        ratio = answered / count

        findings.append(Finding(
            rule="SYN_FLOOD",
            severity="ÉLEVÉ" if ratio < 0.5 else "MOYEN",
            title="Volume anormal de SYN",
            detail=f"{src} a envoyé {count} paquets SYN vers {dst} ; seulement {answered} SYN-ACK en retour.",
            evidence={"source": src, "destination": dst, "syn": count, "syn_ack": answered, "taux_reponse": f"{ratio:.0%}"},
        ))

    return findings


def detect_dns(packets, volume_threshold: int, chars_threshold: int) -> list[Finding]:
    per_source = Counter()

    per_source_domains = defaultdict(set)

    per_source_server = defaultdict(Counter)

    tunnel_chars = Counter()

    tunnel_count = Counter()

    tunnel_example = {}

    tunnel_server = defaultdict(Counter)

    for p in packets:
        if not p.dns_query or p.dns_response:
            continue

        per_source[p.src] += 1

        per_source_domains[p.src].add(p.dns_query)

        per_source_server[p.src][p.dst] += 1

        base = _base_domain(p.dns_query)

        sub = p.dns_query[: -len(base)].rstrip(".") if p.dns_query.endswith(base) else ""

        key = (p.src, base)

        tunnel_chars[key] += len(sub)

        tunnel_count[key] += 1

        tunnel_server[key][p.dst] += 1

        if len(sub) > len(tunnel_example.get(key, "")):
            tunnel_example[key] = p.dns_query

    findings = []

    for src, count in per_source.items():
        if count >= volume_threshold:
            server = per_source_server[src].most_common(1)[0][0]

            findings.append(Finding(
                rule="DNS_VOLUME",
                severity="MOYEN",
                title="Volume élevé de requêtes DNS",
                detail=f"{src} a émis {count} requêtes DNS ({len(per_source_domains[src])} noms distincts).",
                evidence={"source": src, "destination": server, "requetes": count, "noms_uniques": len(per_source_domains[src])},
            ))

    for (src, base), chars in tunnel_chars.items():
        example = tunnel_example.get((src, base), "")

        longest_label = max((len(label) for label in example.split(".")), default=0)

        if chars < chars_threshold and longest_label < 52:
            continue

        server = tunnel_server[(src, base)].most_common(1)[0][0]

        findings.append(Finding(
            rule="DNS_TUNNEL",
            severity="ÉLEVÉ",
            title="Possible exfiltration / tunnel DNS",
            detail=f"{src} a encodé {chars} caractères dans des sous-domaines de {base} sur {tunnel_count[(src, base)]} requêtes.",
            evidence={"source": src, "destination": server, "domaine": base, "caracteres": chars, "label_max": longest_label, "exemple": example[:120]},
        ))

    return findings


def detect_unusual_ports(packets, threshold: int) -> list[Finding]:
    tcp_flows = {}

    for p in packets:
        if p.proto == "tcp" and p.syn and not p.ack and p.dport is not None:
            tcp_flows[(p.src, p.sport, p.dst, p.dport)] = (p.src, p.dst, p.dport)

    counts = Counter()

    for p in packets:
        if p.proto == "tcp":
            key = tcp_flows.get((p.src, p.sport, p.dst, p.dport)) or tcp_flows.get((p.dst, p.dport, p.src, p.sport))

            if key:
                counts[("tcp",) + key] += 1

        elif p.proto == "udp" and p.sport is not None and p.dport is not None:
            if p.dport < 49152 and p.sport > p.dport and p.dport not in COMMON_PORTS:
                counts[("udp", p.src, p.dst, p.dport)] += 1

    findings = []

    for (proto, src, dst, port), count in counts.items():
        if port in COMMON_PORTS:
            continue

        suspicious = port in SUSPICIOUS_PORTS

        if count < threshold and not suspicious:
            continue

        findings.append(Finding(
            rule="PORT_INHABITUEL",
            severity="ÉLEVÉ" if suspicious else "MOYEN",
            title=f"Trafic {proto.upper()} sur un port {'connu pour être malveillant' if suspicious else 'inhabituel'}",
            detail=f"{count} paquets échangés entre {src} et {dst}:{port}.",
            evidence={"source": src, "destination": dst, "port": port, "protocole": proto.upper(), "paquets": count},
        ))

    return findings


def detect_cleartext(packets) -> list[Finding]:
    seen = set()

    findings = []

    for p in packets:
        if p.dport not in CLEARTEXT_PORTS:
            continue

        if p.proto == "tcp" and not (p.syn and not p.ack):
            continue

        if p.proto == "udp" and p.dport != 69:
            continue

        key = (p.src, p.dst, p.dport)

        if key in seen:
            continue

        seen.add(key)

        name = CLEARTEXT_PORTS[p.dport]

        findings.append(Finding(
            rule="CLAIR",
            severity="MOYEN" if p.dport == 23 else "INFO",
            title=f"Protocole en clair : {name}",
            detail=f"{p.src} a ouvert une session {name} vers {p.dst}. Les identifiants peuvent circuler en clair.",
            evidence={"source": p.src, "destination": p.dst, "port": p.dport},
        ))

    return findings


def detect(packets, args) -> list[Finding]:
    findings = []

    findings += detect_port_scans(packets, _opt(args, "port_scan_threshold", 20))

    findings += detect_syn_floods(packets, _opt(args, "syn_threshold", 100))

    findings += detect_dns(packets, _opt(args, "dns_threshold", 100), _opt(args, "dns_chars_threshold", 500))

    findings += detect_unusual_ports(packets, _opt(args, "unusual_port_threshold", 50))

    scanned = {(f.evidence["source"], f.evidence["destination"]) for f in findings if f.rule == "SCAN_PORTS"}

    findings += [f for f in detect_cleartext(packets) if (f.evidence["source"], f.evidence["destination"]) not in scanned]

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.rule, str(f.evidence.get("source", ""))))

    return findings


def _utc(ts: float | None) -> str | None:
    if ts is None:
        return None

    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def summarize(packets, findings) -> Summary:
    flows = set()

    times = [p.time for p in packets if p.time is not None]

    for p in packets:
        a = (p.src, p.sport)

        b = (p.dst, p.dport)

        flows.add((p.proto,) + tuple(sorted([a, b], key=str)))

    return Summary(
        paquets_ip=len(packets),
        flux_uniques=len(flows),
        alertes=len(findings),
        debut_utc=_utc(min(times)) if times else None,
        fin_utc=_utc(max(times)) if times else None,
    )


def analyze(capture_path, args) -> tuple[list[Finding], Summary]:
    capture = Path(capture_path)

    if not capture.is_file():
        raise RuntimeError(f"Capture introuvable : {capture}")

    tshark = find_tshark(getattr(args, "tshark", None))

    lines = run_tshark(tshark, capture, int(_opt(args, "timeout", 300)))

    packets = parse_lines(lines)

    findings = detect(packets, args)

    return findings, summarize(packets, findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyse heuristique d'une capture PCAP/PCAPNG.")

    parser.add_argument("capture", type=Path)

    parser.add_argument("--tshark", default=None)

    parser.add_argument("--timeout", type=int, default=300)

    parser.add_argument("--port-scan-threshold", type=int, default=20)

    parser.add_argument("--syn-threshold", type=int, default=100)

    parser.add_argument("--dns-threshold", type=int, default=100)

    parser.add_argument("--dns-chars-threshold", type=int, default=500)

    parser.add_argument("--unusual-port-threshold", type=int, default=50)

    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    try:
        findings, summary = analyze(args.capture, args)
    except RuntimeError as exc:
        print(f"[!] {exc}", file=sys.stderr)

        return 1

    print(f"Paquets IP : {summary.paquets_ip} | Flux : {summary.flux_uniques} | Alertes : {summary.alertes}")

    print(f"Période UTC : {summary.debut_utc} -> {summary.fin_utc}\n")

    for f in findings:
        evidence = " · ".join(f"{k}: {v}" for k, v in f.evidence.items())

        print(f"[{f.severity}] {f.rule} — {f.title}\n    {f.detail}\n    {evidence}\n")

    if not findings:
        print("Aucun indicateur détecté.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
