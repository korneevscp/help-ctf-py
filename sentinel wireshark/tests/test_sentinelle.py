import argparse
import io
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import sentinelle
from sentinelle import Packet, detect, parse_line, summarize


def args(**overrides):
    base = dict(tshark=None, timeout=300, port_scan_threshold=20, syn_threshold=100,
                dns_threshold=100, dns_chars_threshold=500, unusual_port_threshold=50)

    base.update(overrides)

    return argparse.Namespace(**base)


def syn(src, dst, dport, sport=40000, t=0.0):
    return Packet(t, src, dst, "tcp", sport, dport, syn=True, ack=False)


class ParseTests(unittest.TestCase):

    def test_tcp_line(self):
        line = "1700000000.5\t10.0.0.1\t10.0.0.2\t\t\t5555\t80\t1\t0\t\t\t\t"

        p = parse_line(line)

        self.assertEqual((p.src, p.dst, p.proto, p.sport, p.dport, p.syn, p.ack), ("10.0.0.1", "10.0.0.2", "tcp", 5555, 80, True, False))

    def test_dns_line_true_false_format(self):
        line = "1\t10.0.0.1\t8.8.8.8\t\t\t\t\t\t\t53000\t53\tExample.COM.\tFalse"

        p = parse_line(line)

        self.assertEqual((p.proto, p.dns_query, p.dns_response), ("udp", "example.com", False))

    def test_ipv6_and_short_line(self):
        p = parse_line("1\t\t\tfe80::1\tfe80::2")

        self.assertEqual((p.src, p.dst, p.proto), ("fe80::1", "fe80::2", "other"))

    def test_no_ip(self):
        self.assertIsNone(parse_line("1\t\t\t\t"))


class RuleTests(unittest.TestCase):

    def test_vertical_scan(self):
        packets = [syn("10.0.0.5", "10.0.0.9", port) for port in range(1, 30)]

        rules = {f.rule for f in detect(packets, args())}

        self.assertIn("SCAN_PORTS", rules)

    def test_no_scan_below_threshold(self):
        packets = [syn("10.0.0.5", "10.0.0.9", port) for port in range(1, 10)]

        self.assertNotIn("SCAN_PORTS", {f.rule for f in detect(packets, args())})

    def test_horizontal_scan(self):
        packets = [syn("10.0.0.5", f"10.0.1.{i}", 445) for i in range(25)]

        self.assertIn("SCAN_HORIZONTAL", {f.rule for f in detect(packets, args())})

    def test_syn_flood(self):
        packets = [syn("1.2.3.4", "10.0.0.9", 80, sport=1000 + i) for i in range(150)]

        flood = [f for f in detect(packets, args()) if f.rule == "SYN_FLOOD"]

        self.assertEqual(flood[0].severity, "ÉLEVÉ")

        self.assertEqual(flood[0].evidence["source"], "1.2.3.4")

    def test_dns_tunnel(self):
        packets = [Packet(0, "10.0.0.7", "8.8.8.8", "udp", 50000, 53, dns_query=f"{'a' * 40}{i}.evil.com") for i in range(20)]

        tunnel = [f for f in detect(packets, args()) if f.rule == "DNS_TUNNEL"]

        self.assertEqual(tunnel[0].evidence["domaine"], "evil.com")

    def test_dns_responses_ignored(self):
        packets = [Packet(0, "8.8.8.8", "10.0.0.7", "udp", 53, 50000, dns_query="x.com", dns_response=True) for _ in range(200)]

        self.assertNotIn("DNS_VOLUME", {f.rule for f in detect(packets, args())})

    def test_suspicious_port_reverse_shell(self):
        packets = [syn("10.0.0.2", "6.6.6.6", 4444, sport=50000)]

        packets += [Packet(0, "6.6.6.6", "10.0.0.2", "tcp", 4444, 50000, ack=True) for _ in range(3)]

        hit = [f for f in detect(packets, args()) if f.rule == "PORT_INHABITUEL"]

        self.assertEqual((hit[0].severity, hit[0].evidence["paquets"]), ("ÉLEVÉ", 4))

    def test_telnet_cleartext(self):
        hit = [f for f in detect([syn("10.0.0.2", "10.0.0.3", 23)], args()) if f.rule == "CLAIR"]

        self.assertEqual(hit[0].severity, "MOYEN")

    def test_scan_does_not_trigger_cleartext(self):
        packets = [syn("10.0.0.5", "10.0.0.9", port) for port in range(1, 30)]

        self.assertNotIn("CLAIR", {f.rule for f in detect(packets, args())})

    def test_sorted_by_severity(self):
        packets = [syn("10.0.0.2", "10.0.0.3", 21)] + [syn("10.0.0.5", "10.0.0.9", p) for p in range(100, 130)]

        severities = [f.severity for f in detect(packets, args())]

        self.assertEqual(severities, sorted(severities, key=sentinelle.SEVERITY_ORDER.get))

    def test_summary(self):
        packets = [syn("a", "b", 80, t=0.0), Packet(60.0, "b", "a", "tcp", 80, 40000, syn=True, ack=True)]

        s = summarize(packets, [])

        self.assertEqual((s.paquets_ip, s.flux_uniques, s.debut_utc, s.fin_utc), (2, 1, "1970-01-01 00:00:00", "1970-01-01 00:01:00"))


class AnalyzeTests(unittest.TestCase):

    def test_missing_file(self):
        with self.assertRaises(RuntimeError):
            sentinelle.analyze("/nope.pcap", args())

    def test_missing_tshark(self):
        with mock.patch("sentinelle.shutil.which", return_value=None), \
                mock.patch("sentinelle.Path.is_file", return_value=False), \
                mock.patch.dict("os.environ", {}, clear=True):
            with self.assertRaises(RuntimeError):
                sentinelle.find_tshark(None)

    def test_pipeline_with_fake_tshark(self):
        lines = [f"1\t10.0.0.5\t10.0.0.9\t\t\t40000\t{p}\t1\t0\t\t\t\t" for p in range(1, 40)]

        with mock.patch("sentinelle.find_tshark", return_value="tshark"), \
                mock.patch("sentinelle.run_tshark", return_value=lines), \
                mock.patch("sentinelle.Path.is_file", return_value=True):
            findings, summary = sentinelle.analyze("x.pcap", args())

        self.assertEqual(summary.paquets_ip, 39)

        self.assertIn("SCAN_PORTS", {f.rule for f in findings})


class AppTests(unittest.TestCase):

    def setUp(self):
        import app

        self.app = app

        self.client = app.app.test_client()

    def test_get(self):
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_bad_extension(self):
        resp = self.client.post("/", data={"capture": (io.BytesIO(b"x"), "x.txt")}, content_type="multipart/form-data")

        self.assertEqual(resp.status_code, 400)

    def test_post_renders_report(self):
        finding = sentinelle.Finding("SCAN_PORTS", "ÉLEVÉ", "Scan", "d", {"source": "10.9.9.9", "destination": "10.0.0.1"})

        summary = sentinelle.Summary(10, 2, 1, None, None)

        with mock.patch.object(self.app, "analyze", return_value=([finding], summary)):
            resp = self.client.post("/", data={"capture": (io.BytesIO(b"x"), "c.pcap")}, content_type="multipart/form-data")

        self.assertEqual(resp.status_code, 200)

        self.assertIn(b"10.9.9.9", resp.data)

    def test_tshark_error_shown(self):
        with mock.patch.object(self.app, "analyze", side_effect=RuntimeError("tshark introuvable")):
            resp = self.client.post("/", data={"capture": (io.BytesIO(b"x"), "c.pcap")}, content_type="multipart/form-data")

        self.assertEqual(resp.status_code, 500)

        self.assertIn("tshark introuvable".encode(), resp.data)


if __name__ == "__main__":
    unittest.main()
