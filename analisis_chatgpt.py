#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
ANALIZADOR FORENSE AVANZADO DE PCAP / PCAPNG
------------------------------------------

Capacidades:
- Estadísticas generales por protocolo
- Top IPs origen y destino
- Tráfico por puertos
- Consultas DNS
- Serie de tiempo de paquetes

Detección de ataques:
- SYN Flood
- DDoS distribuido (múltiples orígenes contra un solo destino)
- Escaneo de puertos
- Puertos inusuales
- DNS sospechoso
- Exceso de RST
- ICMP Unreachable
- DHCP Starvation (agotamiento del pool DHCP)

Requiere:
- scapy
"""

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, BOOTP, DHCP
from collections import Counter, defaultdict
from datetime import datetime
import math


class PcapAnalyzer:

    def __init__(self, filepath, bucket_seconds=5,
                 syn_threshold=100,
                 ddos_threshold=20,
                 scan_port_threshold=20,
                 dhcp_threshold=50):

        self.filepath = filepath
        self.bucket_seconds = bucket_seconds
        self.syn_threshold = syn_threshold
        self.ddos_threshold = ddos_threshold
        self.scan_port_threshold = scan_port_threshold
        self.dhcp_threshold = dhcp_threshold

        # Estadísticas básicas
        self.protocol_counts = Counter()
        self.app_proto_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.dst_port_counts = Counter()
        self.time_buckets = Counter()
        self.dns_queries = Counter()

        # Detección de ataques TCP
        self.syn_flows = Counter()
        self.syn_ack_flows = Counter()
        self.src_dst_ports = defaultdict(set)
        self.rst_counts = Counter()
        self.icmp_unreach = Counter()

        # DDoS distribuido
        self.ddos_targets = defaultdict(set)

        # DHCP Starvation
        self.dhcp_discover = Counter()
        self.dhcp_request = Counter()
        self.dhcp_macs = defaultdict(set)

        self.start_time = None
        self.end_time = None
        self.total_packets = 0

    # -------------------------------------------------------------

    def load_and_analyze(self, limit=None):
        print(f"[+] Cargando archivo: {self.filepath}")
        packets = rdpcap(self.filepath)

        if limit:
            packets = packets[:limit]

        print(f"[+] Paquetes analizados: {len(packets)}\n")

        for pkt in packets:
            self.total_packets += 1
            self._update_time(pkt)
            self._analyze_packet(pkt)

    # -------------------------------------------------------------

    def _update_time(self, pkt):
        if not hasattr(pkt, "time"):
            return

        t = float(pkt.time)

        if self.start_time is None or t < self.start_time:
            self.start_time = t

        if self.end_time is None or t > self.end_time:
            self.end_time = t

        bucket = math.floor(t / self.bucket_seconds) * self.bucket_seconds
        self.time_buckets[bucket] += 1

    # -------------------------------------------------------------

    def _analyze_packet(self, pkt):

        ip_layer = None

        if IP in pkt:
            ip_layer = pkt[IP]
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]

        if not ip_layer:
            self.protocol_counts["non-ip"] += 1
            return

        src = ip_layer.src
        dst = ip_layer.dst

        self.src_ip_counts[src] += 1
        self.dst_ip_counts[dst] += 1

        # ================= TCP =================
        if TCP in pkt:
            self.protocol_counts["TCP"] += 1
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport

            self.dst_port_counts[dport] += 1
            self.src_dst_ports[(src, dst)].add(dport)
            self.ddos_targets[dst].add(src)

            if dport in (80, 8080):
                self.app_proto_counts["HTTP"] += 1
            elif dport == 443:
                self.app_proto_counts["HTTPS"] += 1
            elif dport == 22:
                self.app_proto_counts["SSH"] += 1
            else:
                self.app_proto_counts["TCP_other"] += 1

            flags = tcp.flags

            if flags & 0x02 and not (flags & 0x10):
                self.syn_flows[(src, dst, dport)] += 1

            if flags & 0x12 == 0x12:
                self.syn_ack_flows[(src, dst, sport)] += 1

            if flags & 0x04:
                self.rst_counts[(src, dst)] += 1

        elif UDP in pkt:
            self.protocol_counts["UDP"] += 1
            udp = pkt[UDP]
            dport = udp.dport

            self.dst_port_counts[dport] += 1
            self.src_dst_ports[(src, dst)].add(dport)

            if dport == 53 or DNS in pkt:
                self.app_proto_counts["DNS"] += 1
            else:
                self.app_proto_counts["UDP_other"] += 1

        elif ICMP in pkt:
            self.protocol_counts["ICMP"] += 1
            icmp = pkt[ICMP]

            if hasattr(icmp, "type") and icmp.type == 3:
                self.icmp_unreach[(src, dst)] += 1

        if DNS in pkt and pkt[DNS].qd is not None:
            dns = pkt[DNS]
            if isinstance(dns.qd, DNSQR):
                qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                self.dns_queries[qname] += 1

        # ================= DHCP =================
        if pkt.haslayer(BOOTP) and pkt.haslayer(DHCP):
            mac = pkt[BOOTP].chaddr

            for opt in pkt[DHCP].options:
                if opt[0] == "message-type":
                    msg_type = opt[1]

                    if msg_type == 1:
                        self.dhcp_discover[src] += 1
                        self.dhcp_macs[src].add(mac)

                    elif msg_type == 3:
                        self.dhcp_request[src] += 1
                        self.dhcp_macs[src].add(mac)

    # -------------------------------------------------------------

    def detect_iocs(self):

        findings = {
            "syn_flood": [],
            "ddos_distributed": [],
            "port_scans": [],
            "unusual_ports": [],
            "suspicious_dns": [],
            "high_rst": [],
            "icmp_unreachable": [],
            "dhcp_starvation": []
        }

        for (src, dst, dport), syn in self.syn_flows.items():
            if syn >= self.syn_threshold:
                synack = self.syn_ack_flows.get((dst, src, dport), 0)
                findings["syn_flood"].append({
                    "src": src, "dst": dst, "port": dport,
                    "syn": syn, "syn_ack": synack
                })

        for dst, srcs in self.ddos_targets.items():
            if len(srcs) >= self.ddos_threshold:
                findings["ddos_distributed"].append({
                    "dst": dst, "origenes": len(srcs)
                })

        for (src, dst), ports in self.src_dst_ports.items():
            if len(ports) >= self.scan_port_threshold:
                findings["port_scans"].append({
                    "src": src, "dst": dst, "unique_ports": len(ports)
                })

        common_ports = {80, 443, 22, 53}
        for port, count in self.dst_port_counts.items():
            if port not in common_ports and port > 1024 and count > 10:
                findings["unusual_ports"].append({
                    "port": port, "count": count
                })

        for dom, count in self.dns_queries.items():
            if len(dom) > 50 or dom.count(".") > 4:
                findings["suspicious_dns"].append({
                    "domain": dom, "count": count
                })

        for (src, dst), count in self.rst_counts.items():
            if count > 20:
                findings["high_rst"].append({
                    "src": src, "dst": dst, "count": count
                })

        for (src, dst), count in self.icmp_unreach.items():
            if count > 10:
                findings["icmp_unreachable"].append({
                    "src": src, "dst": dst, "count": count
                })

        for ip in self.dhcp_discover:
            if self.dhcp_discover[ip] >= self.dhcp_threshold and len(self.dhcp_macs[ip]) >= 20:
                findings["dhcp_starvation"].append({
                    "src": ip,
                    "discover": self.dhcp_discover[ip],
                    "unique_macs": len(self.dhcp_macs[ip])
                })

        return findings

    # -------------------------------------------------------------

    def print_basic_stats(self):

        print("\n================ RESUMEN GENERAL ================\n")
        print(f"Archivo: {self.filepath}")
        print(f"Total de paquetes: {self.total_packets}")

        if self.start_time and self.end_time:
            inicio = datetime.fromtimestamp(self.start_time)
            fin = datetime.fromtimestamp(self.end_time)
            print(f"Ventana temporal: {inicio}  ->  {fin}")

        print("\n--- Protocolos ---")
        for proto, cnt in self.protocol_counts.most_common():
            print(f"{proto}: {cnt}")

        print("\n--- Top IP Origen ---")
        for ip, cnt in self.src_ip_counts.most_common(10):
            print(f"{ip}: {cnt}")

        print("\n--- Top IP Destino ---")
        for ip, cnt in self.dst_ip_counts.most_common(10):
            print(f"{ip}: {cnt}")

    # -------------------------------------------------------------

    def print_iocs(self, findings):

        print("\n================= HALLAZGOS =================\n")

        for categoria, datos in findings.items():
            print(f"\n--- {categoria.upper()} ---")
            if not datos:
                print("No se detectaron eventos.")
                continue
            for d in datos:
                print(d)

    # -------------------------------------------------------------

    def print_conclusion(self, findings):

        print("\n================= CONCLUSIÓN AUTOMÁTICA =================\n")

        if findings["ddos_distributed"]:
            for d in findings["ddos_distributed"]:
                print(" ATAQUE DDoS DETECTADO")
                print(f"   Víctima: {d['dst']}")
                print(f"   Orígenes simultáneos: {d['origenes']}\n")
        else:
            print("NO se detectó ataque DDoS distribuido.\n")

        if findings["syn_flood"]:
            print("ATAQUE SYN FLOOD DETECTADO")
            print(f"   Flujos sospechosos: {len(findings['syn_flood'])}\n")
        else:
            print(" NO se detectó SYN Flood.\n")

        if findings["dhcp_starvation"]:
            for d in findings["dhcp_starvation"]:
                print(" ATAQUE DHCP STARVATION DETECTADO")
                print(f"   Origen: {d['src']}")
                print(f"   DHCP DISCOVER: {d['discover']}")
                print(f"   MACs falsas: {d['unique_macs']}\n")
        else:
            print("NO se detectó ataque DHCP Starvation.\n")


# ============================ MAIN ============================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analizador avanzado de ataques en PCAP")
    parser.add_argument("pcap", help="Archivo .pcap o .pcapng")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    analyzer = PcapAnalyzer(filepath=args.pcap)
    analyzer.load_and_analyze(limit=args.limit)
    analyzer.print_basic_stats()

    findings = analyzer.detect_iocs()
    analyzer.print_iocs(findings)
    analyzer.print_conclusion(findings)

    print("\n[+] Análisis completo.")
