#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Analizador forense básico de archivos PCAP/PCAPNG.

Hace:
- Volumen por protocolo (TCP, UDP, ICMP, DNS, HTTP/HTTPS básico por puerto).
- IPs origen/destino más activas.
- Dominios vistos en DNS.
- Serie de tiempo de paquetes (para ver picos).
- Búsqueda de IOCs:
    * Posible SYN flood.
    * Posibles scans de puertos.
    * Puertos destino inusuales.
    * Consultas DNS sospechosas.
Genera un resumen de hallazgos en consola.
"""

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR
from collections import Counter, defaultdict
from datetime import datetime
import math

class PcapAnalyzer:
    def __init__(self, filepath, bucket_seconds=5, syn_threshold=100, scan_port_threshold=20):
        """
        :param filepath: ruta al archivo pcap/pcapng
        :param bucket_seconds: tamaño del intervalo de tiempo para series (segundos)
        :param syn_threshold: mínimo de SYNs para marcar un posible SYN flood
        :param scan_port_threshold: mínimo de puertos diferentes para marcar posible scan
        """
        self.filepath = filepath
        self.bucket_seconds = bucket_seconds
        self.syn_threshold = syn_threshold
        self.scan_port_threshold = scan_port_threshold

        # contadores y estructuras
        self.protocol_counts = Counter()
        self.app_proto_counts = Counter()
        self.src_ip_counts = Counter()
        self.dst_ip_counts = Counter()
        self.time_buckets = Counter()
        self.dns_queries = Counter()
        self.syn_flows = Counter()          # (src, dst, dport) -> #SYN
        self.syn_ack_flows = Counter()      # (src, dst, sport) -> #SYN-ACK
        self.src_dst_ports = defaultdict(set)   # (src, dst) -> set(dst_ports)
        self.dst_port_counts = Counter()
        self.rst_counts = Counter()         # (src, dst) -> #RST
        self.icmp_unreach = Counter()       # (src, dst) -> #icmp unreachable

        self.start_time = None
        self.end_time = None
        self.total_packets = 0

    def load_and_analyze(self, limit=None):
        """
        Carga el pcap y recorre todos los paquetes aplicando análisis.
        :param limit: si quieres analizar solo los primeros N paquetes (para pruebas)
        """
        print(f"[+] Cargando archivo: {self.filepath}")
        packets = rdpcap(self.filepath)
        if limit:
            packets = packets[:limit]

        print(f"[+] Paquetes cargados: {len(packets)}")

        for pkt in packets:
            self.total_packets += 1
            self._update_time(pkt)
            self._analyze_packet(pkt)

        print("[+] Análisis básico completado.\n")

    # ------------- FUNCIONES INTERNAS DE ANÁLISIS -------------

    def _update_time(self, pkt):
        if not hasattr(pkt, "time"):
            return
        t = float(pkt.time)
        if self.start_time is None or t < self.start_time:
            self.start_time = t
        if self.end_time is None or t > self.end_time:
            self.end_time = t

        # series de tiempo
        if self.bucket_seconds > 0:
            bucket = math.floor(t / self.bucket_seconds) * self.bucket_seconds
            self.time_buckets[bucket] += 1

    def _analyze_packet(self, pkt):
        # Identificación de IP
        ip_layer = None
        if IP in pkt:
            ip_layer = pkt[IP]
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]

        if not ip_layer:
            # sin IP, solo cuenta protocolo genérico
            self.protocol_counts["non-ip"] += 1
            return

        src = ip_layer.src
        dst = ip_layer.dst
        self.src_ip_counts[src] += 1
        self.dst_ip_counts[dst] += 1

        # Protocolo de transporte / red
        if TCP in pkt:
            self.protocol_counts["TCP"] += 1
            tcp = pkt[TCP]
            dport = tcp.dport
            sport = tcp.sport
            self.dst_port_counts[dport] += 1
            self.src_dst_ports[(src, dst)].add(dport)

            # Identificación simple de "aplicación" por puerto
            if dport in (80, 8080):
                self.app_proto_counts["HTTP"] += 1
            elif dport == 443:
                self.app_proto_counts["HTTPS"] += 1
            elif dport == 22:
                self.app_proto_counts["SSH"] += 1
            else:
                self.app_proto_counts["TCP_other"] += 1

            # SYN / SYN-ACK para flood o conexión normal
            flags = tcp.flags
            # SYN sin ACK
            if flags & 0x02 and not (flags & 0x10):
                self.syn_flows[(src, dst, dport)] += 1
            # SYN-ACK (respuesta del servidor)
            if flags & 0x12 == 0x12:  # SYN(0x02) + ACK(0x10)
                self.syn_ack_flows[(src, dst, sport)] += 1

            # RST para conexiones fallidas
            if flags & 0x04:
                self.rst_counts[(src, dst)] += 1

        elif UDP in pkt:
            self.protocol_counts["UDP"] += 1
            udp = pkt[UDP]
            dport = udp.dport
            self.dst_port_counts[dport] += 1
            self.src_dst_ports[(src, dst)].add(dport)

            if dport == 53 or (DNS in pkt):
                self.app_proto_counts["DNS"] += 1
            else:
                self.app_proto_counts["UDP_other"] += 1

        elif ICMP in pkt:
            self.protocol_counts["ICMP"] += 1
            icmp = pkt[ICMP]
            # ICMP unreachable: tipo 3
            if hasattr(icmp, "type") and icmp.type == 3:
                self.icmp_unreach[(src, dst)] += 1

        else:
            self.protocol_counts["other-ip-proto"] += 1

        # DNS
        if DNS in pkt and pkt[DNS].qd is not None:
            dns = pkt[DNS]
            if isinstance(dns.qd, DNSQR):
                qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
                self.dns_queries[qname] += 1

    # ------------- REPORTES Y HALLAZGOS -------------

    def print_basic_stats(self, top_n=10):
        print("=== RESUMEN BÁSICO ===")
        print(f"Archivo: {self.filepath}")
        print(f"Total de paquetes: {self.total_packets}")
        if self.start_time and self.end_time:
            start_str = datetime.fromtimestamp(self.start_time)
            end_str = datetime.fromtimestamp(self.end_time)
            dur = self.end_time - self.start_time
            print(f"Ventana temporal: {start_str}  ->  {end_str}  (duración ~{dur:.1f} s)")
        print()

        print(">>> Volumen por protocolo de transporte:")
        for proto, count in self.protocol_counts.most_common():
            pct = (count / self.total_packets) * 100 if self.total_packets else 0
            print(f"  - {proto}: {count} paquetes ({pct:.1f}%)")
        print()

        print(">>> Volumen por tipo de aplicación (aprox. por puerto):")
        for proto, count in self.app_proto_counts.most_common():
            pct = (count / self.total_packets) * 100 if self.total_packets else 0
            print(f"  - {proto}: {count} paquetes ({pct:.1f}%)")
        print()

        print(f">>> Top {top_n} IP origen:")
        for ip, count in self.src_ip_counts.most_common(top_n):
            print(f"  - {ip}: {count} paquetes enviados")
        print()

        print(f">>> Top {top_n} IP destino:")
        for ip, count in self.dst_ip_counts.most_common(top_n):
            print(f"  - {ip}: {count} paquetes recibidos")
        print()

        print(f">>> Top {top_n} puertos destino:")
        for port, count in self.dst_port_counts.most_common(top_n):
            print(f"  - {port}: {count} paquetes")
        print()

        print(f">>> Top {top_n} dominios DNS consultados:")
        for dom, count in self.dns_queries.most_common(top_n):
            print(f"  - {dom}: {count} consultas")
        print()

        print(">>> Serie de tiempo (paquetes por intervalo):")
        if not self.time_buckets:
            print("  (no se pudo calcular)")
        else:
            # mostrar algunos intervalos
            for bucket, count in sorted(self.time_buckets.items())[:top_n]:
                ts = datetime.fromtimestamp(bucket)
                print(f"  - {ts} : {count} paquetes")
        print()

    def detect_iocs(self):
        """
        Analiza las estructuras y devuelve un dict con hallazgos anómalos.
        """
        findings = {
            "syn_flood_candidates": [],
            "port_scan_candidates": [],
            "unusual_ports": [],
            "suspicious_dns": [],
            "high_rst_pairs": [],
            "icmp_unreachable_pairs": []
        }

        # 1) Posibles SYN flood
        for (src, dst, dport), syn_count in self.syn_flows.items():
            if syn_count >= self.syn_threshold:
                # Revisar si hay pocas respuestas SYN-ACK
                synack_count = self.syn_ack_flows.get((dst, src, dport), 0)
                ratio = synack_count / syn_count if syn_count > 0 else 0
                findings["syn_flood_candidates"].append({
                    "src": src,
                    "dst": dst,
                    "dport": dport,
                    "syn_count": syn_count,
                    "synack_count": synack_count,
                    "synack_ratio": ratio
                })

        # 2) Port scan: muchos puertos distintos desde un mismo origen hacia un mismo destino
        for (src, dst), ports in self.src_dst_ports.items():
            if len(ports) >= self.scan_port_threshold:
                findings["port_scan_candidates"].append({
                    "src": src,
                    "dst": dst,
                    "unique_dst_ports": len(ports),
                    "ports": sorted(list(ports))
                })

        # 3) Puertos inusuales: puertos relativamente altos y poco comunes
        common_ports = {80, 443, 22, 53, 25, 110, 143}
        for port, count in self.dst_port_counts.most_common():
            if port not in common_ports and port > 1024 and count > 10:
                findings["unusual_ports"].append({
                    "port": port,
                    "count": count
                })

        # 4) DNS sospechoso: dominios muy largos o con aspecto aleatorio
        for dom, count in self.dns_queries.items():
            if len(dom) > 50 or dom.count(".") > 4:
                findings["suspicious_dns"].append({
                    "domain": dom,
                    "count": count,
                    "reason": "nombre muy largo o muchos subdominios"
                })

        # 5) Pares con muchos RST
        for (src, dst), count in self.rst_counts.items():
            if count > 20:  # umbral ajustable
                findings["high_rst_pairs"].append({
                    "src": src,
                    "dst": dst,
                    "rst_count": count
                })

        # 6) Pares con muchos ICMP unreachable
        for (src, dst), count in self.icmp_unreach.items():
            if count > 10:
                findings["icmp_unreachable_pairs"].append({
                    "src": src,
                    "dst": dst,
                    "unreach_count": count
                })

        return findings

    def print_iocs(self, findings):
        print("=== POSIBLES IOCs / HALLAZGOS ANÓMALOS ===")

        syn = findings["syn_flood_candidates"]
        if syn:
            print("\n>>> Posibles SYN flood:")
            for f in syn:
                print(f"  - {f['src']} -> {f['dst']}:{f['dport']} | SYN={f['syn_count']} SYN-ACK={f['synack_count']} ratio={f['synack_ratio']:.2f}")
        else:
            print("\n>>> No se detectaron patrones claros de SYN flood con el umbral configurado.")

        scans = findings["port_scan_candidates"]
        if scans:
            print("\n>>> Posibles scans de puertos:")
            for f in scans:
                print(f"  - {f['src']} -> {f['dst']} | puertos únicos={f['unique_dst_ports']}")
        else:
            print("\n>>> No se detectaron scans claros de puertos con el umbral configurado.")

        up = findings["unusual_ports"]
        if up:
            print("\n>>> Puertos destino inusuales con alto volumen:")
            for f in up:
                print(f"  - Puerto {f['port']} : {f['count']} paquetes")
        else:
            print("\n>>> No se detectaron puertos inusuales con mucho tráfico.")

        sus_dns = findings["suspicious_dns"]
        if sus_dns:
            print("\n>>> Consultas DNS potencialmente sospechosas:")
            for f in sus_dns[:20]:
                print(f"  - {f['domain']} ({f['count']} consultas) - {f['reason']}")
        else:
            print("\n>>> No se detectaron dominios DNS obviamente sospechosos según la heurística simple.")

        rst_pairs = findings["high_rst_pairs"]
        if rst_pairs:
            print("\n>>> Pares con muchos paquetes TCP RST (conexiones fallidas):")
            for f in rst_pairs:
                print(f"  - {f['src']} -> {f['dst']} | RST={f['rst_count']}")
        else:
            print("\n>>> No se observaron pares con RST anormalmente altos (según el umbral).")

        icmp_pairs = findings["icmp_unreachable_pairs"]
        if icmp_pairs:
            print("\n>>> Pares con muchos ICMP unreachable (hosts/puertos no alcanzables):")
            for f in icmp_pairs:
                print(f"  - {f['src']} -> {f['dst']} | unreachable={f['unreach_count']}")
        else:
            print("\n>>> No se observaron muchos ICMP unreachable (según el umbral).")

        print()

# ------------- EJEMPLO DE USO -------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analizador forense básico de PCAP/PCAPNG.")
    parser.add_argument("pcap", help="Ruta al archivo .pcap o .pcapng")
    parser.add_argument("--bucket", type=int, default=5, help="Tamaño de intervalo de tiempo en segundos (default: 5)")
    parser.add_argument("--syn-threshold", type=int, default=100, help="Umbral de SYNs para marcar posible SYN flood")
    parser.add_argument("--scan-threshold", type=int, default=20, help="Umbral de puertos únicos para marcar scan")
    parser.add_argument("--limit", type=int, default=None, help="Número máximo de paquetes a analizar (debug)")

    args = parser.parse_args()

    analyzer = PcapAnalyzer(
        filepath=args.pcap,
        bucket_seconds=args.bucket,
        syn_threshold=args.syn_threshold,
        scan_port_threshold=args.scan_threshold
    )
    analyzer.load_and_analyze(limit=args.limit)
    analyzer.print_basic_stats()

    findings = analyzer.detect_iocs()
    analyzer.print_iocs(findings)

    print("[+] Análisis finalizado.")
