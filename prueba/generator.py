
from pathlib import Path
from scapy.all import (
    Ether, ARP, IP, UDP, DNS, DNSQR, DNSRR,
    BOOTP, DHCP, wrpcap
)

OUTPUT = Path("captures")
OUTPUT.mkdir(exist_ok=True)

# Direcciones reservadas para documentación y pruebas.
VICTIM_IP = "192.0.2.10"
ROUTER_IP = "192.0.2.1"
DNS_IP = "192.0.2.53"

VICTIM_MAC = "02:00:00:00:00:10"
ROUTER_MAC = "02:00:00:00:00:01"
ATTACKER_MAC = "02:00:00:00:00:99"

AUTHORIZED_DHCP = "192.0.2.2"
ROGUE_DHCP = "192.0.2.99"

def save(name, packets):
    path = OUTPUT / name
    wrpcap(str(path), packets)
    print(f"[OK] {path} - {len(packets)} paquetes")


# --------------------------------------------------
# 1. ARP SPOOFING
# --------------------------------------------------

def arp_test():
    packets = [
        # ARP legítimo: el router anuncia su MAC.
        Ether(src=ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff") /
        ARP(
            op=2,
            psrc=ROUTER_IP,
            hwsrc=ROUTER_MAC,
            pdst=VICTIM_IP,
            hwdst=VICTIM_MAC
        ),

        # Simulación de suplantación:
        # otra MAC anuncia la IP del router.
        Ether(src=ATTACKER_MAC, dst="ff:ff:ff:ff:ff:ff") /
        ARP(
            op=2,
            psrc=ROUTER_IP,
            hwsrc=ATTACKER_MAC,
            pdst=VICTIM_IP,
            hwdst=VICTIM_MAC
        )
    ]

    save("arp_spoof.pcap", packets)


# --------------------------------------------------
# 2. DNS SPOOFING
# --------------------------------------------------

def dns_test():
    transaction_id = 0x1234

    query = (
        Ether(src=VICTIM_MAC, dst=ROUTER_MAC) /
        IP(src=VICTIM_IP, dst=DNS_IP) /
        UDP(sport=53000, dport=53) /
        DNS(
            id=transaction_id,
            rd=1,
            qd=DNSQR(qname="example.test", qtype="A")
        )
    )

    legitimate_response = (
        Ether(src=ROUTER_MAC, dst=VICTIM_MAC) /
        IP(src=DNS_IP, dst=VICTIM_IP) /
        UDP(sport=53, dport=53000) /
        DNS(
            id=transaction_id,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.test", qtype="A"),
            an=DNSRR(
                rrname="example.test",
                type="A",
                ttl=60,
                rdata="192.0.2.80"
            )
        )
    )

    # Respuesta simulada con un destino diferente.
    forged_response = (
        Ether(src=ATTACKER_MAC, dst=VICTIM_MAC) /
        IP(src=DNS_IP, dst=VICTIM_IP) /
        UDP(sport=53, dport=53000) /
        DNS(
            id=transaction_id,
            qr=1,
            aa=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.test", qtype="A"),
            an=DNSRR(
                rrname="example.test",
                type="A",
                ttl=60,
                rdata="203.0.113.66"
            )
        )
    )

    save(
        "dns_spoof.pcap",
        [query, legitimate_response, forged_response]
    )


# --------------------------------------------------
# 3. IP SPOOFING
# --------------------------------------------------

def ip_test():
    legitimate = (
        Ether(src=VICTIM_MAC, dst=ROUTER_MAC) /
        IP(src=VICTIM_IP, dst="198.51.100.20") /
        UDP(sport=40000, dport=5000) /
        b"LAB_NORMAL_TRAFFIC"
    )

    simulated_spoof = (
        Ether(src=ATTACKER_MAC, dst=ROUTER_MAC) /
        IP(src="203.0.113.77", dst="198.51.100.20") /
        UDP(sport=40001, dport=5000) /
        b"LAB_SPOOFED_SOURCE"
    )

    save("ip_spoof.pcap", [legitimate, simulated_spoof])


# --------------------------------------------------
# 4. DHCP SPOOFING
# --------------------------------------------------


def dhcp_packet(server_ip, server_mac, offered_ip, xid):
    return (
        Ether(
            src=server_mac,
            dst="ff:ff:ff:ff:ff:ff"
        ) /
        IP(
            src=server_ip,
            dst="255.255.255.255"
        ) /
        UDP(
            sport=67,
            dport=68
        ) /
        BOOTP(
            op=2,
            xid=xid,
            yiaddr=offered_ip,
            siaddr=server_ip,
            chaddr=bytes.fromhex("020000000010")
        ) /
        DHCP(options=[
            ("message-type", 2),
            ("server_id", server_ip),
            ("lease_time", 3600),
            ("subnet_mask", "255.255.255.0"),
            ("router", ROUTER_IP),
            ("name_server", DNS_IP),
            "end"
        ])
    )

def dhcp_test():
    legitimate = dhcp_packet(
        AUTHORIZED_DHCP,
        ROUTER_MAC,
        "192.0.2.100",
        1001
    )

    simulated_rogue = dhcp_packet(
        ROGUE_DHCP,
        ATTACKER_MAC,
        "192.0.2.150",
        1002
    )

    save("dhcp_spoof.pcap", [legitimate, simulated_rogue])


# --------------------------------------------------
# 5. BASELINE: TRÁFICO LEGÍTIMO
# --------------------------------------------------

def baseline_test():
    arp = (
        Ether(src=ROUTER_MAC, dst="ff:ff:ff:ff:ff:ff") /
        ARP(
            op=2,
            psrc=ROUTER_IP,
            hwsrc=ROUTER_MAC,
            pdst=VICTIM_IP,
            hwdst=VICTIM_MAC
        )
    )

    dns = (
        Ether(src=ROUTER_MAC, dst=VICTIM_MAC) /
        IP(src=DNS_IP, dst=VICTIM_IP) /
        UDP(sport=53, dport=53000) /
        DNS(
            id=0x4321,
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname="example.test"),
            an=DNSRR(
                rrname="example.test",
                type="A",
                ttl=60,
                rdata="192.0.2.80"
            )
        )
    )

    save("baseline.pcap", [arp, dns])


if __name__ == "__main__":
    arp_test()
    dns_test()
    ip_test()
    dhcp_test()
    baseline_test()

    print("\nGeneración de escenarios finalizada.")
