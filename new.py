from scapy.all import DNS, DNSQR, IP, UDP
from scapy.arch import get_if_addr
from scapy.layers.dns import DNSRR  # Import DNSRR separately

from scapy.sendrecv import sniff, send  # Import sniff from scapy.sendrecv


def dns_server(pkt):
    if DNS in pkt and pkt[DNS].opcode == 0:
        qname = pkt[DNSQR].qname
        print(f"DNS Query for {qname}")

        # Craft DNS response
        dns_response = (
            IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport) /
            DNS(
                id=pkt[DNS].id,
                qr=1,
                aa=1,
                qdcount=1,
                ancount=1,
                qd=pkt[DNSQR],
                an=DNSRR(rrname=pkt[DNSQR].qname, rdata=get_if_addr(pkt[IP].dst))
            )
        )

        # Send the response
        send(dns_response, verbose=False)


def main():
    # Start sniffing DNS traffic
    sniff(filter="udp and port 53", prn=dns_server)


if __name__ == "__main__":
    main()
