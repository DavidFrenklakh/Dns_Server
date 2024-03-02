from scapy.all import *
import socket

def dns_server(pkt):
    if DNS in pkt and pkt[DNS].opcode == 0:  # Check if DNS query
        qname = pkt[DNSQR].qname.decode()[:-1]  # Extract the domain name from the query
        print(f"DNS Query for {qname}")

        # Resolve domain name to IPv4 address
        try:
            ip_address = socket.gethostbyname(qname)
            print(f"Resolved {qname} to {ip_address}")

            # Craft DNS response
            dns_response = IP(dst=pkt[IP].src)/UDP(dport=pkt[UDP].sport, sport=53)/\
                           DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                               an=DNSRR(rrname=qname, type='A', rdata=ip_address))

            # Send the response
            send(dns_response, verbose=False)
            print(f"Sent DNS response for {qname} to {pkt[IP].src}")
        except (socket.gaierror, IndexError) as e:
            print(f"Unable to resolve {qname}: {e}")

def main():
    print("Starting DNS server on 127.0.0.1:53...")
    try:
        # Sniff DNS traffic on port 53
        sniff(filter="udp and port 53 and host 127.0.0.1", prn=dns_server, store=0)
    except KeyboardInterrupt:
        print("\nDNS server stopped.")

if __name__ == "__main__":
    main()
