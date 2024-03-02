from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, sr1
import socket


def dns_query(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"Resolved IP address for {domain}: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"Failed to resolve IP address for {domain}")
        return None


def send_dns_request(domain, dns_server="8.8.8.8"):
    dns_request = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    response = sr1(dns_request, verbose=0)

    if response and response.haslayer(DNSRR):
        print("Response received:")
        for answer in response[DNSRR]:
            print(f"{answer.rrname.decode()}: {answer.rdata}")
        return response[DNSRR].rdata.decode()
    else:
        print("No response received from DNS server.")
        return None


if __name__ == "__main__":
    domain = input("Enter the domain you want to query: ")
    local_ip = dns_query(domain)

    if local_ip:
        dns_response = send_dns_request(domain)
        if dns_response:
            print(f"DNS server {dns_response} resolved {domain} to {local_ip}.")
