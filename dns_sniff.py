from scapy.all import *
from scapy.layers.dns import DNSQR, DNSRR, DNS


def filter_dns(pkt):
    return (DNS in pkt
            and pkt[DNS].qdcount != 0
            and pkt[DNS].qd.qname.decode()[:-1] == url
            and pkt[DNS].qd.qtype == dns_type)


def print_query_data(pkt):
    if pkt[DNS].rcode == 0:
        query_type_name = {1: 'A', 5: 'CNAME', 12: 'PTR', 28: 'AAAA'}
        ans = ''

        if pkt[DNS].qr == 0:
            if pkt[DNS].qd.qtype in query_type_name.keys():
                print(f"[QUERY-REQUEST]: url={pkt[DNS].qd.qname.decode()[:-1]} "
                      f"TYPE={query_type_name[pkt[DNS].qd.qtype]}")
        else:
            for i in range(pkt[DNS].ancount):
                if pkt[DNS].an[i].type in query_type_name.keys():
                    if query_type_name[pkt[DNS].an[i].type] == 'CNAME':
                        ans = f"[QUERY-REPLAY]: Ans={pkt[DNS].an[i].rdata.decode()[:-1]}"
                    else:
                        ans = f"[QUERY-REPLAY]: Ans={pkt[DNS].an.rdata}"

                    print(f"{ans}   "
                          f"[QUERY]: {pkt[DNS].an[i].rrname.decode()[:-1]}"
                          f"TYPE={query_type_name[pkt[DNS].an[i].type]}")


if __name__ == '__main__':
    print("Starting DNS sniffing using scapy....")
    # sniff(lfilter=filter_dns, prn=print_query_data)

    while True:
        url = input("enter url/domain: ")
        dns_type = int(input("enter DNS type (1:ipv4    28:ipv6): "))
        sniff(count=2, lfilter=filter_dns, prn=print_query_data)
