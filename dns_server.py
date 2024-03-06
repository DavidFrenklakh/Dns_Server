from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, send, sniff, sr1
import sqlite3
import time

DNS_SERVER = "127.0.0.1"
GOOGLE_DNS_SERVER = "8.8.8.8"
DNS_DST_PORT = 53

DNS_A_TYPE = 1
DNS_AAAA_TYPE = 28
DNS_CNAME_TYPE = 5

con = sqlite3.connect("dns_server.db")
cur = con.cursor()


def create_table(cur):
    """
    Function to create the 'names' table if it doesn't already exist.
    The table should have columns: id (text), ttl (int), record type (text), result (text).
    """
    try:
        cur.execute("CREATE TABLE IF NOT EXISTS names (id TEXT PRIMARY KEY, ttl INTEGER, record_type TEXT, result TEXT)")
        con.commit()
        print("Created table 'names' successfully.")
    except Exception as e:
        print(f"Error creating database table: {e}")


def purge_old_entries(cur, con):
    """
    Function to purge (delete) all entries from the 'names' table that have a TTL lower than the current time.
    """
    try:
        current_time = int(time.time())  # Get current time in seconds
        cur.execute("DELETE FROM names WHERE ttl < ?", (current_time,))
        con.commit()
        print("Old entries purged successfully.")
    except sqlite3.Error as e:
        print(f"Error purging old entries: {e}")


def insert_new_entry(cur, id, ttl, record_type, result):
    """
    Function to insert a new DNS entry into the database.
    This function inserts a new entry into the 'names' table with the provided details.
    """
    try:
        cur.execute("INSERT INTO names (id, ttl, record_type, result) VALUES (?, ?, ?, ?)", (id, ttl, record_type, result))
        con.commit()
        print("New entry inserted successfully.")
    except sqlite3.Error as e:
        print(f"Error inserting new entry: {e}")


def dns_server():
    """
    Function to run the DNS server.
    This function listens for DNS queries, resolves them, and sends back responses.
    """

    def dns_response(pkt):
        """
        Function to handle DNS responses.
        Checks if a DNS query is received and sends a DNS response.
        """
        if DNSQR in pkt and pkt.dport == DNS_DST_PORT:
            query_domain = pkt[DNSQR].qname.decode()

            # Check if the query domain is already in the database
            cur.execute("SELECT * FROM names WHERE id = ?", (query_domain,))
            existing_entry = cur.fetchone()
            if existing_entry:
                ttl = existing_entry[1]
                ip = existing_entry[3]
                if ttl >= int(time.time()):  # Check if TTL is still valid
                    dns_reply = IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=DNS_DST_PORT) / DNS(
                        id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=query_domain, ttl=ttl, rdata=ip))
                    send(dns_reply, verbose=0)
                    print(f"Responded to {query_domain} with cached result {ip} for client {pkt[IP].src}")
                    return
                else:
                    purge_old_entries(cur, con)

            # If not in the database or TTL expired, perform DNS resolution
            dns_request = IP(dst=GOOGLE_DNS_SERVER) / UDP(dport=DNS_DST_PORT) / DNS(rd=1, qd=DNSQR(qname=query_domain))
            dns_response = sr1(dns_request, verbose=0)
            if dns_response and DNSRR in dns_response:
                response = dns_response[DNS]
                ip = extract_ip_from_response(response)
                if ip:
                    ttl = int(time.time()) + getattr(response, 'ttl', 0)
                    insert_new_entry(cur, query_domain, ttl, response.an.type, ip)
                    dns_reply = IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=DNS_DST_PORT) / DNS(
                        id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, an=DNSRR(rrname=query_domain, ttl=10, rdata=ip))
                    send(dns_reply, verbose=0)
                    print(f"Resolved {query_domain} to {ip} for client {pkt[IP].src}")
                    return

    print("DNS server is running...")
    sniff(filter="udp and port 53", prn=dns_response, store=0)


def extract_ip_from_response(response):
    """
    Function to extract IP address from a DNS response.
    This function recursively extracts the IP address from DNS response packets.
    """
    if DNSRR in response:
        for rr in response[DNSRR]:
            if rr.type == DNS_A_TYPE or rr.type == DNS_AAAA_TYPE:
                response = rr.rdata
            elif rr.type == DNS_CNAME_TYPE:
                return extract_ip_from_response(sr1(IP(dst=GOOGLE_DNS_SERVER) / UDP(dport=DNS_DST_PORT) / DNS(rd=1, qd=DNSQR(qname=rr.rdata.decode()))))

    return response


def main():
    """
    Main function to start the DNS server and handle DNS queries.
    """
    try:
        dns_server()
    except KeyboardInterrupt:
        print("\n\n\nExiting...")


if __name__ == "__main__":
    main()
