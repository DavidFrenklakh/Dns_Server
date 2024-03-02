from scapy.all import *


def client(server_ip, server_port):
    print(f"Connecting to server {server_ip}:{server_port}...")

    # Send TCP SYN packet to initiate connection
    syn_pkt = IP(dst=server_ip) / TCP(dport=server_port, flags="S")
    syn_ack_pkt = sr1(syn_pkt)

    if TCP in syn_ack_pkt and syn_ack_pkt[TCP].flags & 18:  # Check if SYN-ACK flags are set
        print("Received TCP SYN-ACK")

        # Craft TCP ACK packet to complete TCP handshake
        ack_pkt = IP(dst=server_ip) / TCP(dport=server_port, flags="A", seq=syn_ack_pkt[TCP].ack,
                                          ack=syn_ack_pkt[TCP].seq + 1)
        send(ack_pkt)
        print("Sent TCP ACK")

        # Send custom message
        message = "Hello from Scapy Client!"
        data_pkt = IP(dst=server_ip) / TCP(dport=server_port, flags="PA", seq=syn_ack_pkt[TCP].ack,
                                           ack=syn_ack_pkt[TCP].seq + 1) / message
        response = sr1(data_pkt)
        print("Sent message to server:", message)
        print("Response from server:", response.summary())
    else:
        print("Failed to establish TCP connection")


def main():
    server_ip = "127.0.0.1"
    server_port = 53
    client(server_ip, server_port)


if __name__ == "__main__":
    main()
