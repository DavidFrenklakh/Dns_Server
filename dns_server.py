from scapy.all import *


# def server(ip, port):
#     print(f"Starting server on {ip} port {port}...")
#     while True:
#         pass


def get_domain_from_ip(ip):
    try:
        domain = socket.gethostbyaddr(ip)[0]
        return domain
    except socket.herror:
        return "Unknown"


def main():
    while True:
        ip = input("Enter the IP address: ")
        domain = get_domain_from_ip(ip)
        print(f"The domain associated with {ip} is: {domain}")


# def main():
#     ip = '127.0.0.1'
#     port = 53
#     server(ip, port)


if __name__ == "__main__":
    main()
