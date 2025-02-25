import sys
import os
from scapy.all import sniff, Ether, IP, TCP, UDP, ARP

def display_packet(packet):
    """
    Display packet details in a clean, human-readable format.
    """
    print("\n" + "=" * 50)
    if Ether in packet:
        print("[Ethernet Frame]")
        print(f"  Source MAC: {packet[Ether].src}")
        print(f"  Destination MAC: {packet[Ether].dst}")
        print(f"  Ethernet Type: {packet[Ether].type}")

    if IP in packet:
        print("[IP Packet]")
        print(f"  Source IP: {packet[IP].src}")
        print(f"  Destination IP: {packet[IP].dst}")
        print(f"  Protocol: {packet[IP].proto}")

    if TCP in packet:
        print("[TCP Segment]")
        print(f"  Source Port: {packet[TCP].sport}")
        print(f"  Destination Port: {packet[TCP].dport}")
        print(f"  Sequence Number: {packet[TCP].seq}")
        print(f"  Acknowledgment Number: {packet[TCP].ack}")
        print(f"  Flags: {packet[TCP].flags}")

    if UDP in packet:
        print("[UDP Datagram]")
        print(f"  Source Port: {packet[UDP].sport}")
        print(f"  Destination Port: {packet[UDP].dport}")

    if ARP in packet:
        print("[ARP Packet]")
        print(f"  Sender MAC: {packet[ARP].hwsrc}")
        print(f"  Sender IP: {packet[ARP].psrc}")
        print(f"  Target MAC: {packet[ARP].hwdst}")
        print(f"  Target IP: {packet[ARP].pdst}")

    print("=" * 50)

def packet_filter(packet, filter_protocol=None, filter_ip=None, filter_port=None):
    """
    Filter packets based on protocol, IP, or port.
    """
    if filter_protocol and not packet.haslayer(filter_protocol):
        return False
    if filter_ip and (IP in packet and packet[IP].src != filter_ip and packet[IP].dst != filter_ip):
        return False
    if filter_port and ((TCP in packet and packet[TCP].dport != filter_port and packet[TCP].sport != filter_port) or
                        (UDP in packet and packet[UDP].dport != filter_port and packet[UDP].sport != filter_port)):
        return False
    return True

def start_sniffing(interface=None, filter_protocol=None, filter_ip=None, filter_port=None, save_to_file=False):
    """
    Start sniffing network traffic with optional filters and saving to file.
    """
    print("\n[+] Starting network sniffer...")
    print(f"  Interface: {interface if interface else 'All interfaces'}")
    print(f"  Filters: Protocol={filter_protocol}, IP={filter_ip}, Port={filter_port}")
    print("  Press Ctrl+C to stop sniffing.\n")

    def packet_handler(packet):
        if packet_filter(packet, filter_protocol, filter_ip, filter_port):
            display_packet(packet)
            if save_to_file:
                with open("captured_packets.txt", "a") as f:
                    f.write(str(packet) + "\n")

    try:
        sniff(iface=interface, prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n[!] Sniffing stopped by user.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

def main_menu():
    """
    Display a menu for the user to configure the sniffer.
    """
    print("\n=== Network Sniffer ===")
    print("1. Start sniffing")
    print("2. Set filters")
    print("3. Save packets to file")
    print("4. Exit")
    choice = input("Enter your choice: ")
    return choice

def main():
    interface = None
    filter_protocol = None
    filter_ip = None
    filter_port = None
    save_to_file = False

    while True:
        choice = main_menu()

        if choice == "1":
            start_sniffing(interface, filter_protocol, filter_ip, filter_port, save_to_file)
        elif choice == "2":
            print("\n=== Set Filters ===")
            filter_protocol = input("Enter protocol to filter (e.g., TCP, UDP, ARP, IP): ").upper()
            filter_ip = input("Enter IP address to filter (e.g., 192.168.1.100): ")
            filter_port = input("Enter port to filter (e.g., 80): ")
            if filter_port:
                filter_port = int(filter_port)
        elif choice == "3":
            save_to_file = True
            print("\n[+] Packets will be saved to 'captured_packets.txt'.")
        elif choice == "4":
            print("\n[+] Exiting...")
            sys.exit(0)
        else:
            print("\n[!] Invalid choice. Please try again.")

if __name__ == "__main__":
    # Check if the script is running on Windows
    if os.name == "nt":
        print("[!] Please run this script as an administrator on Windows.")
    try:
        main()
    except PermissionError:
        print("[!] Permission denied. Please run the script with administrative privileges.")