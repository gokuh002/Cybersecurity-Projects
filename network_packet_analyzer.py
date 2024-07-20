from scapy.all import sniff

def packet_callback(packet):
    # Print a summary of each packet
    print(packet.summary())

# Define the number of packets to capture
packet_count = int(input('Enter the number of packets you want to sniff : '))

print(f"Starting to capture {packet_count} packets...")

# Start sniffing packets
sniff(prn=packet_callback, count=packet_count)
