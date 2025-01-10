from scapy.all import wrpcap, Ether, Raw

# Function to convert txt file to pcap
def convert_txt_to_pcap(txt_file_path, pcap_file_path):
    packets = []

    with open(txt_file_path, 'r') as file:
        for line in file:
            # Create an Ethernet frame with the packet data
            ether_frame = Ether() / Raw(load=line.strip().encode())
            packets.append(ether_frame)

    # Write the packets to a .pcap file
    wrpcap(pcap_file_path, packets)

# Specify your paths
txt_file_path = r'C:\Users\HP\OneDrive\Desktop\SAE105\uploads\fichier1000.txt'
pcap_file_path = r'C:\Users\HP\OneDrive\Desktop\SAE105\uploads\converted_file.pcap'

# Convert the file
convert_txt_to_pcap(txt_file_path, pcap_file_path)
print(f"Converted {txt_file_path} to {pcap_file_path}")
