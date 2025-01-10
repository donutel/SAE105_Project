from scapy.all import wrpcap, Raw

def convert_txt_to_pcap(txt_file_path, pcap_file_path):
    packets = []
    with open(txt_file_path, 'r') as file:
        for line in file:
            packet_data = bytes(line.strip(), 'utf-8')
            packet = Raw(load=packet_data)
            packets.append(packet)
    wrpcap(pcap_file_path, packets)

# Specify your paths
txt_file_path = 'C:\Users\HP\OneDrive\Desktop\SAE105\uploads\fichier1000.txt'
pcap_file_path = 'output_file.pcap'

# Convert the file
convert_txt_to_pcap(txt_file_path, pcap_file_path)
