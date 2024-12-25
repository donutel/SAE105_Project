import re

def parse_and_save_tcpdump(file_path, output_path):
    packets = []

    # Open the tcpdump file
    with open(file_path, 'r') as f:
        lines = f.readlines()

    # Updated Regex pattern to capture the required data
    pattern = re.compile(r'(?P<timestamp>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(?P<source>[\d\-\.a-zA-Z]+(?:\.[^:]+)?)\.(?P<source_port>\d+)\s+>\s+(?P<destination>[\d\-\.a-zA-Z]+(?:\.[^:]+)?)\.(?P<destination_port>\d+):\s*'
                         r'Flags\s*\[(?P<flags>[^\]]+)\],\s*'
                         r'seq\s*(?P<seq_start>\d+):(?P<seq_end>\d+),\s*ack\s*(?P<ack>\d+),\s*'
                         r'win\s*(?P<win>\d+),\s*length\s*(?P<length>\d+)(?::\s*(?P<protocol>\w+))?')

    # Open the output file to save the cleaned packets
    with open(output_path, 'w') as out_file:
        # Loop through the lines and apply the regex
        for line in lines:
            line = line.strip()  # Clean up the line by removing extra spaces

            # Skip hex dump lines (starting with '0x')
            if line.startswith('0x'):
                continue  # Skip hex dump lines
            
            print(f"Debugging line: {line}")  # Print the raw line for debugging
            
            # Check for TCP/IP packet match
            match = pattern.match(line)

            if match:
                packet = match.groupdict()  # Get matched data as a dictionary
                # Save packet information to the new file
                out_file.write(f"{packet}\n")
                print(f"Matched packet: {packet}")  # Print the matched data for debugging
                packets.append(packet)

    return packets

# Testing the parser and saving cleaned data to a new file
if __name__ == '__main__':
    # Path to your tcpdump file and output path for the cleaned packets
    file_path = r'C:\Users\HP\OneDrive\Desktop\tcpdump_analyzer\fichier1000.txt'
    output_path = r'C:\Users\HP\OneDrive\Desktop\tcpdump_analyzer\cleaned_packets.txt'

    # Parse the file and extract important packet data, saving them to a new file
    packets = parse_and_save_tcpdump(file_path, output_path)

    # Print the results
    if packets:
        print(f"Extracted {len(packets)} packets.")
    else:
        print("No packets were found.")
    