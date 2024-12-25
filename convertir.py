import re
import csv

def analyze_failed_connection(line):
    """
    Analyze a failed connection line and identify potential issues.
    
    :param line: Raw text of the failed connection line
    :return: Description of the problem
    """
    problems = []

    # Check if the line contains critical fields (basic validation)
    if not re.search(r"IP", line):
        problems.append("Missing 'IP' field (not a valid IP connection).")
    
    # Check for valid flags
    if not re.search(r"Flags\s+\[\w+\]", line):
        problems.append("Missing or invalid flags.")
    
    # Check if the sequence numbers or window size is malformed
    if not re.search(r"seq\s+\d+:\d+,", line):
        problems.append("Malformed sequence numbers.")
    if not re.search(r"win\s+\d+,", line):
        problems.append("Malformed or missing window size.")
    
    # Check if the length field is present
    if not re.search(r"length\s+\d+", line):
        problems.append("Missing or invalid length field.")
    
    # Check for DNS or IP issues
    if re.search(r"([a-zA-Z\-]+\.com|[a-zA-Z\-]+\.net)", line):
        if not re.search(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", line):
            problems.append("DNS name found but no corresponding IP address.")
    else:
        if not re.search(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", line):
            problems.append("No valid IP address found.")
    
    # If no problems detected, mark as "Uncategorized error"
    if not problems:
        problems.append("Uncategorized error (could not determine exact issue).")

    return "; ".join(problems)

def process_file_with_failures(file_path):
    """
    Process the file to extract both successful and failed connections.
    
    :param file_path: Path to the .txt file to process
    :return: Two lists - one for successful connections and one for failed connections with analysis
    """
    successful_connections = []  # For storing successful connections
    failed_connections = []      # For storing failed connections with analysis

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                # Ignore hex dump lines
                if re.match(r"^\s*[0-9a-fA-F]{4}.*", line):
                    continue  # Skip hex dump lines
                
                # Pattern for successful connections
                success_pattern = re.compile(
                    r"(\d{2}:\d{2}:\d{2})\.(\d+)\s+IP\s+([a-zA-Z0-9\.\-]+)\.(\d+)\s+>\s+([0-9\.]+)\.(\S+):\s+Flags\s+\[([A-Za-z]+)\],\s+seq\s+(\d+):(\d+),\s+win\s+(\d+),\s+length\s+(\d+):\s+(\S+)"
                )
                success_match = success_pattern.match(line)

                if success_match:
                    # Extract fields for successful connections
                    time = success_match.group(1)  # Time
                    microseconds = success_match.group(2)
                    src_ip = success_match.group(3)
                    src_port = success_match.group(4)
                    dst_ip = success_match.group(5)
                    dst_port = success_match.group(6)
                    flags = success_match.group(7)
                    seq_start = success_match.group(8)
                    seq_end = success_match.group(9)
                    window_size = success_match.group(10)
                    length = success_match.group(11)
                    protocol = success_match.group(12)
                    
                    successful_connections.append([
                        time, microseconds, src_ip, src_port, dst_ip, dst_port, 
                        flags, seq_start, seq_end, window_size, length, protocol
                    ])
                else:
                    # Analyze failed connection
                    problem_description = analyze_failed_connection(line)
                    failed_connections.append([line.strip(), problem_description])

    except FileNotFoundError:
        print(f"Erreur: Le fichier '{file_path}' n'a pas été trouvé.")
    except IOError:
        print(f"Erreur: Impossible d'ouvrir le fichier '{file_path}'.")

    return successful_connections, failed_connections

def save_connections_to_csv(successful, failed, output_file):
    """
    Save successful and failed connections into the same CSV file.
    
    :param successful: List of successful connections
    :param failed: List of failed connections
    :param output_file: Path to the output CSV file
    """
    headers = [
        'Time', 'Microseconds', 'Source IP', 'Source Port', 'Destination IP', 
        'Destination Port', 'Flags', 'Sequence Start', 'Sequence End', 
        'Window Size', 'Length', 'Protocol'
    ]

    try:
        with open(output_file, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            
            # Write successful connections
            writer.writerow(['Successful Connections'])
            writer.writerow(headers)
            writer.writerows(successful)
            
            # Separate section for failed connections
            writer.writerow([])  # Empty row
            writer.writerow(['Failed Connections'])
            writer.writerow(['Raw Data', 'Problem Description'])
            writer.writerows(failed)
        
        print(f"Les données ont été sauvegardées dans {output_file}")
    except IOError:
        print("Erreur lors de l'enregistrement du fichier CSV.")

def main():
    # Define paths
    file_path = r'C:\Users\HP\OneDrive\Desktop\tcpdump_analyzer\fichier1000.txt'
    output_file = r'C:\Users\HP\OneDrive\Desktop\tcpdump_analyzer\connections_output.csv'

    # Process the file
    successful, failed = process_file_with_failures(file_path)

    # Save results to CSV
    save_connections_to_csv(successful, failed, output_file)

if __name__ == "__main__":
    main()
