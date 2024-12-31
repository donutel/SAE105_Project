#this is for handling upload file in flask
from flask import Flask, render_template, request, redirect, url_for
import os
import re


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pcap', 'cap'}

#this is the upload function
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')  # you have to be in the path where uploads exists
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/')
def index():
    return render_template('upload.html')
#this is the parsing extracting to a file fucntion
def parse_tcpdump_line(line):
    # Regular expression to extract timestamp, source IP, destination IP, and connection status
    pattern = r'(\S+)\s+IP\s+([\d\.]+)\.(\d+)\s+>\s+([\d\.]+)\.(\d+):\s+Flags\s+\[(\w+)\]'
    match = re.match(pattern, line)

    if match:
        timestamp = match.group(1)
        source_ip = match.group(2)
        dest_ip = match.group(4)
        status = "success" if match.group(6) == "S" else "failed"
        return {
            'timestamp': timestamp,
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'status': status
        }
    return None

def process_tcpdump_file(file_path):
    successful = []
    failed = []

    with open(file_path, 'r') as f:
        for line in f:
            result = parse_tcpdump_line(line)
            if result:
                if result['status'] == 'success':
                    successful.append(result)
                else:
                    failed.append(result)

    return {'successful': successful, 'failed': failed}

# Example usage
file_path = r'C:\Users\HP\OneDrive\Desktop\SAE105\uploads\fichier1000.txt'
data = process_tcpdump_file(file_path)

# Print results
print('Successful Connections:', data['successful'])
print('Failed Connections:', data['failed'])







import re
from datetime import datetime


def extract_info_from_file(file_path):
    connections = {
        "successful": [],
        "failed": [],
        "errors": [],
        "ips": set()
    }

    with open(file_path, 'r') as file:
        lines = file.readlines()

        # Track the state of each connection attempt
        ongoing_connections = {}

        for line in lines:
            # Match SYN packet (Initiation of connection)
            syn_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([^\s]+)\s+>\s+([^\s]+)\s+Flags\s+\[S\]', line)
            if syn_match:
                timestamp, source_ip, dest_ip = syn_match.groups()
                print(f"Detected SYN packet: {source_ip} -> {dest_ip} at {timestamp}")
                # Track SYN requests
                ongoing_connections[(source_ip, dest_ip)] = {'SYN': timestamp}
                connections["ips"].add(source_ip)
                connections["ips"].add(dest_ip)
                continue

            # Match SYN-ACK packet (Response to the SYN)
            syn_ack_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([^\s]+)\s+>\s+([^\s]+)\s+Flags\s+\[S\.\]', line)
            if syn_ack_match:
                timestamp, source_ip, dest_ip = syn_ack_match.groups()
                print(f"Detected SYN-ACK packet: {source_ip} -> {dest_ip} at {timestamp}")
                if (dest_ip, source_ip) in ongoing_connections and 'SYN' in ongoing_connections[(dest_ip, source_ip)]:
                    ongoing_connections[(dest_ip, source_ip)]['SYN-ACK'] = timestamp
                connections["ips"].add(source_ip)
                connections["ips"].add(dest_ip)
                continue

            # Match ACK packet (Final step of the handshake)
            ack_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([^\s]+)\s+>\s+([^\s]+)\s+Flags\s+\[\.\]', line)
            if ack_match:
                timestamp, source_ip, dest_ip = ack_match.groups()
                print(f"Detected ACK packet: {source_ip} -> {dest_ip} at {timestamp}")
                if (source_ip, dest_ip) in ongoing_connections and 'SYN' in ongoing_connections[(source_ip, dest_ip)] and 'SYN-ACK' in ongoing_connections[(source_ip, dest_ip)]:
                    connections["successful"].append({
                        "timestamp": timestamp,
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "status": "successful"
                    })
                    print(f"Successful connection: {source_ip} -> {dest_ip} at {timestamp}")
                    del ongoing_connections[(source_ip, dest_ip)]
                else:
                    # Failed connection (missing SYN or SYN-ACK)
                    connections["failed"].append({
                        "timestamp": timestamp,
                        "source_ip": source_ip,
                        "dest_ip": dest_ip,
                        "status": "failed"
                    })
                    print(f"Failed connection: {source_ip} -> {dest_ip} at {timestamp}")
                connections["ips"].add(source_ip)
                connections["ips"].add(dest_ip)
                continue

            # Detect errors (such as failed connection attempts or protocol errors)
            if 'RST' in line:  # TCP Reset Flag error
                connections["errors"].append(f"Error: TCP Reset - Connection aborted detected at {line}")
            elif 'NXDomain' in line or 'error' in line.lower() or 'fail' in line.lower():  # DNS or Protocol errors
                connections["errors"].append(f"Error: {line.strip()}")

    return connections






def check_successful_connection(packets):

    successful_connections = []
    
    for i in range(1, len(packets) - 1):
        packet1 = packets[i - 1]
        packet2 = packets[i]
        packet3 = packets[i + 1]

        # Look for SYN packets (client-to-server)
        if 'S' in packet1['Flags'] and 'A' not in packet1['Flags']:
            # Look for SYN-ACK response (server-to-client)
            if 'S' in packet2['Flags'] and 'A' in packet2['Flags']:
                # Look for final ACK from client to complete handshake
                if 'A' in packet3['Flags'] and 'S' not in packet3['Flags']:
                    successful_connections.append((packet1, packet2, packet3))
    
    return successful_connections





@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)
    file = request.files['file']
    if file and allowed_file(file.filename):
        filename = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filename)
        data = extract_info_from_file(filename)  # Analyze the uploaded file
        
        # Check if there are any errors and prepare a summary for display
        error_messages = data["errors"] if data["errors"] else ["No errors detected"]
        
        return render_template('results.html', data=data, errors=error_messages)
    return 'Invalid file format'



if __name__ == '__main__':
    app.run(debug=True)
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])








# Example usage:
file_path = r'C:\Users\HP\OneDrive\Desktop\SAE105\uploads\fichier1000'
data = extract_info_from_file(file_path)
print("Successful connections:", data["successful"])
print("Failed connections:", data["failed"])
print("Errors:", data["errors"])
print("Unique IPs:", data["ips"])


