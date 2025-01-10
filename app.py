from flask import Flask, render_template, request, redirect, url_for, send_file
import os
import re
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import RawPcapReader
from datetime import datetime


app = Flask(__name__)
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pcap'}

# Check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Home route to render the upload page
@app.route('/')
def index():
    return render_template('upload.html')

# Function to process txt files
def process_txt_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
    return analyze_tcpdump(lines)


# Detailed TCPDump analysis function
def analyze_tcpdump(file_lines):
    connections = {
        "successful": [],
        "failed": [],
        "dns_queries": [],
        "errors": [],
        "all_packets": [],
        "unique_ips": set()
    }

    for line in file_lines:
        # Match successful connections (SYN packets)
        syn_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([^\s]+)\s+>\s+([^\s]+).*Flags\s+\[S\]', line)
        if syn_match:
            timestamp, source_ip, dest_ip = syn_match.groups()
            connections["successful"].append({
                "timestamp": timestamp,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "status": "Successful (SYN Packet)"
            })
            connections["unique_ips"].update([source_ip, dest_ip])

        # Match failed connections (RST packets)
        rst_match = re.match(r'(\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+([^\s]+)\s+>\s+([^\s]+).*Flags\s+\[R\]', line)
        if rst_match:
            timestamp, source_ip, dest_ip = rst_match.groups()
            connections["failed"].append({
                "timestamp": timestamp,
                "source_ip": source_ip,
                "dest_ip": dest_ip,
                "status": "Failed (RST Packet)"
            })
            connections["unique_ips"].update([source_ip, dest_ip])

        # Identify DNS queries
        if 'PTR?' in line or 'A?' in line:
            connections["dns_queries"].append(line.strip())

        # Detect errors (RST, NXDomain, etc.)
        if 'RST' in line or 'NXDomain' in line or 'error' in line.lower():
            connections["errors"].append(line.strip())

        # Store all packet information
        connections["all_packets"].append(line.strip())

    return connections

# Function to generate graphs
import uuid  # Import this at the top of your file

def generate_graphs(data):
    successful_count = len(data["successful"])
    failed_count = len(data["failed"])
    dns_count = len(data["dns_queries"])
    errors_count = len(data["errors"])

    # Generate unique filenames for the graphs
    graph1_filename = f"connection_types_{uuid.uuid4().hex}.png"
    graph2_filename = f"connection_counts_{uuid.uuid4().hex}.png"

    # Generate a pie chart
    fig1, ax1 = plt.subplots()
    ax1.pie([successful_count, failed_count, dns_count, errors_count],
            labels=["Successful", "Failed", "DNS Queries", "Errors"],
            autopct='%1.1f%%', startangle=90)
    ax1.axis('equal')
    plt.title('Connection Types')
    plt.savefig(os.path.join(app.root_path, 'static', graph1_filename))
    plt.close()

    # Generate a bar chart
    fig2, ax2 = plt.subplots()
    ax2.bar(["Successful", "Failed", "DNS Queries", "Errors"],
            [successful_count, failed_count, dns_count, errors_count],
            color=['green', 'red', 'blue', 'orange'])
    plt.title('Connection Counts')
    plt.ylabel('Count')
    plt.savefig(os.path.join(app.root_path, 'static', graph2_filename))
    plt.close()

    # Return the graph filenames
    return graph1_filename, graph2_filename


# Upload route to handle file uploads and analysis
@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return redirect(request.url)

    file = request.files['file']
    if file and allowed_file(file.filename):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        try:
            # Process the file based on extension
            if file.filename.endswith('.txt'):
                data = process_txt_file(file_path)
            elif file.filename.endswith('.pcap'):
                data = process_pcap_file(file_path)
            else:
                return 'Unsupported file format'

            # Generate a unique Excel filename
            excel_filename = f"tcpdump_analysis_{datetime.now().strftime('%Y%m%d%H%M%S')}.xlsx"
            excel_path = os.path.join(app.config['UPLOAD_FOLDER'], excel_filename)

            # Convert successful and failed connections to DataFrames and save to Excel
            successful_df = pd.DataFrame(data["successful"])
            failed_df = pd.DataFrame(data["failed"])

            with pd.ExcelWriter(excel_path) as writer:
                successful_df.to_excel(writer, sheet_name="Successful Connections", index=False)
                failed_df.to_excel(writer, sheet_name="Failed Connections", index=False)

            # Pass the filename to the results page
            return render_template('results.html', data=data, excel_url=url_for('download_excel', filename=excel_filename))
        except Exception as e:
            return f"An error occurred: {str(e)}"
    else:
        return 'Invalid file format'


# Route to download the Excel report
@app.route('/download_excel/<filename>')
def download_excel(filename):
    excel_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    return send_file(excel_path, as_attachment=True)



# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)


