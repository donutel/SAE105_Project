import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import re

def analyze_file(file_path):
    successful = []
    failed = []

    problem_descriptions = []
    
    # Your existing script to process successful an
    # d failed connections here...
    # Replace this with the function process_file_with_failures()
    
    # For now, let's assume we return some mock data:
    successful = [
        {"Time": "11:42:06", "Source IP": "192.168.1.1", "Destination IP": "10.0.0.1", "Length": 120},
        {"Time": "11:43:06", "Source IP": "192.168.1.2", "Destination IP": "10.0.0.2", "Length": 200},
    ]
    failed = [
        {"Time": "11:45:06", "Raw Data": "Invalid DNS", "Problem": "DNS resolution failed"},
        {"Time": "11:50:06", "Raw Data": "Malformed Packet", "Problem": "Sequence numbers missing"}
    ]
    
    return successful, failed

def plot_data(successful, failed):
    # Pie chart for success vs. failure
    labels = ['Successful', 'Failed']
    sizes = [len(successful), len(failed)]
    colors = ['#4CAF50', '#FF5733']
    explode = (0.1, 0)  # explode the 1st slice

    fig, ax = plt.subplots()
    ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%',
           shadow=True, startangle=140)
    ax.axis('equal')  # Equal aspect ratio ensures the pie is drawn as a circle.

    st.pyplot(fig)

def main():
    st.title("TCPDump Connectivity Analyzer")
    st.write("Upload your TCPDump file for analysis.")

    uploaded_file = st.file_uploader("Upload a .txt file", type="txt")
    if uploaded_file is not None:
        # Save the file to process it
        with open("uploaded_file.txt", "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        # Process the file
        successful, failed = analyze_file("uploaded_file.txt")
        
        # Display results
        st.subheader("Connectivity Analysis")
        st.write(f"**Total Successful Connections:** {len(successful)}")
        st.write(f"**Total Failed Connections:** {len(failed)}")
        
        # Show tables
        if successful:
            st.subheader("Successful Connections")
            st.dataframe(pd.DataFrame(successful))
        if failed:
            st.subheader("Failed Connections and Diagnostics")
            st.dataframe(pd.DataFrame(failed))
        
        # Plot graphs
        st.subheader("Connectivity Summary")
        plot_data(successful, failed)

        # Recommendations for failed connections
        if failed:
            st.subheader("Recommendations for Failed Connections")
            for item in failed:
                st.write(f"- **Time {item['Time']}**: {item['Problem']}")

if __name__ == "__main__":
    main()
