Network Intrusion Detection System (NIDS)
📌 Overview
This project is a Network Intrusion Detection System (NIDS) built using Streamlit, Scikit-learn, and Scapy. It utilizes a Random Forest machine learning model to analyze network traffic data and detect potential cyberattacks. The application offers three main functionalities: static file analysis, a simulated operating system attack checker, and a live network traffic monitor.

🚀 Features
1. Intruder Detector (Static Analysis)
Batch Processing: Upload network logs (.txt or .csv) containing traffic data.

ML-Based Detection: Uses a trained Random Forest Classifier to categorize traffic as "Normal" or "Attack."

Visualization: Displays traffic distribution and highlights detected attacks in a detailed log view using color coding.

Supported Dataset Format: Designed to work with the NSL-KDD dataset structure.

2. Attacker Checker (OS Simulation)
Scenario Simulation: Simulates specific attack types (e.g., Neptune, Satan) on different Operating Systems (Windows, Linux, Android, Mac).

Impact Analysis: Provides descriptive feedback on how the selected attack affects the chosen OS.

Severity Assessment: Categorizes the threat level (Low to Critical) based on the volume of attack traffic input.

3. Live Detection (Network Sniffer)
Real-Time Monitoring: Captures live network packets using scapy.

Traffic Analysis: Extracts Source IP, Destination IP, Protocol (TCP/UDP), and Packet Length.

Alert System: Flags suspicious activity, such as unusually large packets entering the network.

🛠️ Technology Stack
Python: Core programming language.

Streamlit: Web interface for easy interaction.

Scikit-learn: Machine learning library for training the detection model.

Pandas: Data manipulation and analysis.

Scapy: Packet manipulation program for live network sniffing.

Joblib: For saving and loading the trained model.

⚙️ Installation & Setup
Prerequisites
For Windows Users:

Python 3.7+ installed.

Npcap: Required for Scapy. Download from https://npcap.com/. Ensure you check "Install Npcap in WinPcap API-compatible Mode" during installation.

For Linux / Ubuntu Users:

Python 3.7+ installed.

System Libraries: You may need to install libpcap for Scapy to function correctly.

Bash

sudo apt-get update
sudo apt-get install python3-pip libpcap0.8
Step 1: Clone the Repository
Bash

git clone https://github.com/ombulids/Network-Intrusion-Detection-System-NIDS-
cd network-intrusion-detection
Step 2: Install Dependencies
Run the following command to install the required Python libraries:

Bash

pip install streamlit pandas scikit-learn scapy joblib
(Note: On Linux, if you get a "permission denied" error, use pip3 or add --user to the end of the command).

Step 3: Dataset Preparation
Download the NSL-KDD dataset (specifically KDDTrain+.txt).

Place the KDDTrain+.txt file in the root directory of the project.

Note: On the first run, the system will automatically train the model and save it as Model_Nids.pkl.

Step 4: Run the Application
Windows:

Bash

streamlit run UpdateProject.py
Linux / Ubuntu: To use the Live Detection feature, you must run Streamlit with root privileges (sudo), otherwise Scapy cannot access the network interface.

Bash

sudo streamlit run UpdateProject.py --server.port 8501
(If sudo streamlit is not found, you may need to run it via python: sudo python3 -m streamlit run UpdateProject.py)

⚠️ Important Note regarding Live Detection
The "Live Detection" feature relies on scapy, which interacts directly with network interfaces.

Windows: You must install Npcap (or Nmap) for this to work. You may also need to run your terminal/IDE as Administrator.

Linux/Ubuntu: You must run the script with sudo. If you run it without sudo, the "Live Detection" tab will likely show an error saying "Operation not permitted" when it tries to sniff packets.


📂 Project Structure
├── UpdateProject.py    # Main Streamlit application file
├── KDDTrain+.txt       # Training dataset (User must provide this)
├── Model_Nids.pkl      # Saved Machine Learning Model (Generated after first run)
└── README.md           # Project Documentation
🤝 Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes.

📜 License
This project is licensed under the MIT License.