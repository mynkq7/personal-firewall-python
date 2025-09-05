# Personal Firewall using Python
# Project Overview

This project is a lightweight personal firewall built in Python. It monitors incoming and outgoing network packets and applies rule-based filtering to block or allow traffic. Suspicious or unauthorized connections are logged for auditing purposes.

The firewall is built as a proof-of-concept tool for learning about network security, packet analysis, and intrusion prevention systems (IPS/IDS).

# Objectives

Capture real-time network packets.

Define rules to block or allow traffic (based on IP, port, or protocol).

Log all suspicious packets for security analysis.

Provide practical exposure to packet sniffing, firewalls, and endpoint security.

# Tools & Technologies

Python – Core programming language

Scapy – For packet sniffing and traffic analysis

Logging – To maintain logs of blocked packets

iptables (Linux) – To enforce firewall rules at system level (optional)

Tkinter (optional) – For GUI-based monitoring

# Installation & Setup
1. Clone the Repository
git clone https://github.com/your-username/personal-firewall-python.git
cd personal-firewall-python

2. Install Dependencies
pip install -r requirements.txt

3. Run the Firewall
sudo python3 firewall.py

# Files in Repository

firewall.py → Main firewall script

requirements.txt → Dependencies

README.md → Project description

firewall.log → Generated log file with blocked packets

# Sample Output
Personal Firewall Started...
Blocking traffic from 192.168.1.100
Allowed packet from 192.168.1.5 to 142.250.183.110
Blocked packet from 192.168.1.100 to 192.168.1.5

# Conclusion

This project demonstrates how personal firewalls work internally and gives hands-on experience with packet sniffing, rule-based filtering, and network monitoring. It is an excellent learning step towards building advanced Intrusion Detection and Prevention Systems (IDPS).irewall-python
