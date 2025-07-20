# Automate-firewall
This tool performs real-time packet inspection, checks for malicious IPs using VirusTotal and public blacklists, and automatically blocks threats using iptables.

## Features
* Downloads and parses IP blacklist from myip.ms.
* Sniffs incoming packets using Scapy.
* Checks suspicious IPs and payloads against VirusTotal API.
* Blocks malicious IPs via iptables.
* Stores blacklisted IPs in a MariaDB database.
* Redirects suspicious SSH traffic to a honeypot port (2222). Run a honeypot like Cowrie by pulling its image.

## Requirements
* Python 3.7+
* Linux OS (due to use of iptables)
* Packages: scapy, mariadb, requests
* MariadbDB server with
  CREATE DATABASE blacklist;
  USE blacklist;
  CREATE TABLE blacklist (
    ip VARCHAR(45) PRIMARY KEY,
    date_added DATE
  );

## Files
* blacklist.txt: Raw blacklist from myip.ms
* final_list.txt: Processed recent IPs
* recent_date.txt: Tracks last processed date
