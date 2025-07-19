from scapy.all import *
import time
import ipaddress
import os
import datetime
import requests
import subprocess
import mariadb
from concurrent.futures import ThreadPoolExecutor
executor = ThreadPoolExecutor(max_workers=10)  # Thread pool to manage concurrent tasks

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # Ignore SSL cert warnings

# Get local IP address
result = os.popen("hostname -I | awk '{print $1}'")
var = result.read().strip()

# VirusTotal API key
apikey = "your api key"

cursor = None
conn = None

# Establish DB connection
def DB_connect():
    global cursor, conn
    try:
        conn = mariadb.connect(
            user="firewall_user",
            password="securepass",
            host="localhost",
            port=3306,
            database="blacklist"
        )
        print("Connected to MariaDB successfully!")
        cursor = conn.cursor()
    except mariadb.Error as e:
        print(f"Error connecting to MariaDB: {e}")
        exit(1)

# Download and process blacklist from myip.ms
def blacklist_prep():
    today = datetime.datetime.now()
    try:
        r = requests.get("https://myip.ms/files/blacklist/general/latest_blacklist.txt", verify=False, timeout=10)
        content = r.text
    except Exception as e:
        print("Failed to download blacklist:", str(e))
        return

    try:
        with open("recent_date.txt", "r") as f:
            y, m, d = map(int, f.read().strip().split("-"))
            recent_date = datetime.datetime(y, m, d)
    except:
        recent_date = today - datetime.timedelta(days=7)

    with open("blacklist.txt", "w") as f:
        f.write(content)

    max_seen_date = recent_date
    with open("blacklist.txt", "r") as black, open("final_list.txt", "w") as final:
        for line in black:
            if line.startswith("#") or line.strip() == "":
                continue
            try:
                ip_part, meta_part = line.split("#", 1)
                ip = ip_part.strip()
                date_str = meta_part.split(",")[0].strip()
                y, m, d = map(int, date_str.split("-"))
                entry_date = datetime.datetime(y, m, d)

                if (today - entry_date).days <= 7:
                    final.write(f"{ip},{date_str}\n")
                    if entry_date > max_seen_date:
                        max_seen_date = entry_date
            except Exception as e:
                continue  # skip malformed lines

    with open("recent_date.txt", "w") as f:
        f.write(max_seen_date.strftime("%Y-%m-%d"))

    print("blacklist prepared")

# Add malicious IP to iptables and insert into DB
def ip_tables_update(ipadd):
    try:
        subprocess.check_call(f"iptables -A INPUT -s {ipadd} -j DROP", shell=True)
        cursor.execute("INSERT IGNORE INTO blacklist (ip, date_added) VALUES (?, ?)", (ipadd, str(datetime.datetime.now().date())))
        conn.commit()
        return True
    except:
        return False

# Polls VirusTotal for payload analysis result
def payload_id_analysis(id, ip):
    headers = {"x-apikey": apikey}
    while True:
        response = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
        time.sleep(15)  # Polling delay

        if response.status_code == 200:
            result = response.json()
            status = result["data"]["attributes"]["status"]

            if status == "completed":
                detections = result["data"]["attributes"]
                stat_analysis = detections.get('last_analysis_stats')
                malicious = stat_analysis.get('malicious')
                suspicious = stat_analysis.get('suspicious')
                undetected = stat_analysis.get('undetected')
                harmless = stat_analysis.get('harmless')

                print(f"stat analysis:{stat_analysis}")
                print(f"malicious: {malicious}")
                print(f"Suspicious: {suspicious}")
                print(f"Undetected: {undetected}")
                print(f"harmless: {harmless}")
                print(f"for {ip} payload analysis result")
                print(f"Malicious Detections: {detections}")

                # Block IP if payload found malicious
                if malicious:
                    result = ip_tables_update(ip)
                    if result:
                        print(ip + " successfully removed")
                    else:
                        print(ip + " unsuccessful removal")
                break
            else:
                print("Analysis in progress... Retrying in 10 seconds.")
                time.sleep(10)
        else:
            print("Failed to get analysis:", response.text)
            break

# Upload suspicious payloads to VirusTotal for analysis
def payload_check(packet):
    print("payload_check")
    if packet.haslayer(Raw):
        print("has payload")
        try:
            payload = bytes(packet[Raw].load)
            files = {"file": ("payload.bin", payload)}
            headers = {"x-apikey": apikey}

            while True:
                response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
                if response.status_code == 200:
                    print("file uploading...")
                    result = response.json()
                    id = result["data"]["id"]
                    print("Analysis in progress... getting ID and Retrying in 30 seconds.")
                    time.sleep(30)
                    executor.submit(payload_id_analysis, id, packet[IP].src)
                else:
                    print("Failed to get analysis:", response.text)
                    break
        except Exception as e:
            print("Failed to upload payload:", str(e))
            return None

# Look up an IP on VirusTotal and take action based on analysis
def virus_total_review(packet):
    ipadd = packet[IP].src
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ipadd}"
    headers = {'x-apikey': apikey}
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise requests.exceptions.RequestException(f"API request failed with status code {response.status_code}")

    response_json = response.json()
    if 'data' not in response_json:
        raise ValueError("Invalid response structure")

    attributes = response_json['data']['attributes']
    stat_analysis = attributes.get('last_analysis_stats')
    malicious = stat_analysis.get('malicious')
    suspicious = stat_analysis.get('suspicious')
    undetected = stat_analysis.get('undetected')
    harmless = stat_analysis.get('harmless')

    print(f"stat analysis:{stat_analysis}")
    print(f"malicious: {malicious}")
    print(f"Suspicious: {suspicious}")
    print(f"Undetected: {undetected}")
    print(f"harmless: {harmless}")

    if malicious:
        result = ip_tables_update(ipadd)
        if result:
            print(ipadd + " successfully removed")
        else:
            print(ipadd + " unsuccessful removal")
    elif suspicious:
        # If it's a suspicious IP attacking port 22 (SSH), redirect it to honeypot port
        if packet.haslayer(TCP) and packet[TCP].dport == 22:
            attacker_ip = packet[IP].src
            subprocess.run(f"iptables -t nat -A PREROUTING -s {attacker_ip} -p tcp --dport 22 -j REDIRECT --to-port 2222", shell=True)
        else:
            executor.submit(payload_id_analysis, id, packet)
    else:
        return

# Checks if packet IP is in known blacklist and triggers further checks
def ip_check(packet):
    print("ip check")
    final = open("final_list.txt", "r")
    final_list = final.readlines()
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        blacklist_ips = [line.strip().split(',')[0] for line in final_list]

        if ip_layer.src not in blacklist_ips and ip_layer.src != var:
            print(ip_layer.src)
        else:
            if not ipaddress.ip_address(ip_layer.src).is_private:
                print(f"The {ip_layer.src} is present in blacklist, hence checking virus total for confirmation")
                executor.submit(payload_check, packet)
    final.close()

def main():
    DB_connect()            # Initialize database
    blacklist_prep()        # Download and prep IP blacklist
    sniff(prn=ip_check)     # Start packet sniffing and handle via ip_check
    executor.shutdown(wait=True)  # Wait for all threads to complete

    # Cleanup DB resources
    if cursor:
        cursor.close()
    if conn:
        conn.close()

if __name__ == "__main__":
    main()
