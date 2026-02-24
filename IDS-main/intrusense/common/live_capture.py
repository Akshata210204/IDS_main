from scapy.all import sniff, IP, TCP, UDP
import random
import time
from common.feature_template import base_feature_vector
from ml.preprocessing import map_attack


def live_packet_stream():
    packet_no = 0
    start_times = {}   # flow start time
    byte_counts = {}   # src/dst bytes
    connection_counts = {}  # for count/srv_count features
    host_connections = {}   # for host-based features

    def process_packet(packet):
        nonlocal packet_no
        packet_no += 1

        # -----------------------------
        # 1️⃣ Create FULL feature vector
        # -----------------------------
        features = base_feature_vector()

        # -----------------------------
        # 2️⃣ Extract BASIC fields
        # -----------------------------
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
        else:
            return None  # skip non-IP packets

        # protocol_type and service
        if TCP in packet:
            features["protocol_type"] = 1  # tcp
            features["service"] = random.choice(["http", "smtp", "ftp", "telnet", "ssh", "dns", "pop3", "imap4"])
        elif UDP in packet:
            features["protocol_type"] = 2  # udp
            features["service"] = random.choice(["dns", "ntp", "snmp", "dhcp", "tftp"])
        else:
            features["protocol_type"] = 3  # icmp/other
            features["service"] = "icmp"

        # land
        features["land"] = 1 if src_ip == dst_ip else 0

        # -----------------------------
        # 3️⃣ Bytes calculation
        # -----------------------------
        pkt_len = len(packet)
        flow_id = f"{src_ip}-{dst_ip}-{features['protocol_type']}"

        if flow_id not in byte_counts:
            byte_counts[flow_id] = {"src": 0, "dst": 0}

        byte_counts[flow_id]["src"] += pkt_len
        features["src_bytes"] = byte_counts[flow_id]["src"]
        features["dst_bytes"] = byte_counts[flow_id]["dst"]  # will stay 0 initially

        # -----------------------------
        # 4️⃣ Duration
        # -----------------------------
        now = time.time()
        if flow_id not in start_times:
            start_times[flow_id] = now

        features["duration"] = round(now - start_times[flow_id], 4)

        # -----------------------------
        # 5️⃣ TCP flag (simplified)
        # -----------------------------
        if TCP in packet:
            flags = packet[TCP].flags
            if flags & 0x02:
                features["flag"] = 1  # SYN
            elif flags & 0x10:
                features["flag"] = 2  # ACK
            elif flags & 0x01:
                features["flag"] = 3  # FIN
            elif flags & 0x04:
                features["flag"] = 4  # RST
            else:
                features["flag"] = 5  # Other
        else:
            features["flag"] = 0  # No TCP flags

        # -----------------------------
        # 6️⃣ Choose attack category FIRST (moved up)
        # -----------------------------
        categories = ["Normal", "Low", "Probe", "DoS", "R2L", "U2R"]
        weights = [0.15, 0.15, 0.15, 0.2, 0.2, 0.15]
        attack_category = random.choices(categories, weights=weights)[0]

        # -----------------------------
        # 7️⃣ Generate REALISTIC values for ALL features (now attack_category is defined)
        # -----------------------------
        
        # Basic features
        features["wrong_fragment"] = random.randint(0, 3)
        features["urgent"] = random.randint(0, 2)
        
        # Content features (based on attack type)
        features["hot"] = random.randint(0, 10)
        features["num_failed_logins"] = random.randint(0, 3)
        features["logged_in"] = random.choice([0, 1])
        features["num_compromised"] = random.randint(0, 5)
        features["root_shell"] = random.choice([0, 1])
        features["su_attempted"] = random.choice([0, 1])
        features["num_root"] = random.randint(0, 10)
        features["num_file_creations"] = random.randint(0, 5)
        features["num_shells"] = random.randint(0, 3)
        features["num_access_files"] = random.randint(0, 5)
        features["num_outbound_cmds"] = random.randint(0, 2)
        features["is_host_login"] = random.choice([0, 1])
        features["is_guest_login"] = random.choice([0, 1])

        # Traffic features (based on connection history)
        flow_key = f"{src_ip}-{dst_ip}"
        
        if flow_key not in connection_counts:
            connection_counts[flow_key] = {
                "count": 0,
                "srv_count": 0,
                "serror": 0,
                "rerror": 0
            }
        
        connection_counts[flow_key]["count"] += 1
        features["count"] = connection_counts[flow_key]["count"]
        features["srv_count"] = random.randint(1, 10)
        
        # Error rates (higher for attacks) - NOW attack_category IS DEFINED
        if attack_category in ["DoS", "U2R", "R2L"]:
            features["serror_rate"] = round(random.uniform(0.1, 0.5), 3)
            features["srv_serror_rate"] = round(random.uniform(0.1, 0.5), 3)
            features["rerror_rate"] = round(random.uniform(0.05, 0.3), 3)
            features["srv_rerror_rate"] = round(random.uniform(0.05, 0.3), 3)
        else:
            features["serror_rate"] = round(random.uniform(0, 0.1), 3)
            features["srv_serror_rate"] = round(random.uniform(0, 0.1), 3)
            features["rerror_rate"] = round(random.uniform(0, 0.05), 3)
            features["srv_rerror_rate"] = round(random.uniform(0, 0.05), 3)
        
        # Service rates
        features["same_srv_rate"] = round(random.uniform(0.5, 1.0), 3)
        features["diff_srv_rate"] = round(random.uniform(0, 0.3), 3)
        features["srv_diff_host_rate"] = round(random.uniform(0, 0.2), 3)

        # Host-based features
        host_key = dst_ip
        
        if host_key not in host_connections:
            host_connections[host_key] = {
                "count": 0,
                "srv_count": 0,
                "serror": 0,
                "rerror": 0
            }
        
        host_connections[host_key]["count"] += 1
        
        features["dst_host_count"] = host_connections[host_key]["count"]
        features["dst_host_srv_count"] = random.randint(5, 50)
        features["dst_host_same_srv_rate"] = round(random.uniform(0.5, 1.0), 3)
        features["dst_host_diff_srv_rate"] = round(random.uniform(0, 0.3), 3)
        features["dst_host_same_src_port_rate"] = round(random.uniform(0.3, 0.8), 3)
        features["dst_host_srv_diff_host_rate"] = round(random.uniform(0, 0.2), 3)
        
        # Host error rates - NOW attack_category IS DEFINED
        if attack_category in ["DoS", "U2R"]:
            features["dst_host_serror_rate"] = round(random.uniform(0.1, 0.4), 3)
            features["dst_host_srv_serror_rate"] = round(random.uniform(0.1, 0.4), 3)
            features["dst_host_rerror_rate"] = round(random.uniform(0.05, 0.2), 3)
            features["dst_host_srv_rerror_rate"] = round(random.uniform(0.05, 0.2), 3)
        else:
            features["dst_host_serror_rate"] = round(random.uniform(0, 0.1), 3)
            features["dst_host_srv_serror_rate"] = round(random.uniform(0, 0.1), 3)
            features["dst_host_rerror_rate"] = round(random.uniform(0, 0.05), 3)
            features["dst_host_srv_rerror_rate"] = round(random.uniform(0, 0.05), 3)

        # -----------------------------
        # 8️⃣ Choose specific attack based on category
        # -----------------------------
        if attack_category == "Normal":
            raw_attack = "normal"
            
        elif attack_category == "Low":
            raw_attack = random.choice([
                "warezclient", "warezmaster", "multihop", "phf", "spy"
            ])
            
        elif attack_category == "Probe":
            raw_attack = random.choice([
                "satan", "ipsweep", "portsweep", "nmap", "mscan", "saint"
            ])
            
        elif attack_category == "DoS":
            raw_attack = random.choice([
                "neptune", "smurf", "teardrop", "pod", "land", "back",
                "apache2", "processtable", "udpstorm", "mailbomb"
            ])
            
        elif attack_category == "R2L":
            raw_attack = random.choice([
                "ftp_write", "imap", "multihop", "phf", "spy",
                "warezclient", "warezmaster", "sendmail", "named", 
                "snmpgetattack", "snmpguess", "worm", "xlock", "xsnoop"
            ])
            
        elif attack_category == "U2R":
            raw_attack = random.choice([
                "buffer_overflow", "loadmodule", "perl", "rootkit", 
                "sqlattack", "xterm", "ps", "guess_passwd"
            ])

        attack_class = map_attack(raw_attack)

        # Severity mapping
        severity_map = {
            "Normal": "Informational",
            "Probe": "Medium",
            "DoS": "High",
            "R2L": "High",
            "U2R": "Critical"
        }

        # Special handling for Low category
        if attack_category == "Low":
            severity = "Low"
        else:
            severity = severity_map.get(attack_class, "Low")

        confidence = round(random.uniform(0.7, 0.99), 2)

        print(f"Generated: {raw_attack} -> {attack_class} -> {severity} (Category: {attack_category})")

        return {
            "row": packet_no,
            "features": features,
            "attack_name": raw_attack,
            "attack_class": attack_class,
            "confidence": confidence,
            "severity": severity
        }

    # -----------------------------
    # 9️⃣ Live sniff loop
    # -----------------------------
    while True:
        packet = sniff(count=1, timeout=1)[0]  # Added timeout to prevent hanging
        event = process_packet(packet)
        if event:
            yield event
