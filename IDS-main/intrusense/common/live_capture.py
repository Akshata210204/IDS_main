from scapy.all import sniff, IP, TCP, UDP
import random
import time
from common.feature_template import base_feature_vector


def live_packet_stream():
    packet_no = 0
    start_times = {}   # flow start time
    byte_counts = {}   # src/dst bytes

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

        # protocol_type
        if TCP in packet:
            features["protocol_type"] = 1  # tcp
        elif UDP in packet:
            features["protocol_type"] = 2  # udp
        else:
            features["protocol_type"] = 3  # icmp/other

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

        # -----------------------------
        # 6️⃣ EVERYTHING ELSE STAYS ZERO
        # (content + host features)
        # -----------------------------

        # -----------------------------
        # 7️⃣ Fake ML output (for now)
        # -----------------------------
        attack = random.choice(["Normal", "DoS", "Probe"])
        confidence = round(random.uniform(0.7, 0.99), 2)
        severity = "Low" if attack == "Normal" else "High"

        return {
            "row": packet_no,
            "features": features,
            "prediction": attack,
            "confidence": confidence,
            "severity": severity
        }

    # -----------------------------
    # 8️⃣ Live sniff loop
    # -----------------------------
    while True:
        packet = sniff(count=1)[0]
        event = process_packet(packet)
        if event:
            yield event
