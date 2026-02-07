import os
import pandas as pd
from datetime import datetime
import csv
BASE_DIR = "logs"


def _user_dir(user_email):
    path = os.path.join(BASE_DIR, user_email.replace("@", "_"))
    os.makedirs(path, exist_ok=True)
    return path


def start_new_session(user_email):
    user_path = _user_dir(user_email)

    existing = sorted(os.listdir(user_path))
    session_no = len(existing) + 1

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"session_{session_no}_{timestamp}.csv"

    filepath = os.path.join(user_path, filename)

    pd.DataFrame(columns=[
        "timestamp",
        "packet",
        "attack",
        "severity",
        "confidence"
    ]).to_csv(filepath, index=False)


    return filepath


def save_log(filepath, row):
    file_exists = os.path.exists(filepath)

    with open(filepath, "a", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["timestamp", "packet", "attack", "severity", "confidence"]
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "packet": row["packet"],
            "attack": row["attack"],
            "severity": row["severity"],
            "confidence": row["confidence"]
        })

def list_sessions(user_email):
    user_path = _user_dir(user_email)
    files = sorted(os.listdir(user_path), reverse=True)  # 🔥 newest first

    sessions = []
    total = len(files)

    for i, f in enumerate(files):
        parts = f.replace(".csv", "").split("_", 2)
        timestamp = parts[2].replace("_", " ")
        sessions.append({
            "session_no": total - i,   # keeps numbering logical
            "filename": f,
            "timestamp": timestamp
        })

    return sessions, user_path



def delete_session(user_email, filename):
    user_path = _user_dir(user_email)
    os.remove(os.path.join(user_path, filename))
