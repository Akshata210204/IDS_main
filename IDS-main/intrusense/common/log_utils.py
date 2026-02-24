import os
import pandas as pd
from datetime import datetime
import csv
from common.feature_template import base_feature_vector
BASE_DIR = "logs"


def _user_dir(user_email):
    path = os.path.join(BASE_DIR, user_email.replace("@", "_"))
    os.makedirs(path, exist_ok=True)
    return path


from common.feature_template import base_feature_vector

def start_new_session(user_email):
    user_path = _user_dir(user_email)

    existing = sorted(os.listdir(user_path))
    session_no = len(existing) + 1

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"session_{session_no}_{timestamp}.csv"
    filepath = os.path.join(user_path, filename)

    # 🔥 USE FEATURE TEMPLATE AS CSV HEADER
    features = base_feature_vector()

    columns = (
        ["timestamp", "packet"]
        + list(features.keys())
        + ["attack_name", "attack_class", "severity", "confidence"]
    )

    pd.DataFrame(columns=columns).to_csv(filepath, index=False)
    return filepath


def save_log(filepath, row):
    """
    Save a single log row to the CSV file.
    Ensures all feature columns are present and headers are properly maintained.
    """
    # Check if file exists and is empty
    file_exists = os.path.isfile(filepath)
    is_empty = not file_exists or os.path.getsize(filepath) == 0
    
    # Add timestamp if not present
    if 'timestamp' not in row:
        row['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Get all fieldnames from the row
    fieldnames = list(row.keys())
    
    # Make sure timestamp is first
    if 'timestamp' in fieldnames:
        fieldnames.remove('timestamp')
        fieldnames = ['timestamp'] + fieldnames
    
    # Write to file
    with open(filepath, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        # Write header if file is empty
        if is_empty:
            writer.writeheader()
        
        # Write the row
        writer.writerow(row)



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
