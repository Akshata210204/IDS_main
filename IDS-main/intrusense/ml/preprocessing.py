import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
""""
# Map attacks into 3 categories
def map_attack(x):
    x = str(x).lower().strip()
    if x == "normal":
        return "Normal"
    elif x in ["neptune","smurf","teardrop","pod","land","back"]:
        return "DoS"
    elif x in ["satan","ipsweep","portsweep","nmap"]:
        return "Probe"
    else:
        return "Normal"  # fallback
"""  
def map_attack(x):
    x = str(x).lower().strip()

    # Normal Traffic
    if x == "normal":
        return "Normal"

    # Denial of Service (DoS) Attacks
    elif x in [
        "neptune", "smurf", "teardrop", "pod", "land", "back",
        "apache2", "processtable", "udpstorm", "mailbomb"
    ]:
        return "DoS"

    # Probe / Reconnaissance Attacks
    elif x in [
        "satan", "ipsweep", "portsweep", "nmap", "mscan", "saint"
    ]:
        return "Probe"

    # Remote to Local (R2L) Attacks
    elif x in [
        "ftp_write", "imap", "multihop", "phf", "spy",
        "warezclient", "warezmaster", "sendmail", "named", "snmpgetattack",
        "snmpguess", "worm", "xlock", "xsnoop"
    ]:
        return "R2L"

    # User to Root (U2R) Attacks
    elif x in [
        "buffer_overflow", "guess_passwd","loadmodule", "perl", "rootkit", "sqlattack", "xterm", "ps"
    ]:
        return "U2R"

    # Fallback (for any unknown labels)
    else:
        return "Normal"

def load_and_preprocess(filepath, training=True, scaler=None, label_encoder=None, training_columns=None, has_header=True):
    # Read CSV (with headers if has_header=True)
    if has_header:
        df = pd.read_csv(filepath, header=0)
    else:
        raise ValueError("Your file is CSV with headers. Please set has_header=True.")

    # Drop difficulty if exists
    if "difficulty" in df.columns:
        df = df.drop(columns=["difficulty"])

    # Map attack labels
    df["label"] = df["label"].apply(map_attack)

    # Split features and labels
    X = df.drop("label", axis=1)
    y = df["label"]

    # One-hot encode categorical features
    X = pd.get_dummies(X, columns=["protocol_type","service","flag"])

    if training:
        # Save training columns
        training_columns = X.columns

        # Scale numerical values
        scaler = StandardScaler()
        X = scaler.fit_transform(X)

        # Encode labels
        label_encoder = LabelEncoder()
        y = label_encoder.fit_transform(y)

        return X, y, scaler, label_encoder, list(training_columns)

    else:
        # Reindex with training columns (align test data with train structure)
        X = X.reindex(columns=training_columns, fill_value=0)

        # Scale using trained scaler
        X = scaler.transform(X)

        # Encode labels
        y = label_encoder.transform(y)

        return X, y, None, None, None
