import pandas as pd
import numpy as np
import joblib
import tempfile
import os
import time

from ml.preprocessing import load_and_preprocess
from ml.model import build_bilstm


# =================================================
# PATHS (VERY IMPORTANT)
# =================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(BASE_DIR))

MODEL_PATH = os.path.join(PROJECT_ROOT, "bilstm_ids.weights.h5")
ENCODER_PATH = os.path.join(PROJECT_ROOT, "label_encoder.pkl")
SCALER_PATH = os.path.join(PROJECT_ROOT, "scaler.pkl")
COLUMNS_PATH = os.path.join(PROJECT_ROOT, "training_columns.pkl")

# =================================================
# LOAD PREPROCESSING OBJECTS
# =================================================
scaler = joblib.load(SCALER_PATH)
label_encoder = joblib.load(ENCODER_PATH)
training_columns = joblib.load(COLUMNS_PATH)

num_classes = len(label_encoder.classes_)


# =================================================
# LOAD MODEL SAFELY
# ================================================
def load_model():
    input_shape = (1, len(training_columns))

    model = build_bilstm(input_shape, num_classes)

    # Force layer creation
    model.build((None, *input_shape))

    model.load_weights(MODEL_PATH)

    return model






# =================================================
# SEVERITY LOGIC
# =================================================
def detect_severity(attack):
    attack = str(attack).lower()

    if attack == "normal":
        return "Low"
    elif attack in ["probe"]:
        return "Medium"
    elif attack in ["dos", "r2l", "u2r"]:
        return "High"
    else:
        return "Medium"


# =================================================
# OFFLINE DETECTION
# =================================================
def run_detection(file_input):

    model = load_model()

    # Handle UploadedFile or bytes
    if isinstance(file_input, bytes):
        file_bytes = file_input
    else:
        file_bytes = file_input.getvalue()

    # Save temp CSV
    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(file_bytes)
        temp_path = tmp.name

    df = pd.read_csv(temp_path)

    X, _, _, _, _ = load_and_preprocess(
        filepath=temp_path,
        training=False,
        has_header=True,
        scaler=scaler,
        label_encoder=label_encoder,
        training_columns=training_columns
    )

    os.remove(temp_path)

    if X.ndim == 2:
        X = np.expand_dims(X, axis=1)

    preds = model.predict(X, verbose=0)

    pred_classes = np.argmax(preds, axis=1)
    pred_labels = label_encoder.inverse_transform(pred_classes)
    confidence = np.max(preds, axis=1)

    df["Predicted_Attack"] = pred_labels
    df["Confidence"] = confidence.round(3)
    df["Severity"] = df["Predicted_Attack"].apply(detect_severity)

    return df


# =================================================
# LIVE STREAM DETECTION
# =================================================
def stream_detection(file_input, delay=1, start_index=0):

    model = load_model()

    # Handle UploadedFile or bytes
    if isinstance(file_input, bytes):
        file_bytes = file_input
    else:
        file_bytes = file_input.getvalue()

    with tempfile.NamedTemporaryFile(delete=False, suffix=".csv") as tmp:
        tmp.write(file_bytes)
        temp_path = tmp.name

    df = pd.read_csv(temp_path)

    X, _, _, _, _ = load_and_preprocess(
        filepath=temp_path,
        training=False,
        has_header=True,
        scaler=scaler,
        label_encoder=label_encoder,
        training_columns=training_columns
    )

    os.remove(temp_path)

    if X.ndim == 2:
        X = np.expand_dims(X, axis=1)

    for i in range(start_index, len(X)):

        row_X = X[i:i + 1]

        preds = model.predict(row_X, verbose=0)

        pred_class = np.argmax(preds, axis=1)[0]
        pred_label = label_encoder.inverse_transform([pred_class])[0]
        confidence = float(np.max(preds))

        yield {
            "row": i + 1,
            "prediction": pred_label,
            "confidence": round(confidence, 3),
            "severity": detect_severity(pred_label)
        }

        time.sleep(delay)
