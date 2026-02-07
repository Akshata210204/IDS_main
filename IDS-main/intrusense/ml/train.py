import joblib
import time
import numpy as np
import json
import os
from pathlib import Path

from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.utils.class_weight import compute_class_weight
from sklearn.model_selection import StratifiedShuffleSplit

from tensorflow.keras.callbacks import Callback
from tensorflow.keras.models import load_model

from preprocessing import load_and_preprocess
from model import build_bilstm

# =======================================
# BASIC SETUP
# =======================================
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "2"

BASE_DIR = Path(__file__).resolve().parent
STATUS_FILE = BASE_DIR / "training_status.json"
RESULTS_FILE = BASE_DIR / "training_results.json"

EPOCHS = 2   # keep this SAME in Streamlit

# =======================================
# RESET STATUS FILE (IMPORTANT)
# =======================================
STATUS_FILE.write_text(json.dumps({
    "status": "starting",
    "epoch": 0,
    "total_epochs": EPOCHS
}))

# =======================================
# 1️⃣ Load and Preprocess Data
# =======================================
train_file = "C:/Users/AKSHATA/Downloads/IDS-main/IDS-main/intrusense/nsl-kdd/KDDTrain+.csv"

X_train, y_train, scaler, label_encoder, training_columns = load_and_preprocess(
    train_file, training=True, has_header=True
)

num_classes = len(label_encoder.classes_)
print(f"Loaded training data: {X_train.shape[0]} samples | {num_classes} classes")

# =======================================
# 2️⃣ Reshape for BiLSTM
# =======================================
X_train = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])
input_shape = (X_train.shape[1], X_train.shape[2])

# =======================================
# 3️⃣ Build Model
# =======================================
model = build_bilstm(input_shape, num_classes)

# =======================================
# 4️⃣ Class Weights
# =======================================
class_weights = compute_class_weight(
    class_weight="balanced",
    classes=np.unique(y_train),
    y=y_train
)
class_weights = dict(enumerate(class_weights))

# =======================================
# 5️⃣ Train / Validation Split
# =======================================
sss = StratifiedShuffleSplit(n_splits=1, test_size=0.1, random_state=42)
train_idx, val_idx = next(sss.split(X_train, y_train))

# =======================================
# 6️⃣ Streamlit Callback (CRITICAL FIX)
# =======================================
class StreamlitCallback(Callback):

    def on_epoch_begin(self, epoch, logs=None):
        STATUS_FILE.write_text(json.dumps({
            "status": "running",
            "epoch": epoch + 1,
            "total_epochs": EPOCHS
        }))

    def on_train_end(self, logs=None):
        STATUS_FILE.write_text(json.dumps({
            "status": "completed",
            "epoch": EPOCHS,
            "total_epochs": EPOCHS
        }))

# =======================================
# 7️⃣ TRAIN MODEL (REAL)
# =======================================
history = model.fit(
    X_train[train_idx],
    y_train[train_idx],
    validation_data=(X_train[val_idx], y_train[val_idx]),
    epochs=EPOCHS,
    batch_size=32,
    class_weight=class_weights,
    callbacks=[StreamlitCallback()],
    verbose=0   # ⛔ VERY IMPORTANT (no terminal spam)
)

# =======================================
# 8️⃣ SAVE MODEL & PREPROCESSORS
# =======================================
model.save_weights(BASE_DIR / "bilstm_ids.weights.h5")
joblib.dump(scaler, BASE_DIR / "scaler.pkl")
joblib.dump(label_encoder, BASE_DIR / "label_encoder.pkl")
joblib.dump(training_columns, BASE_DIR / "training_columns.pkl")

# =======================================
# 9️⃣ EVALUATE MODEL
# =======================================
y_pred = model.predict(X_train, verbose=0)
y_pred_classes = np.argmax(y_pred, axis=1)

accuracy = accuracy_score(y_train, y_pred_classes)
cm = confusion_matrix(y_train, y_pred_classes)
report = classification_report(
    y_train,
    y_pred_classes,
    target_names=label_encoder.classes_,
    output_dict=True,
    zero_division=0
)

# =======================================
# 🔟 SAVE RESULTS FOR STREAMLIT
# =======================================
results = {
    "train_accuracy": float(history.history["accuracy"][-1]),
    "val_accuracy": float(history.history["val_accuracy"][-1]),
    "train_loss": float(history.history["loss"][-1]),
    "val_loss": float(history.history["val_loss"][-1]),
    "final_accuracy": float(accuracy),
    "confusion_matrix": cm.tolist(),
    "classification_report": report
}

with open(RESULTS_FILE, "w") as f:
    json.dump(results, f, indent=4)
