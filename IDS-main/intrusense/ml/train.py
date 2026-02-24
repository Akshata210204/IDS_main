import joblib
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, LSTM, Bidirectional, Dropout
from preprocessing import load_and_preprocess
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import numpy as np

train_file = "C:/OneDrive/Desktop/NEWP/Data/nsl-kdd/KDDTrain+.csv"

# Load and preprocess
X_train, y_train, scaler, label_encoder, training_columns = load_and_preprocess(
    train_file, training=True, has_header=True
)

num_classes = len(label_encoder.classes_)

# Reshape input for BiLSTM
X_train = X_train.reshape(X_train.shape[0], 1, X_train.shape[1])

# BiLSTM model
model = Sequential()
model.add(Bidirectional(LSTM(64, return_sequences=True), input_shape=(X_train.shape[1], X_train.shape[2])))
model.add(Dropout(0.3))
model.add(Bidirectional(LSTM(32)))
model.add(Dropout(0.3))
model.add(Dense(num_classes, activation='softmax'))

# ⚠️ Use sparse_categorical_crossentropy since labels are integers
model.compile(optimizer='adam', loss='sparse_categorical_crossentropy', metrics=['accuracy'])
model.summary()

# ✅ Train model using integer labels (no to_categorical)
history = model.fit(
    X_train, y_train,
    epochs=3,
    batch_size=128,
    validation_split=0.1,
    verbose=2
)

# Save everything
model.save("bilstm_ids.keras")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")
joblib.dump(training_columns, "training_columns.pkl")

# Evaluation
y_train_pred = model.predict(X_train)
y_train_pred_classes = np.argmax(y_train_pred, axis=1)

print("\n=== Training Evaluation Metrics ===")
print("✅ Accuracy:", accuracy_score(y_train, y_train_pred_classes))
print("✅ Confusion Matrix:\n", confusion_matrix(y_train, y_train_pred_classes))
print("✅ Classification Report:\n", classification_report(y_train, y_train_pred_classes, target_names=label_encoder.classes_))
