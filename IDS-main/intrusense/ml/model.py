# model.py
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout, Bidirectional, LSTM, Input
from io import StringIO
import sys

def build_bilstm(input_shape, num_classes):
    model = Sequential([
        Input(shape=input_shape),
        Bidirectional(LSTM(64, return_sequences=False)),
        Dropout(0.5),
        Dense(64, activation="relu"),
        Dropout(0.3),
        Dense(num_classes, activation="softmax")
    ])

    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"]
    )
    return model


if __name__ == "__main__":
    model = build_bilstm((1, 100), 3)

    print("\nMODEL ARCHITECTURE")
    print("-" * 60)

    from io import StringIO
    stream = StringIO()
    model.summary(print_fn=lambda x: stream.write(x + "\n"))
    summary_text = stream.getvalue()

    print(summary_text)

    print("-" * 60)
    print("Model build completed successfully")

