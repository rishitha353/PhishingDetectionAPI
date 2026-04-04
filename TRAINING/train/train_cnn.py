import pandas as pd
import numpy as np
import tensorflow as tf
from tensorflow.keras import layers, models
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Load and preprocess data
df = pd.read_csv("dataset.csv")
df["Result"] = df["Result"].replace(-1, 0)

X = df.drop("Result", axis=1)
y = df["Result"]

# Normalize features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Reshape into 2D "image-like" format: (samples, height, width, channels)
X_reshaped = X_scaled.reshape(-1, 5, 6, 1)  # 5x6 grid, 1 channel
y_categorical = tf.keras.utils.to_categorical(y)

# Split data
X_train, X_test, y_train, y_test = train_test_split(X_reshaped, y_categorical, test_size=0.2)

# Build CNN model
model = models.Sequential([
    layers.Conv2D(32, (2, 2), activation='relu', input_shape=(5, 6, 1)),
    layers.MaxPooling2D(2, 2),
    layers.Flatten(),
    layers.Dense(64, activation='relu'),
    layers.Dense(2, activation='softmax')
])

model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])
model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=10)

# Save model
model.save("models/cnn_model.h5")
