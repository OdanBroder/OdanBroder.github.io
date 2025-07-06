import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

np.random.seed(42)

# Create hourly data for a week
hours = np.arange(0, 24 * 7)
profits = np.random.rand(len(hours)) * 100

# Create a DataFrame
data = pd.DataFrame({
    'hour': hours,
    'profit': profits
})

X = data['hour'].values.reshape(-1, 1)
y = data['profit'].values

# Build the model
model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(1,)),
    layers.Dense(64, activation='relu'),
    layers.Dense(1)
])

# Compile the model
model.compile(optimizer='adam', loss='mean_squared_error')

# Train the model
model.fit(X, y, epochs=100, verbose=1)

# Save the model
model.save('profits_model.h5')