import sys
import numpy as np
import tensorflow as tf
from tensorflow import keras

# Load the trained model
if len(sys.argv) < 2:
    print("Usage: python run_model.py <model_filename>")
    sys.exit(1)
model_filename = sys.argv[1]
try:
    model = keras.models.load_model(model_filename)

    input_hours = np.arange(0, 24 * 7).reshape(-1, 1)

    # Run predictions
    predicted_profits = model.predict(input_hours)

    # Print the results
    for hour, profit in zip(input_hours.flatten(), predicted_profits.flatten()):
        print(f"Hour {hour}: Predicted profit = {profit:.2f}")
except Exception as e:
    print(f"Error loading model: {e}")
    sys.exit(1)