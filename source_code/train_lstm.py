import pandas as pd
import numpy as np
import glob
import os
import joblib
from sklearn.preprocessing import LabelEncoder
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout

## --- Path configuration ---
DATA_PATH = "/home/cyber1/ips-ai/data/CICIDS2017"
MODEL_PATH = "/home/cyber1/ips-ai/src/ml/lstm_model.h5"
SCALER_PATH = "/home/cyber1/ips-ai/src/ml/scaler.pkl"
FEATURES_PATH = "/home/cyber1/ips-ai/src/ml/features.pkl"
SEQUENCE_LENGTH = 10 

# Load the same selected CICIDS2017 files used for RF training.
all_files = sorted(glob.glob(os.path.join(DATA_PATH, "*.csv")))
feature_names = joblib.load(FEATURES_PATH)

print("Loading selected CICIDS2017 files...")

df_list = []
for f in all_files[:6]:
    # Read the header and normalize column names.
    temp_head = pd.read_csv(f, nrows=0)
    # Load only the columns required by the trained feature set.
    temp_head.columns = temp_head.columns.str.strip()
    
    # Identify the columns required by the trained feature set.
    cols_to_use = [c for c in temp_head.columns if c in feature_names or c == 'Label']
    
    # Reload the dataset using only the required feature columns.
    # Normalize column names to ensure consistent matching.
    temp_df = pd.read_csv(f, usecols=lambda x: x.strip() in feature_names or x.strip() == 'Label')
    temp_df.columns = temp_df.columns.str.strip()
    
    print(
        f"Loaded file: {os.path.basename(f)} "
        f"| Records: {len(temp_df)}"
    )
    df_list.append(temp_df)

df = pd.concat(df_list, ignore_index=True)

# Data preprocessing and cleanup
df.columns = df.columns.str.strip()
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Binary label encoding: BENIGN = 0, attack = 1.
le = LabelEncoder()
y_binary = (le.fit_transform(df['Label']) != le.transform(['BENIGN'])[0]).astype(int)

# Apply the scaler generated during RF training.
scaler = joblib.load(SCALER_PATH)
# Use float32 to reduce memory consumption during training.
X_scaled = scaler.transform(df[feature_names]).astype("float32")

# Release the original DataFrame to reduce memory usage.
del df

# --- Sequence construction for many-to-one LSTM training ---
def create_sequences_fast(X, y, time_steps=SEQUENCE_LENGTH):
    """
    Convert flat samples into fixed-length temporal windows.
    Pre-allocation is used to reduce memory overhead.
    """
    num_samples = len(X) - time_steps
    # Pre-allocate memory for improved performance.
    Xs = np.zeros((num_samples, time_steps, X.shape[1]), dtype='float32')
    ys = y[time_steps:].astype('int8')
    
    for i in range(num_samples):
        Xs[i] = X[i:(i + time_steps)]
        # Report progress periodically during sequence generation.
        if i % 200000 == 0:
            print(f"Sequence generation progress: {i}/{num_samples}")
            
    return Xs, ys

print(
    f"Generating temporal sequences "
    f"(window size: {SEQUENCE_LENGTH})..."
)
X_lstm, y_lstm = create_sequences_fast(X_scaled, y_binary)

# LSTM architecture definition
model = Sequential([
   # First LSTM layer keeps the temporal sequence for the next recurrent layer.
    LSTM(64, input_shape=(SEQUENCE_LENGTH, len(feature_names)), return_sequences=True),
    Dropout(0.2),
   # Second LSTM layer summarizes the sequence into a single representation.
    LSTM(32, return_sequences=False), 
    Dropout(0.2),
    Dense(16, activation='relu'),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])

# Model training
print("Starting LSTM training...")
# Batch size selected according to the available experimental environment.
model.fit(X_lstm, y_lstm, epochs=10, batch_size=1024, validation_split=0.2)

# Save the trained model
model.save(MODEL_PATH)
print(f"Training completed. Model saved to: {MODEL_PATH}")
