import pandas as pd
import numpy as np
import glob
import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split

# --- Path configuration ---
DATA_PATH = "/home/cyber1/ips-ai/data/CICIDS2017"
MODEL_PATH = "/home/cyber1/ips-ai/src/ml/rf_model.pkl"
SCALER_PATH = "/home/cyber1/ips-ai/src/ml/scaler.pkl"
FEATURES_PATH = "/home/cyber1/ips-ai/src/ml/features.pkl"

# Official feature order. It must match FEATURE_ORDER used by the inference engine.
FEATURE_NAMES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total",
    "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
    "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
    "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
    "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
    "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
    "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
    "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
    "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
]

def load_data_optimized(path):
    all_files = glob.glob(os.path.join(path, "*.csv"))
   # The selected subset reflects the available experimental hardware.
    selected_files = all_files[:6] 
    
    df_list = []
    for f in selected_files:
        print(f"Loading and preprocessing: {f}")
       # Load and retain only the required CICIDS2017 feature columns.
        temp_df = pd.read_csv(f)
        temp_df.columns = temp_df.columns.str.strip()
        # Retain only the required feature columns.
        temp_df = temp_df[FEATURE_NAMES + ['Label']]
        temp_df.replace([np.inf, -np.inf], np.nan, inplace=True)
        temp_df.dropna(inplace=True)
      # Use float32 to reduce memory usage.
        for col in FEATURE_NAMES:
            temp_df[col] = temp_df[col].astype('float32')
        df_list.append(temp_df)
    
    return pd.concat(df_list, axis=0, ignore_index=True)

# Load and prepare the dataset.
df = load_data_optimized(DATA_PATH)
X = df[FEATURE_NAMES]
y = df['Label']

# Label encoding and feature scaling.
le = LabelEncoder()
y_bin = (le.fit_transform(y) != le.transform(['BENIGN'])[0]).astype(int)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Save the scaler and feature order for LSTM training and runtime inference.
joblib.dump(scaler, SCALER_PATH)
joblib.dump(FEATURE_NAMES, FEATURES_PATH)

# Random Forest training.
print(
    f"Training Random Forest using "
    f"{X_scaled.shape[0]} samples..."
)
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y_bin, test_size=0.2, random_state=42)

# Use all available CPU cores during training.
rf = RandomForestClassifier(n_estimators=100, max_depth=20, n_jobs=-1, verbose=1)
rf.fit(X_train, y_train)

# Save the trained model.
joblib.dump(rf, MODEL_PATH)
print(f"Model saved to: {MODEL_PATH}")
print(f"Test accuracy: {rf.score(X_test, y_test):.4f}")
