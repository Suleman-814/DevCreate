import pandas as pd
import numpy as np
import glob
import os
from pathlib import Path

# Your required features
FEATURES = ["packets", "bytes", "duration", "pps", "bps", "mean_iat", "var_iat", "syn_ratio", "ack_ratio", "payload_bytes"]

def process_chunk(chunk):
    """Process a chunk of the dataset."""
    try:
        # Map available features
        data = {}
        
        # Total packets
        if ' Fwd Packet Length Max' in chunk.columns:
            data["packets"] = chunk[' Fwd Packet Length Max'].fillna(0)
        else:
            data["packets"] = chunk.get("Total Fwd Packets", 0) + chunk.get("Total Backward Packets", 0)
        
        # Total bytes
        if ' Flow Bytes/s' in chunk.columns:
            data["bytes"] = chunk[' Flow Bytes/s'].fillna(0)
        else:
            data["bytes"] = chunk.get("Total Length of Fwd Packets", 0) + chunk.get("Total Length of Bwd Packets", 0)
        
        # Duration
        if ' Flow Duration' in chunk.columns:
            data["duration"] = chunk[' Flow Duration'].fillna(0)
        else:
            data["duration"] = chunk.get("Flow Duration", 1)
        
        # Calculate rates
        data["pps"] = data["packets"] / np.maximum(data["duration"], 1e-6)
        data["bps"] = data["bytes"] / np.maximum(data["duration"], 1e-6)
        
        # IAT features
        if ' Flow IAT Mean' in chunk.columns:
            data["mean_iat"] = chunk[' Flow IAT Mean'].fillna(0)
        else:
            data["mean_iat"] = chunk.get("Flow IAT Mean", 0)
            
        if ' Flow IAT Std' in chunk.columns:
            data["var_iat"] = chunk[' Flow IAT Std'].fillna(0)
        else:
            data["var_iat"] = chunk.get("Flow IAT Std", 0)
        
        # Flag ratios
        total_packets = np.maximum(data["packets"], 1)
        if ' SYN Flag Count' in chunk.columns:
            data["syn_ratio"] = chunk[' SYN Flag Count'].fillna(0) / total_packets
        else:
            data["syn_ratio"] = chunk.get("SYN Flag Count", 0) / total_packets
            
        if ' ACK Flag Count' in chunk.columns:
            data["ack_ratio"] = chunk[' ACK Flag Count'].fillna(0) / total_packets
        else:
            data["ack_ratio"] = chunk.get("ACK Flag Count", 0) / total_packets
        
        # Payload bytes
        if ' Fwd Packet Length Mean' in chunk.columns:
            data["payload_bytes"] = chunk[' Fwd Packet Length Mean'].fillna(0)
        else:
            data["payload_bytes"] = chunk.get("Total Length of Fwd Packets", 0)
        
        # Add label (normal vs attack)
        if ' Label' in chunk.columns:
            data["label"] = (chunk[' Label'] != "BENIGN").astype(int)
        else:
            data["label"] = (chunk["Label"] != "BENIGN").astype(int)
        
        return pd.DataFrame(data)
    
    except Exception as e:
        print(f"Error processing chunk: {str(e)}")
        return None

def preprocess_dataset(input_dir, output_file):
    """Preprocess the ISCX dataset files."""
    # Get all ISCX CSV files in the input directory
    all_files = glob.glob(os.path.join(input_dir, "*ISCX.csv"))
    
    if not all_files:
        print("No ISCX dataset files found!")
        return
    
    processed_data = []
    total_rows = 0
    
    for filename in all_files:
        print(f"\nProcessing {filename}...")
        try:
            # Read first row to get column names
            df_sample = pd.read_csv(filename, nrows=1)
            print(f"Columns found: {df_sample.columns.tolist()}")
            
            # Process file in chunks
            chunk_size = 10000
            chunks_processed = 0
            
            for chunk in pd.read_csv(filename, chunksize=chunk_size):
                df = process_chunk(chunk)
                if df is not None:
                    processed_data.append(df)
                    chunks_processed += 1
                    total_rows += len(df)
                    print(f"Processed chunk {chunks_processed} ({total_rows} total rows)")
                    
        except Exception as e:
            print(f"Error processing file {filename}: {str(e)}")
            continue
    
    if processed_data:
        print("\nCombining processed data...")
        final_df = pd.concat(processed_data, ignore_index=True)
        
        # Remove infinities and NaN
        final_df = final_df.replace([np.inf, -np.inf], np.nan)
        final_df = final_df.dropna()
        
        # Save to file
        final_df.to_csv(output_file, index=False)
        print(f"Processed data saved to {output_file}")
        print(f"Final dataset shape: {final_df.shape}")
    else:
        print("No data was processed successfully")

if __name__ == "__main__":
    input_dir = "data"
    output_file = "data/processed_dataset.csv"
    preprocess_dataset(input_dir, output_file)
