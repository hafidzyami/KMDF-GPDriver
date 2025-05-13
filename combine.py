import pandas as pd
import glob

# Step 1: Ambil semua file
benign_files = glob.glob(r"C:\Users\hafid\OneDrive\Desktop\KMDF-GPDriver\dataset\benign\*.csv")
malware_files = glob.glob(r"C:\Users\hafid\OneDrive\Desktop\KMDF-GPDriver\dataset\malware\*.csv")
all_files = benign_files + malware_files

# Step 2: Gabungkan
dfs = [pd.read_csv(f) for f in all_files]
combined_df = pd.concat(dfs, ignore_index=True)

# Step 3: Definisikan prefix
prefix = r"\\device\\harddiskvolume5\\new\\ransomware_high_confidence\\avoslocker\\"

# Step 4: Normalisasi dan cek startswith (dengan 1 backslash)
combined_df['IS_MALWARE'] = combined_df['ProcessName'].astype(str).str.lower().str.strip().str.startswith(prefix).astype(int)

# Step 5: Simpan hasil
output_path = r"C:\Users\hafid\OneDrive\Desktop\KMDF-GPDriver\dataset_hafidz.csv"
combined_df.to_csv(output_path, index=False)

# Step 6: Debug output
print("✅ Jumlah baris dengan IS_MALWARE = 1:", combined_df['IS_MALWARE'].sum())
print("Contoh yang terdeteksi:")
print(combined_df[combined_df['IS_MALWARE'] == 1][['ProcessName']].head())
