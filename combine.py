import os
import pandas as pd
import glob

def main():
    # Path ke direktori dataset
    benign_dir = r"C:\Users\hafid\OneDrive\Desktop\KMDF-GPDriver\dataset\benign"
    malware_dir = r"C:\Users\hafid\OneDrive\Desktop\KMDF-GPDriver\dataset\malware"
    output_file = r"C:\Users\hafid\OneDrive\Desktop\KMDF-GPDriver\datasetcombine.csv"
    
    # Mendapatkan semua file CSV di kedua direktori
    benign_files = glob.glob(os.path.join(benign_dir, "*.csv"))
    malware_files = glob.glob(os.path.join(malware_dir, "*.csv"))
    
    print(f"Ditemukan {len(benign_files)} file CSV benign")
    print(f"Ditemukan {len(malware_files)} file CSV malware")
    
    # Daftar untuk menyimpan semua dataframe
    all_dfs = []
    
    # Membaca dan memproses file benign
    for file in benign_files:
        try:
            df = pd.read_csv(file)
            # Tambahkan kolom IS_MALWARE dengan nilai 0
            df['IS_MALWARE'] = 0
            all_dfs.append(df)
            print(f"Berhasil menambahkan file benign: {os.path.basename(file)}")
        except Exception as e:
            print(f"Error pada file {file}: {str(e)}")
    
    # Membaca dan memproses file malware
    for file in malware_files:
        try:
            df = pd.read_csv(file)
            # Tambahkan kolom IS_MALWARE berdasarkan kondisi
            df['IS_MALWARE'] = df['ProcessName'].apply(
                lambda x: 1 if isinstance(x, str) and x.startswith('\\Device\\HarddiskVolume5\\new\\ransomware_high_confidence') else 0
            )
            all_dfs.append(df)
            print(f"Berhasil menambahkan file malware: {os.path.basename(file)}")
        except Exception as e:
            print(f"Error pada file {file}: {str(e)}")
    
    if not all_dfs:
        print("Tidak ada data yang dapat digabungkan.")
        return
    
    # Gabungkan semua dataframe
    combined_df = pd.concat(all_dfs, ignore_index=True)
    
    # Simpan ke file CSV
    combined_df.to_csv(output_file, index=False)
    
    print(f"\nBerhasil menggabungkan {len(all_dfs)} file CSV")
    print(f"Total {len(combined_df)} baris data")
    print(f"File hasil disimpan di: {output_file}")

if __name__ == "__main__":
    main()