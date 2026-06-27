import os
import glob
import json
import re

def get_base_name(filename):
    if isinstance(filename, bytes):
        filename = filename.decode("utf-8", errors="ignore")
    
    # Extract the MD5/SHA1/SHA256 hash part from the filename
    match = re.search(r"([a-fA-F0-9]{32,64})", filename)
    if match:
        return match.group(1)
    
    if filename.lower().endswith('.exe'):
        return filename[:-4] + ".exe"
    return filename

def get_file_size(file_path):
    size = 0
    try:
        with open(file_path, "rb") as bf:
            head = bf.read(200)
            if b"git-lfs" in head:
                for line in head.decode('utf-8', errors='ignore').split('\n'):
                    if line.startswith("size "):
                        size = int(line.split(" ")[1])
                        break
            else:
                size = os.path.getsize(file_path)
    except Exception as e:
        pass
    return size

def get_files_in_dir(directory):
    files = []
    for root, _, filenames in os.walk(directory):
        for f in filenames:
            if f.endswith('.zip') or f.endswith('.npz'):
                continue
            files.append(os.path.join(root, f))
    return files

def main():
    original_dir = "datasets/Test"
    adversarial_dirs = ["datasets/Malgpt", "datasets/GAMMA"]

    print(f"[*] Loading original files from {original_dir}...")
    original_files = get_files_in_dir(original_dir)
    
    original_map = {}
    for path in original_files:
        basename = os.path.basename(path)
        base = get_base_name(basename)
        original_map[base] = path

    print(f"    Loaded {len(original_map)} original files.")

    report = {}

    for adv_dir in adversarial_dirs:
        dataset_name = os.path.basename(adv_dir)
        print(f"\n[*] Processing adversarial dataset: {dataset_name}")
        
        adv_files = get_files_in_dir(adv_dir)
        
        original_sizes = []
        adv_sizes = []
        overheads = []
        
        detailed_files = []
        
        for path in adv_files:
            basename = os.path.basename(path)
            base = get_base_name(basename)
            
            if base in original_map:
                ori_path = original_map[base]
                ori_size = get_file_size(ori_path)
                adv_size = get_file_size(path)
                
                if ori_size > 0 and adv_size > 0:
                    original_sizes.append(ori_size)
                    adv_sizes.append(adv_size)
                    overhead = (adv_size - ori_size) / ori_size * 100
                    overheads.append(overhead)
                    
                    detailed_files.append({
                        "filename": basename,
                        "ori_size_bytes": ori_size,
                        "adv_size_bytes": adv_size,
                        "overhead_percent": overhead
                    })
            else:
                # Could not find original mapping
                pass
        
        avg_ori_size = sum(original_sizes) / len(original_sizes) if original_sizes else 0
        avg_adv_size = sum(adv_sizes) / len(adv_sizes) if adv_sizes else 0
        avg_overhead = sum(overheads) / len(overheads) if overheads else 0
        
        print(f"    Total matched files: {len(original_sizes)}")
        print(f"    Size (ori/avg) (KB): {avg_ori_size/1024:.2f} / {avg_adv_size/1024:.2f}")
        print(f"    % Avg Overhead: {avg_overhead:.2f}%")
        
        report[dataset_name] = {
            "matched_files_count": len(original_sizes),
            "avg_ori_size_kb": avg_ori_size / 1024,
            "avg_adv_size_kb": avg_adv_size / 1024,
            "avg_overhead_percent": avg_overhead,
            "files": detailed_files
        }
        
    report_path = "dataset_size_overhead_report.json"
    with open(report_path, "w") as f:
        json.dump(report, f, indent=4)
        
    print(f"\n[+] Saved report to {report_path}")

if __name__ == '__main__':
    main()
