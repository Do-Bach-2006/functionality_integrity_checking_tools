import os
import numpy as np
import re
import json

DATASETS_API_DIR = "datasets/APIs"
DATASETS_SYS_DIR = "datasets/syscalls"

def get_base_name(filename):
    if isinstance(filename, bytes):
        filename = filename.decode('utf-8', errors='ignore')
    elif hasattr(filename, 'item'):
        val = filename.item()
        if isinstance(val, bytes):
            filename = val.decode('utf-8', errors='ignore')
        else:
            filename = str(val)
    else:
        filename = str(filename)
        
    match = re.search(r'([a-fA-F0-9]{32,64})', filename)
    if match:
        return match.group(1)
    return filename.split('.exe')[0] + '.exe'

def get_features(data, key_choices, count):
    for key in key_choices:
        if key in data.files:
            val = data[key]
            return val.tolist() if hasattr(val, 'tolist') else list(val)
    return [[] for _ in range(count)]

def extract_json_if_needed(data):
    if hasattr(data, 'tolist'):
        data = data.tolist()
    if isinstance(data, str):
        try:
            return json.loads(data)
        except:
            return []
    return data if data is not None else []

def check_integrity(api_chain, trace_count):
    api_ok = len(api_chain) > 0
    sys_ok = trace_count > 2
    is_alive = api_ok or sys_ok
    return is_alive, sys_ok, api_ok

def main():
    orig_sys_path = os.path.join(DATASETS_SYS_DIR, "Test_syscall.npz")
    orig_api_path = os.path.join(DATASETS_API_DIR, "Test_full.npz")
    
    if not os.path.exists(orig_sys_path) or not os.path.exists(orig_api_path):
        print("[!] Original baseline datasets not found.")
        return
        
    print(f"[*] Loading original syscall dataset: {orig_sys_path}")
    orig_sys_data = np.load(orig_sys_path, allow_pickle=True)
    orig_sys_names = get_features(orig_sys_data, ['name'], 0)
    orig_sys_counts = get_features(orig_sys_data, ['trace_count'], len(orig_sys_names))
    orig_sys_labels = get_features(orig_sys_data, ['label'], len(orig_sys_names))
    
    print(f"[*] Loading original API dataset: {orig_api_path}")
    orig_api_data = np.load(orig_api_path, allow_pickle=True)
    orig_api_names = get_features(orig_api_data, ['name'], 0)
    orig_api_chains = get_features(orig_api_data, ['api_cuckoo', 'api'], len(orig_api_names))
    orig_api_labels = get_features(orig_api_data, ['label'], len(orig_api_names))
    
    baseline = {}
    for name, tcount, label in zip(orig_sys_names, orig_sys_counts, orig_sys_labels):
        base = get_base_name(name)
        lbl_str = label.decode('utf-8') if isinstance(label, bytes) else (str(label) if label != [] else "")
        baseline[base] = {
            "name": name,
            "label": lbl_str,
            "trace_count": int(tcount) if tcount is not None else 0,
            "api_chain": []
        }
        
    for name, api, label in zip(orig_api_names, orig_api_chains, orig_api_labels):
        base = get_base_name(name)
        lbl_str = label.decode('utf-8') if isinstance(label, bytes) else (str(label) if label != [] else "")
        if base not in baseline:
            baseline[base] = {
                "name": name,
                "label": lbl_str,
                "trace_count": 0,
                "api_chain": extract_json_if_needed(api)
            }
        else:
            baseline[base]["api_chain"] = extract_json_if_needed(api)
            baseline[base]["label"] = lbl_str
            
    total_files = 0
    alive_count = 0
    dqeaf_alive_count = 0
    api_only = 0
    sys_only = 0
    both = 0
    neither = 0
    
    for base, info in baseline.items():
        if info.get("label", "").lower() == "benign":
            continue
            
        total_files += 1
        is_alive, sys_ok, api_ok = check_integrity(info["api_chain"], info["trace_count"])
        if is_alive:
            alive_count += 1
            if api_ok and sys_ok:
                both += 1
            elif api_ok:
                api_only += 1
            elif sys_ok:
                sys_only += 1
        else:
            neither += 1
            
        if len(info["api_chain"]) > 0:
            dqeaf_alive_count += 1
            
    alive_percentage = (alive_count / total_files * 100) if total_files > 0 else 0.0
    dqeaf_alive_percentage = (dqeaf_alive_count / total_files * 100) if total_files > 0 else 0.0
    
    print("\n" + "="*45)
    print("      Original Dataset Integrity Report      ")
    print("="*45)
    print("--- Proposed Method ---")
    print(f"Total files in test dataset : {total_files}")
    print(f"Number of 'alive' files     : {alive_count}")
    print(f"Percentage of 'alive' files : {alive_percentage:.2f}%")
    print("-" * 45)
    print(f"Files with API data only    : {api_only}")
    print(f"Files with Syscall data only: {sys_only}")
    print(f"Files with both             : {both}")
    print(f"Files with neither          : {neither}")
    print("-" * 45)
    print("--- DQEAF Method ---")
    print(f"Number of 'alive' files     : {dqeaf_alive_count}")
    print(f"Percentage of 'alive' files : {dqeaf_alive_percentage:.2f}%")
    print("="*45)

if __name__ == '__main__':
    main()
