import numpy as np
import re
import json

def ensure_str(val):
    if isinstance(val, bytes): return val.decode("utf-8", errors="ignore")
    elif hasattr(val, "item"): return str(val.item())
    return str(val)

def get_base_name(filename):
    filename = ensure_str(filename)
    match = re.search(r"([a-fA-F0-9]{32,64})", filename)
    if match: return match.group(1)
    return filename.split(".exe")[0] + ".exe"

def extract_json_if_needed(data):
    if hasattr(data, 'tolist'): data = data.tolist()
    if isinstance(data, str):
        try: return json.loads(data)
        except: return []
    return data if data is not None else []

sys_data = np.load('datasets/syscalls/obfu_syscall.npz', allow_pickle=True)
api_data = np.load('datasets/APIs/obfu_full.npz', allow_pickle=True)

sys_names = sys_data['name']
sys_counts = sys_data['trace_count']

api_names = api_data['name']
apis = api_data['api_cuckoo'] if 'api_cuckoo' in api_data.files else api_data['api']

sys_map = {}
for name, tc in zip(sys_names, sys_counts):
    b = get_base_name(name)
    sys_map[b] = int(tc)

api_map = {}
for name, a in zip(api_names, apis):
    b = get_base_name(name)
    api_map[b] = extract_json_if_needed(a)

dead = 0
not_in_api = 0
for b, tc in sys_map.items():
    if b not in api_map:
        not_in_api += 1
        if tc == 0: dead += 1
    else:
        if tc == 0 and len(api_map[b]) == 0:
            dead += 1

print(f"Total Syscall Bases: {len(sys_map)}")
print(f"Total API Bases: {len(api_map)}")
print(f"Bases in Syscall but not in API: {not_in_api}")
print(f"Total Dead (trace=0 and api=0): {dead}")
