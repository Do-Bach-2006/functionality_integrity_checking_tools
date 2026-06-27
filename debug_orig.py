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

sys_data = np.load('datasets/syscalls/Test_syscall.npz', allow_pickle=True)
api_data = np.load('datasets/APIs/Test_full.npz', allow_pickle=True)

sys_names = sys_data['name']
sys_counts = sys_data['trace_count']
api_names = api_data['name']
apis = api_data['api_cuckoo'] if 'api_cuckoo' in api_data.files else api_data['api']

orig_map = {}
for name, tc in zip(sys_names, sys_counts):
    orig_map[get_base_name(name)] = {"tc": int(tc), "api": []}

for name, a in zip(api_names, apis):
    b = get_base_name(name)
    if b in orig_map:
        orig_map[b]["api"] = extract_json_if_needed(a)

dead = 0
for b, info in orig_map.items():
    if info["tc"] == 0 and len(info["api"]) == 0:
        dead += 1

print(f"Total Orig Bases: {len(orig_map)}")
print(f"Total Orig Dead: {dead}")

# Now, how many of those dead origs are present in obfu?
obfu_sys_data = np.load('datasets/syscalls/obfu_syscall.npz', allow_pickle=True)
obfu_names = [get_base_name(n) for n in obfu_sys_data['name']]

dead_in_obfu = sum(1 for n in obfu_names if n in orig_map and orig_map[n]["tc"] == 0 and len(orig_map[n]["api"]) == 0)

print(f"Total Orig Dead in Obfu: {dead_in_obfu}")
print(f"Total Obfu matching orig: {sum(1 for n in obfu_names if n in orig_map)}")

