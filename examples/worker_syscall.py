import os
import time
import requests
import json
import sys
import io
import pyzipper
from core.redis_orchestrator import RedisOrchestrator
from utils.cleaner import hard_clean_cape_server

class SyscallWorker:
    def __init__(self):
        self.orchestrator = RedisOrchestrator()
        self.headers = {"Authorization": "Token 5f42b8083e6a6e95bd32ff2037ae323252dcb8ff"}

    def submit_to_cape(self, host, file_path):
        url = f"{host}/apiv2/tasks/create/file/"
        options_str = "sniffer=0,procmemdump=0,dumpprocess=0,dump_r0=0,curtain=0,sysmon=0"
        data_params = {
            "timeout": 60,
            "platform": "windows",
            "machine": "win10",
            "package": "binsim",
            "enforce_timeout": False,
            "priority": 1,
            "options": options_str,
        }

        while True:
            try:
                with open(file_path, "rb") as f:
                    files = {"file": (os.path.basename(file_path), f)}
                    r = requests.post(
                        url, headers=self.headers, files=files, data=data_params, timeout=30
                    )
                    if r.status_code == 200:
                        task_ids = r.json().get("data", {}).get("task_ids", [])
                        if task_ids:
                            return task_ids[0]
                    elif r.status_code >= 500:
                        time.sleep(15)
                        continue
                    else:
                        print(f" [!] Error Submitting to {host}: {r.status_code} {r.text}")
                        return None
            except Exception as e:
                time.sleep(10)

    def wait_for_report(self, host, task_id):
        status_url = f"{host}/apiv2/tasks/view/{task_id}/"
        report_url = f"{host}/apiv2/tasks/get/report/{task_id}/json/"
        print(f"[*] Waiting on Task {task_id} at {host}...", end="", flush=True)

        for i in range(240):
            try:
                r = requests.get(status_url, headers=self.headers, timeout=10)
                if r.status_code == 200:
                    status = r.json().get("data", {}).get("status")
                    if status in ["reported", "failed_analysis", "timeout", "completed"]:
                        rep_req = requests.get(report_url, headers=self.headers, timeout=60)
                        if rep_req.status_code == 200:
                            report_data = rep_req.json()
                            if report_data.get("error") is True:
                                time.sleep(5)
                                continue
                            print(" OK!")
                            return report_data
                time.sleep(10)
            except Exception:
                pass
        return {}

    def find_binsim_sha256(self, obj):
        if isinstance(obj, dict):
            name = obj.get("name") or obj.get("filepath") or obj.get("path")
            if name and "binsim_trace.json" in str(name):
                if "sha256" in obj:
                    return obj["sha256"]
            for v in obj.values():
                result = self.find_binsim_sha256(v)
                if result:
                    return result
        elif isinstance(obj, list):
            for item in obj:
                result = self.find_binsim_sha256(item)
                if result:
                    return result
        return None

    def extract_binsim_trace(self, host, report, task_id):
        assembly_slices = []
        sha256 = self.find_binsim_sha256(report)
        if not sha256:
            return assembly_slices

        dl_url = f"{host}/apiv2/tasks/get/dropped/{task_id}/"
        try:
            r = requests.get(dl_url, headers=self.headers, timeout=60)
            if r.status_code == 200:
                file_bytes = io.BytesIO(r.content)
                extracted_text = None
                try:
                    with pyzipper.AESZipFile(file_bytes) as z:
                        z.setpassword(b"infected")
                        for name in z.namelist():
                            if name.endswith(".json") and (
                                sha256 in name or "binsim_trace" in name
                            ):
                                extracted_text = z.read(name).decode(
                                    "utf-8", errors="ignore"
                                )
                                break
                except Exception as e:
                    print(f" [!] Zip Extraction Error: {e}")

                if extracted_text:
                    for line in extracted_text.strip().split("\n"):
                        if line:
                            try:
                                assembly_slices.append(json.loads(line))
                            except Exception:
                                pass
        except Exception as e:
            print(f" [!] Dropped Download Error: {e}")
        return assembly_slices

    def check_is_running(self, report, trace_count):
        if trace_count > 0:
            return True
        try:
            for proc in report.get("behavior", {}).get("processes", []):
                if len(proc.get("calls", [])) > 0:
                    return True
        except:
            pass
        return False

    def delete_task(self, host, task_id):
        url = f"{host}/apiv2/tasks/delete/{task_id}/"
        try:
            requests.get(url, headers=self.headers, timeout=10)
        except:
            pass

    def run(self):
        print("[*] Syscall Worker listening to 'queue:syscall'...")
        while True:
            try:
                # Use a blocking pop from the orchestrator
                _, msg = self.orchestrator.r.brpop('queue:syscall')
                payload = json.loads(msg)
                
                target_file_name = payload["target_file_name"]
                is_original = payload["is_original"]
                
                # Assuming the orchestrator places the file in a shared directory
                file_path = f"/tmp/{target_file_name}" 
                
                print(f"[*] Syscall Worker processing {target_file_name}")
                
                if not os.path.exists(file_path):
                    print(f" [!] File not found: {file_path}")
                    # In a real environment, the file must be present before dispatch.
                    # We continue but decrement barrier so system doesn't hang forever.
                    self.orchestrator.decrement_barrier(target_file_name, is_original)
                    continue

                # 1. Get Node
                node = self.orchestrator.get_next_cape_node()
                host = node["host"]
                
                # 2. Submit to CAPE (Package: binsim)
                tid = self.submit_to_cape(host, file_path)
                if not tid:
                    print(f" [!] Failed to submit {target_file_name}")
                    self.orchestrator.decrement_barrier(target_file_name, is_original)
                    continue

                # 3. Wait for Report
                report = self.wait_for_report(host, tid)
                
                # 4. Extract Binsim Trace directly from RAM Zip
                frida_assembly = self.extract_binsim_trace(host, report, tid)
                trace_count = len(frida_assembly)
                is_running = self.check_is_running(report, trace_count)
                
                print(f"   [METRICS] Is_Running: {is_running} | Trace Blocks: {trace_count}")
                
                # 5. Delete Task from CAPE
                self.delete_task(host, tid)
                
                # 6. Clean server
                hard_clean_cape_server(node["ssh_host"], node["ssh_user"], node["ssh_pass"])
                
                # 7. Save to Redis (Storing as JSON string to comply with Redis schema)
                key = f"baseline:{target_file_name}:data" if is_original else f"episode:{target_file_name}:data"
                self.orchestrator.r.hset(key, "is_running", json.dumps(is_running))
                self.orchestrator.r.hset(key, "trace_count", trace_count)
                self.orchestrator.r.hset(key, "trace_data", json.dumps(frida_assembly))
                
                # 8. Decrement Barrier
                self.orchestrator.decrement_barrier(target_file_name, is_original)
                
            except Exception as e:
                print(f" [!] Critical Worker Error: {e}")
                time.sleep(5)

if __name__ == "__main__":
    worker = SyscallWorker()
    worker.run()
