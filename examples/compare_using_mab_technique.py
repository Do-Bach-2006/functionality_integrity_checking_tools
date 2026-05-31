# -*- coding: utf-8 -*-
import os
import time
import requests
import numpy as np
import json
import glob
import sys
import codecs
import paramiko  # [NEW] Dùng để SSH vào CAPE Server

# --- CẤU HÌNH CAPEv2 ---
CAPE_HOST = "http://192.168.2.122:8000"
API_TOKEN = "5f42b8083e6a6e95bd32ff2037ae323252dcb8ff"
HEADERS = {"Authorization": "Token {0}".format(API_TOKEN)}

# --- CẤU HÌNH SSH (HARD CLEANUP) ---
SSH_HOST = "192.168.2.122"
SSH_USER = "cape"      # Đổi thành username trên server CAPE của bạn
SSH_PASS = "cape"      # Đổi thành mật khẩu (hoặc cấu hình key-based authentication)
CAPE_DIR = "/opt/CAPEv2" # Đường dẫn cài đặt CAPE

# Cấu hình thư mục
ROOT_DIR = "gamma_adv"  # Thư mục chứa mẫu malware
FINAL_OUTPUT_FILE = "gamma.npz"

# Cấu hình Workspace (Nơi chứa file tạm và log)
WORKSPACE_DIR = "gamma_progress"
PROGRESS_LOG = os.path.join(WORKSPACE_DIR, "processed_log.json")
BATCH_SIZE = 3

# ==============================================================================
# 1. CÁC HÀM HỖ TRỢ BATCH & LOGGING
# ==============================================================================

def ensure_workspace():
    if not os.path.exists(WORKSPACE_DIR):
        os.makedirs(WORKSPACE_DIR)

def load_processed_set():
    if os.path.exists(PROGRESS_LOG):
        try:
            with codecs.open(PROGRESS_LOG, "r", "utf-8") as f:
                return set(json.load(f))
        except:
            return set()
    return set()

def save_batch_npz(data_dict):
    if not data_dict["name"]:
        return

    count = len(data_dict["name"])
    timestamp = int(time.time())

    filename = "batch_{0}_{1}_samples.npz".format(timestamp, count)
    filepath = os.path.join(WORKSPACE_DIR, filename)

    print "\n [SAVE] Đang lưu {0} file vào đĩa -> {1}".format(count, filename)

    try:
        np.savez_compressed(
            filepath,
            name=np.array(data_dict["name"]),
            label=np.array(data_dict["label"]),
            api=np.array(data_dict["api"], dtype=object),
            pe_imports=np.array(data_dict["pe_imports"], dtype=object),
            pe_sections=np.array(data_dict["pe_sections"], dtype=object),
            signatures=np.array(data_dict["signatures"], dtype=object),
        )
    except Exception, e:
        print " [!] Lỗi KHI LƯU FILE NPZ: {0}".format(e)
        return

    current_log = []
    if os.path.exists(PROGRESS_LOG):
        try:
            with codecs.open(PROGRESS_LOG, "r", "utf-8") as f:
                current_log = json.load(f)
        except:
            pass

    current_log.extend(data_dict["name"])

    try:
        with codecs.open(PROGRESS_LOG, "w", "utf-8") as f:
            json.dump(current_log, f, indent=2)
        print " [LOG] Đã cập nhật file processed_log.json."
    except Exception, e:
        print " [!] Lỗi cập nhật JSON Log: {0}".format(e)

def get_length(item):
    try:
        if item is None:
            return 0
        return len(item)
    except:
        return 0

def merge_all_npz():
    print "\n--- BẮT ĐẦU QUÁ TRÌNH GỘP FILE ---"
    
    search_pattern = os.path.join(WORKSPACE_DIR, "*.npz")
    npz_files = glob.glob(search_pattern)
    
    if not npz_files:
        print " [!] Không tìm thấy file .npz nào trong thư mục '{0}'".format(WORKSPACE_DIR)
        return

    print " [*] Tìm thấy {0} file batch .npz. Đang tiến hành đọc và thống kê...".format(len(npz_files))

    all_names = []
    all_labels = []
    all_apis = []
    all_imports = []
    all_sections = []
    all_signatures = []

    total_samples = 0
    zero_api_count = 0
    all_zero_count = 0
    failed_npz_count = 0

    for f in npz_files:
        try:
            d = np.load(f, allow_pickle=True)
            
            names = d["name"].tolist() if hasattr(d["name"], "tolist") else list(d["name"])
            labels = d["label"].tolist() if hasattr(d["label"], "tolist") else list(d["label"])
            apis = d["api"].tolist() if hasattr(d["api"], "tolist") else list(d["api"])
            imports = d["pe_imports"].tolist() if hasattr(d["pe_imports"], "tolist") else list(d["pe_imports"])
            sections = d["pe_sections"].tolist() if hasattr(d["pe_sections"], "tolist") else list(d["pe_sections"])
            signatures = d["signatures"].tolist() if hasattr(d["signatures"], "tolist") else list(d["signatures"])
            
            batch_size = len(names)
            
            for i in range(batch_size):
                total_samples += 1
                
                api_len = get_length(apis[i])
                imp_len = get_length(imports[i])
                sec_len = get_length(sections[i])
                sig_len = get_length(signatures[i])
                
                if api_len == 0:
                    zero_api_count += 1
                    
                if api_len == 0 and imp_len == 0 and sec_len == 0 and sig_len == 0:
                    all_zero_count += 1

            all_names.extend(names)
            all_labels.extend(labels)
            all_apis.extend(apis)
            all_imports.extend(imports)
            all_sections.extend(sections)
            all_signatures.extend(signatures)
            
        except Exception, e:
            print " [!] Lỗi khi đọc file {0}: {1}".format(f, e)
            failed_npz_count += 1

    print "\n--- ĐANG GỘP VÀ LƯU DỮ LIỆU ---"
    try:
        np.savez_compressed(
            FINAL_OUTPUT_FILE,
            name=np.array(all_names),
            label=np.array(all_labels),
            api=np.array(all_apis, dtype=object),
            pe_imports=np.array(all_imports, dtype=object),
            pe_sections=np.array(all_sections, dtype=object),
            signatures=np.array(all_signatures, dtype=object)
        )
        print " [OK] Đã lưu thành công file tổng: {0}".format(FINAL_OUTPUT_FILE)
    except Exception, e:
        print " [!] Lỗi khi lưu file tổng: {0}".format(e)
        return

    print "\n================ BÁO CÁO THỐNG KÊ ================"
    print " - Tổng số batch (.npz) đã gom   : {0}".format(len(npz_files) - failed_npz_count)
    if failed_npz_count > 0:
        print " - Số batch (.npz) lỗi format    : {0}".format(failed_npz_count)
    print " - TỔNG SỐ MẪU ĐÃ TRÍCH XUẤT     : {0}".format(total_samples)
    print " - Số mẫu có 0 API string        : {0}".format(zero_api_count)
    print " - Số mẫu 'chết' (0 API, Imp, Sec, Sig): {0}".format(all_zero_count)
    print "=================================================="

# ==============================================================================
# 2. CÁC HÀM TƯƠNG TÁC CAPE VÀ SSH
# ==============================================================================

def hard_clean_cape_server():
    """
    Kết nối SSH vào CAPE Server, xóa database MongoDB, 
    xóa thư mục storage và khởi động lại dịch vụ.
    """
    sys.stdout.write("\n [SSH] Đang thực hiện Hard Cleanup trên CAPE Server...\n")
    sys.stdout.flush()
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(SSH_HOST, username=SSH_USER, password=SSH_PASS, timeout=10)

        # Danh sách các lệnh Bash dọn rác triệt để
        # LƯU Ý: Đảm bảo đường dẫn CAPE_DIR là chính xác
        commands = [
            # Xóa Database CAPE trong MongoDB (mongosh hoặc mongo tùy version)
            'echo "db.dropDatabase()" | mongo cape || echo "db.dropDatabase()" | mongosh cape',
            # Xóa toàn bộ file phân tích và binary rác
            'echo "{0}" | sudo -S rm -rf {1}/storage/analyses/*'.format(SSH_PASS, CAPE_DIR),
            'echo "{0}" | sudo -S rm -rf {1}/storage/binaries/*'.format(SSH_PASS, CAPE_DIR),
            # Restart các dịch vụ
            'echo "{0}" | sudo -S systemctl restart cape.service'.format(SSH_PASS),
            'echo "{0}" | sudo -S systemctl restart cape-processor.service'.format(SSH_PASS),
            'echo "{0}" | sudo -S systemctl restart cape-web.service'.format(SSH_PASS)
        ]

        for cmd in commands:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            stdout.channel.recv_exit_status() # Đợi lệnh chạy xong

        print " [SSH] Cleanup hoàn tất. Đợi 10s để CAPE khởi động lại..."
        ssh.close()
        time.sleep(10) # Đợi dịch vụ sẵn sàng
    except Exception, e:
        print " [!] Lỗi khi SSH Hard Clean: {0}".format(e)


def submit_to_cape(file_path):
    url = "{0}/apiv2/tasks/create/file/".format(CAPE_HOST)
    options_str = "sniffer=0,procmemdump=0,dumpprocess=0,dump_r0=0,curtain=0,sysmon=0"
    data_params = {
        "timeout": 300,
        "platform": "windows",
        "enforce_timeout": False,
        "options": options_str,
    }

    while True:
        try:
            with open(file_path, "rb") as f:
                files = {"file": (os.path.basename(file_path), f)}
                r = requests.post(
                    url, headers=HEADERS, files=files, data=data_params, timeout=30
                )

                if r.status_code == 200:
                    task_ids = r.json().get("data", {}).get("task_ids", [])
                    if task_ids:
                        return task_ids[0]
                elif r.status_code >= 500:
                    sys.stdout.write(" [!] Server quá tải (500). Đợi 15s...\r")
                    sys.stdout.flush()
                    time.sleep(15)
                    continue
                else:
                    print " [!] Lỗi Submit (HTTP {0}): {1}".format(r.status_code, r.text)
                    return None
        except requests.exceptions.RequestException:
            sys.stdout.write(" [!] Mất kết nối. Đợi 10s...\r")
            sys.stdout.flush()
            time.sleep(10)
        except Exception, e:
            print " [!] Lỗi lạ: {0}".format(e)
            return None

def wait_for_report(task_id):
    status_url = "{0}/apiv2/tasks/view/{1}/".format(CAPE_HOST, task_id)
    report_url = "{0}/apiv2/tasks/get/report/{1}/json/".format(CAPE_HOST, task_id)

    sys.stdout.write("[*] Đợi Task {0}...".format(task_id))
    sys.stdout.flush()

    for i in range(240):
        try:
            r = requests.get(status_url, headers=HEADERS, timeout=10)
            if r.status_code == 200:
                data = r.json().get("data", {})
                status = data.get("status")

                if status in ["reported", "failed_analysis", "timeout", "completed"]:
                    rep_req = requests.get(report_url, headers=HEADERS, timeout=60)
                    if rep_req.status_code == 200:
                        report_data = rep_req.json()

                        if report_data.get("error") is True:
                            time.sleep(5)
                            sys.stdout.write(" (Wait JSON gen...)")
                            sys.stdout.flush()
                            continue

                        if (
                            "target" in report_data
                            or "behavior" in report_data
                            or "static" in report_data
                        ):
                            print " OK!"
                            return report_data

            time.sleep(10)
            if i % 6 == 0:
                sys.stdout.write(".")
                sys.stdout.flush()

        except requests.exceptions.RequestException:
            sys.stdout.write("x")
            sys.stdout.flush()
            time.sleep(10)
        except Exception:
            pass

    print "\n Timeout! Thử tải lần cuối..."
    try:
        return requests.get(report_url, headers=HEADERS, timeout=60).json()
    except:
        return {}

def delete_task(task_id):
    url = "{0}/apiv2/tasks/delete/{1}/".format(CAPE_HOST, task_id)
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return True
        elif r.status_code == 404:
            return True
        return False
    except:
        return False

def extract_features_raw(report):
    features = {"api": [], "imports": [], "sections": [], "signatures": []}
    if not report:
        print " [!] Report rỗng!"
        return features

    try:
        processes = report.get("behavior", {}).get("processes", [])
        all_calls = []
        for proc in processes:
            for call in proc.get("calls", []):
                if isinstance(call, dict) and call.get("api"):
                    all_calls.append(call["api"])
        features["api"] = all_calls
    except Exception, e:
        print " [!] Lỗi API: {0}".format(e)

    try:
        target_pe = report.get("target", {}).get("file", {}).get("pe", {})
        static_pe = report.get("static", {}).get("pe", {})
        pe_node = target_pe if target_pe else static_pe

        raw_imports = pe_node.get("imports", [])
        flat_imp = []
        if isinstance(raw_imports, dict):
            for d in raw_imports.values():
                for f in d.get("imports", []):
                    if f.get("name"):
                        flat_imp.append(f["name"])
        elif isinstance(raw_imports, list):
            for d in raw_imports:
                for f in d.get("imports", []):
                    if f.get("name"):
                        flat_imp.append(f["name"])
        features["imports"] = flat_imp[:1000]

        features["sections"] = pe_node.get("sections", [])
    except Exception, e:
        print " [!] Lỗi Static: {0}".format(e)

    try:
        list_sig = report.get("signatures", [])
        for sig in list_sig:
            if "name" in sig:
                features["signatures"].append(sig["name"])
    except Exception, e:
        print " [!] Lỗi Signatures: {0}".format(e)

    return features

# ==============================================================================
# 3. MAIN LOOP (FULL OPTION)
# ==============================================================================

def main():
    ensure_workspace()

    processed_set = load_processed_set()
    print "--- Đã hoàn thành {0} file trước đó (Skip) ---".format(len(processed_set))

    current_batch = {
        "name": [],
        "label": [],
        "api": [],
        "pe_imports": [],
        "pe_sections": [],
        "signatures": [],
    }

    try:
        for root, dirs, files in os.walk(ROOT_DIR):
            for filename in files:
                if filename.startswith("."):
                    continue
                if filename in processed_set:
                    continue

                file_path = os.path.join(root, filename)
                label = os.path.basename(root)
                print "\n>>> File: {0} | Label: {1}".format(filename, label)

                start_time = time.time()

                tid = submit_to_cape(file_path)
                if not tid:
                    continue

                report = wait_for_report(tid)
                feats = extract_features_raw(report)

                duration = time.time() - start_time

                n_api = len(feats["api"])
                n_imp = len(feats["imports"])
                n_sec = len(feats["sections"])
                n_sig = len(feats["signatures"])
                print "   [RESULT] API: {0} | Import: {1} | Section: {2} | Signatures: {3}".format(n_api, n_imp, n_sec, n_sig)
                print "   [TIME]   Hoàn thành trong: {0:.2f}s".format(duration)

                current_batch["name"].append(filename)
                current_batch["label"].append(label)
                current_batch["api"].append(np.array(feats["api"]))
                current_batch["pe_imports"].append(np.array(feats["imports"]))
                current_batch["pe_sections"].append(feats["sections"])
                current_batch["signatures"].append(np.array(feats["signatures"]))

                processed_set.add(filename)

                delete_task(tid)

                print "   [BATCH]  {0}/{1}".format(len(current_batch['name']), BATCH_SIZE)

                if len(current_batch["name"]) >= BATCH_SIZE:
                    save_batch_npz(current_batch)
                    
                    # --- [NEW] GỌI HARD CLEANUP SAU KHI LƯU BATCH ---
                    hard_clean_cape_server()

                    current_batch = {
                        "name": [],
                        "label": [],
                        "api": [],
                        "pe_imports": [],
                        "pe_sections": [],
                        "signatures": [],
                    }

    except KeyboardInterrupt:
        print "\n\n [STOP] ĐANG DỪNG BỞI NGƯỜI DÙNG... (Đợi lưu file cuối)"
    except Exception, e:
        print "\n\n [CRASH] Lỗi: {0}".format(e)
    finally:
        if len(current_batch["name"]) > 0:
            print "\n [SAFETY SAVE] Lưu {0} file cuối...".format(len(current_batch['name']))
            save_batch_npz(current_batch)
            hard_clean_cape_server() # Dọn dẹp nốt lần cuối

        merge_all_npz()

if __name__ == "__main__":
    main()