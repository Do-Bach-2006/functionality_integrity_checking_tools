# Server Migration & Execution Guide

This guide provides step-by-step instructions on how to migrate the `integrity_functionality_comparison` workflow to your remote server and execute the memory-heavy 3-Layer Evaluator.

## 1. Prerequisites
Ensure your server has Python 3, `pip`, and a C++ compiler (`g++`) installed. For Debian/Ubuntu-based servers, you can install them via:
```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip python3-dev g++ build-essential
```

## 2. Retrieve the Codebase
Clone your GitHub repository onto the server:
```bash
git clone <YOUR_GITHUB_REPO_URL>
cd integrity_functionality_comparison
```

## 3. Setup the Datasets
You mentioned transferring the `.npz` datasets via Google Drive. Once you download them to your server, place them exactly in these directories:

```text
integrity_functionality_comparison/
├── datasets/
│   ├── APIs/
│   │   ├── Test_full.npz
│   │   ├── gamma_full.npz
│   │   ├── MAB-mal_full.npz
│   │   └── ... (all other _full.npz files)
│   └── syscalls/
│       ├── Test_syscall.npz
│       ├── gamma_syscall.npz
│       ├── mab_syscall.npz
│       └── ... (all other _syscall.npz files)
```
*Note: Ensure the prefixes of the datasets in `APIs/` and `syscalls/` match (e.g., `gamma_full.npz` and `gamma_syscall.npz`).*

## 4. Setup the Environment
Create an isolated Python virtual environment to prevent package conflicts, and install the required heavy dependencies (like `z3` and `triton`):
```bash
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

## 5. Compile the C++ `fast_sw` Module
Layer 3 relies on the heavily optimized C++ Smith-Waterman implementation. You **must** compile it on the new server so it matches the server's OS architecture.

Run this compilation command from the root of the project (while your `venv` is activated):
```bash
g++ -O3 -Wall -shared -std=c++17 -fPIC $(python3 -m pybind11 --includes) examples/smith-wanderman.cpp -o fast_sw$(python3-config --extension-suffix)
```
*This will generate a `fast_sw.so` (or similar) file in your root directory. The Python script will automatically detect and import it.*

## 6. Run the Evaluator
Since the script will process over 8,000 samples and utilize Triton/Z3, it will take several hours. Run it in the background using `nohup` so it doesn't terminate if your SSH connection drops:

```bash
nohup python full_functionality_evaluator.py > evaluator_results.log 2>&1 &
```

## 7. Monitor and Retrieve Results
You can safely disconnect from your server. To check on the real-time progress whenever you reconnect, run:
```bash
tail -f evaluator_results.log
```

When the script finishes, it will produce two files:
1. `comprehensive_summary.json` (The high-level metrics for your dataset percentages)
2. `comprehensive_detailed_reports.json` (The file-by-file breakdown of functionality scores)

You can then `scp` or download these JSON files back to your local machine for analysis!
