"""
Cryptography Course Project: Hash-Based File Integrity Checker (FIM)
"""

import os
import hashlib
import hmac
import json
import time
from datetime import datetime

# Supported Cryptographic Hashing Algorithms
SUPPORTED_ALGORITHMS = {
    'md5': hashlib.md5,
    'sha1': hashlib.sha1,
    'sha256': hashlib.sha256,
    'sha512': hashlib.sha512,
    'sha3_256': hashlib.sha3_256
}

def calculate_file_hash(filepath: str, algorithm: str = 'sha256', key: str = None) -> str:
    """
    Computes the cryptographic hash of a file.
    If a secret key is provided, it computes an HMAC (Hash-based Message Authentication Code).
    
    Reads files in 64KB chunks to efficiently handle large files without memory spikes.
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Choose from: {list(SUPPORTED_ALGORITHMS.keys())}")
        
    chunk_size = 65536  # 64 KB chunks
    digest_mod = SUPPORTED_ALGORITHMS[algorithm]
    
    try:
        if key:
            key_bytes = key.encode('utf-8')
            hasher = hmac.new(key_bytes, digestmod=digest_mod)
        else:
            hasher = digest_mod()
            
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError) as e:
        # Handle cases where files are deleted or locked during scanning
        return f"ERROR: {str(e)}"

def calculate_baseline_signature(files_data: dict, key: str, algorithm: str = 'sha256') -> str:
    """
    Computes a top-level HMAC signature of the entire baseline dataset.
    This acts as a second-layer cryptographic shield, preventing an attacker
    from tampering with the baseline JSON file itself without knowing the key.
    
    Canonical serialization (sorted keys) is used to ensure deterministic outputs.
    """
    if not key:
        return ""
    
    # Sort files_data by key (relative filepath) to ensure consistent ordering
    canonical_json = json.dumps(files_data, sort_keys=True)
    key_bytes = key.encode('utf-8')
    
    digest_mod = SUPPORTED_ALGORITHMS.get(algorithm, hashlib.sha256)
    signature_mac = hmac.new(key_bytes, canonical_json.encode('utf-8'), digestmod=digest_mod)
    return signature_mac.hexdigest()

def generate_baseline(directory_path: str, algorithm: str = 'sha256', key: str = None) -> dict:
    """
    Traverses the directory, computes hashes for all files, and structures the baseline metadata.
    If a key is provided, signs the baseline using an HMAC signature.
    """
    if not os.path.exists(directory_path):
        raise FileNotFoundError(f"Monitored directory not found: {directory_path}")
        
    baseline = {
        "monitored_directory": os.path.abspath(directory_path),
        "algorithm": algorithm,
        "timestamp": datetime.now().isoformat(),
        "hmac_enabled": bool(key),
        "files": {}
    }
    
    files_data = {}
    
    for root, _, filenames in os.walk(directory_path):
        for filename in filenames:
            # Skip hidden files and baseline metadata itself to avoid circular hashing
            if filename.startswith('.') or filename == 'baseline_hashes.json':
                continue
                
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, directory_path)
            
            try:
                stat = os.stat(full_path)
                file_hash = calculate_file_hash(full_path, algorithm, key)
                
                if not file_hash.startswith("ERROR:"):
                    files_data[rel_path] = {
                        "hash": file_hash,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "readable_mtime": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    }
            except Exception as e:
                # Silently skip file if it can't be read or accessed
                continue
                
    baseline["files"] = files_data
    
    if key:
        baseline["signature"] = calculate_baseline_signature(files_data, key, algorithm)
        
    return baseline

def verify_integrity(directory_path: str, baseline_data: dict, key: str = None) -> dict:
    """
    Compares the current directory state against the baseline metadata.
    1. Verifies the baseline HMAC signature if enabled (detects baseline tampering).
    2. Scans files and flags Created, Modified, and Deleted entries.
    """
    algorithm = baseline_data.get("algorithm", "sha256")
    hmac_enabled = baseline_data.get("hmac_enabled", False)
    baseline_files = baseline_data.get("files", {})
    
    # 1. Cryptographic Signature Tamper-check
    if hmac_enabled:
        if not key:
            return {
                "status": "COMPROMISED",
                "message": "Security Alert: This baseline is HMAC-signed. A secret key is required for verification!",
                "results": {"created": [], "modified": [], "deleted": []}
            }
        
        expected_signature = calculate_baseline_signature(baseline_files, key, algorithm)
        stored_signature = baseline_data.get("signature", "")
        
        # Use hmac.compare_digest to prevent timing attacks (crucial cryptographic practice!)
        if not hmac.compare_digest(expected_signature, stored_signature):
            return {
                "status": "COMPROMISED",
                "message": "CRITICAL ALERT: Baseline signature mismatch! The baseline file has been tampered with or an invalid secret key was supplied.",
                "results": {"created": [], "modified": [], "deleted": []}
            }
            
    # 2. Scanning and Integrity Matching
    current_files = {}
    created = []
    modified = []
    deleted = []
    
    # Traverse current files
    for root, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename.startswith('.') or filename == 'baseline_hashes.json':
                continue
                
            full_path = os.path.join(root, filename)
            rel_path = os.path.relpath(full_path, directory_path)
            
            try:
                stat = os.stat(full_path)
                # Compute hash using same algorithm. Note: We hash individual files
                # without the key because they are raw files, but they are matched against baseline.
                # If HMAC key is used for individual files, we can do that too, but keeping it standard is also clean.
                # Let's use the key for individual files too if key is present to demonstrate keyed file-hashing!
                file_hash = calculate_file_hash(full_path, algorithm, key if hmac_enabled else None)
                
                if not file_hash.startswith("ERROR:"):
                    current_files[rel_path] = {
                        "hash": file_hash,
                        "size": stat.st_size,
                        "mtime": stat.st_mtime,
                        "readable_mtime": datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    }
            except Exception:
                continue
                
    # Detect Created and Modified files
    for rel_path, current_meta in current_files.items():
        if rel_path not in baseline_files:
            created.append({
                "path": rel_path,
                "size": current_meta["size"],
                "mtime": current_meta["readable_mtime"]
            })
        else:
            baseline_meta = baseline_files[rel_path]
            # Flag modified if hash is different or metadata changes significantly
            if current_meta["hash"] != baseline_meta["hash"]:
                modified.append({
                    "path": rel_path,
                    "baseline_hash": baseline_meta["hash"],
                    "current_hash": current_meta["hash"],
                    "size": current_meta["size"],
                    "mtime": current_meta["readable_mtime"]
                })
                
    # Detect Deleted files
    for rel_path, baseline_meta in baseline_files.items():
        if rel_path not in current_files:
            deleted.append({
                "path": rel_path,
                "size": baseline_meta["size"],
                "mtime": baseline_meta["readable_mtime"]
            })
            
    is_intact = len(created) == 0 and len(modified) == 0 and len(deleted) == 0
    status = "SECURE" if is_intact else "WARNING"
    message = "Integrity scan complete. All file hashes match baseline." if is_intact else "Integrity scan complete. File modifications or unauthorized additions/deletions detected!"
    
    return {
        "status": status,
        "message": message,
        "results": {
            "created": created,
            "modified": modified,
            "deleted": deleted
        },
        "scanned_files": current_files
    }

def benchmark_algorithms(directory_path: str) -> dict:
    """
    Measures the hashing throughput and execution speed across different cryptographic algorithms.
    Helps demonstrate cryptographic tradeoffs between speed (e.g. MD5) and security (e.g. SHA-3).
    """
    results = {}
    
    # Gather a sample list of files to benchmark
    files_to_hash = []
    for root, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename.startswith('.') or filename == 'baseline_hashes.json':
                continue
            files_to_hash.append(os.path.join(root, filename))
            
    if not files_to_hash:
        return {alg: 0.0 for alg in SUPPORTED_ALGORITHMS}
        
    for name, _ in SUPPORTED_ALGORITHMS.items():
        start_time = time.perf_counter()
        # Hash each file in the test suite
        for filepath in files_to_hash:
            calculate_file_hash(filepath, name)
        end_time = time.perf_counter()
        
        # Keep precision to 6 decimal places in milliseconds
        elapsed_ms = (end_time - start_time) * 1000
        results[name] = round(elapsed_ms, 4)
        
    return results
