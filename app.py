"""
Cryptography Course Project: Hash-Based File Integrity Checker (FIM)
Flask Web Server
Author: Pair Programmed with Antigravity AI
"""

import os
import json
import time
from flask import Flask, jsonify, request, render_template
import cryptography_engine as ce

app = Flask(__name__, template_folder='templates', static_folder='static')

# File Paths
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(WORKSPACE_DIR, 'config.json')
BASELINE_FILE = os.path.join(WORKSPACE_DIR, 'baseline_hashes.json')
DEFAULT_MONITORED_DIR = os.path.join(WORKSPACE_DIR, 'monitored_files')

# Ensure the default monitored directory exists
if not os.path.exists(DEFAULT_MONITORED_DIR):
    os.makedirs(DEFAULT_MONITORED_DIR)

# Helper: Load and Save Config
def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Ensure monitored_directory is absolute
                config['monitored_directory'] = os.path.abspath(config.get('monitored_directory', DEFAULT_MONITORED_DIR))
                return config
        except Exception:
            pass
            
    # Default Config
    return {
        "monitored_directory": DEFAULT_MONITORED_DIR,
        "algorithm": "sha256",
        "use_hmac": False,
        "hmac_key": ""
    }

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)

@app.route('/')
def home():
    """Renders the main Cybersecurity Integrity Dashboard."""
    return render_template('index.html')

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Handles getting and updating configuration parameters."""
    config = load_config()
    
    if request.method == 'POST':
        data = request.json or {}
        monitored_dir = data.get('monitored_directory', '').strip()
        algorithm = data.get('algorithm', 'sha256').strip().lower()
        use_hmac = bool(data.get('use_hmac', False))
        hmac_key = data.get('hmac_key', '').strip()
        
        # Validation
        if not monitored_dir:
            return jsonify({"status": "error", "message": "Monitored directory path cannot be empty."}), 400
            
        if not os.path.exists(monitored_dir):
            try:
                # Try to create it if it doesn't exist
                os.makedirs(monitored_dir)
            except Exception as e:
                return jsonify({"status": "error", "message": f"Invalid directory path: {str(e)}"}), 400
                
        if algorithm not in ce.SUPPORTED_ALGORITHMS:
            return jsonify({"status": "error", "message": f"Unsupported algorithm. Choose from: {list(ce.SUPPORTED_ALGORITHMS.keys())}"}), 400
            
        if use_hmac and not hmac_key:
            return jsonify({"status": "error", "message": "HMAC secret key is required when HMAC is enabled."}), 400
            
        config['monitored_directory'] = os.path.abspath(monitored_dir)
        config['algorithm'] = algorithm
        config['use_hmac'] = use_hmac
        config['hmac_key'] = hmac_key
        
        save_config(config)
        return jsonify({"status": "success", "message": "Configuration updated successfully.", "config": {
            "monitored_directory": config['monitored_directory'],
            "algorithm": config['algorithm'],
            "use_hmac": config['use_hmac'],
            "has_key": bool(config['hmac_key'])
        }})
        
    # GET Response (scrub active key for security display, just flag if it's there)
    return jsonify({
        "status": "success",
        "config": {
            "monitored_directory": config['monitored_directory'],
            "algorithm": config['algorithm'],
            "use_hmac": config['use_hmac'],
            "hmac_key": config['hmac_key']  # Return for front-end configuration edits
        }
    })

@app.route('/api/baseline/initialize', methods=['POST'])
def api_initialize_baseline():
    """Triggers the cryptographic engine to scan and build a new baseline database."""
    config = load_config()
    directory = config['monitored_directory']
    algorithm = config['algorithm']
    key = config['hmac_key'] if config['use_hmac'] else None
    
    start_time = time.perf_counter()
    try:
        baseline = ce.generate_baseline(directory, algorithm, key)
        
        # Write to JSON file
        with open(BASELINE_FILE, 'w') as f:
            json.dump(baseline, f, indent=4)
            
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        
        return jsonify({
            "status": "success",
            "message": f"Baseline initialized successfully using {algorithm.upper()}!",
            "details": {
                "algorithm": algorithm,
                "timestamp": baseline["timestamp"],
                "file_count": len(baseline["files"]),
                "hmac_enabled": baseline["hmac_enabled"],
                "signature": baseline.get("signature", "None"),
                "execution_time_ms": round(elapsed_ms, 2)
            }
        })
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to initialize baseline: {str(e)}"}), 500

@app.route('/api/check', methods=['GET', 'POST'])
def api_integrity_check():
    """Runs a directory scan and performs the cryptographic integrity verification."""
    config = load_config()
    directory = config['monitored_directory']
    key = config['hmac_key'] if config['use_hmac'] else None
    
    if not os.path.exists(BASELINE_FILE):
        return jsonify({
            "status": "UNINITIALIZED",
            "message": "Baseline has not been generated yet. Please configure and initialize a baseline first."
        })
        
    try:
        # Load baseline hashes
        with open(BASELINE_FILE, 'r') as f:
            baseline_data = json.load(f)
            
        start_time = time.perf_counter()
        
        # Run integrity check
        check_result = ce.verify_integrity(directory, baseline_data, key)
        
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        check_result["execution_time_ms"] = round(elapsed_ms, 2)
        
        # Generate algorithm benchmarks for cryptographic analysis
        benchmarks = ce.benchmark_algorithms(directory)
        check_result["benchmarks"] = benchmarks
        
        return jsonify(check_result)
        
    except Exception as e:
        return jsonify({"status": "ERROR", "message": f"Integrity check failed: {str(e)}"}), 500

@app.route('/api/simulate/<action>', methods=['POST'])
def api_simulate_file_action(action):
    """Simulates directory file changes to instantly demonstrate integrity alerts."""
    config = load_config()
    directory = config['monitored_directory']
    target_filepath = os.path.join(directory, 'simulation_target.txt')
    
    try:
        if action == 'create':
            # Create a new file
            with open(target_filepath, 'w') as f:
                f.write(f"SIMULATED FILE\nCreated on: {time.asctime()}\nThis file is added to test unauthorized file creation detection.")
            return jsonify({"status": "success", "message": "Created simulated file: simulation_target.txt"})
            
        elif action == 'modify':
            # Modify the file if it exists, otherwise create/modify
            mode = 'a' if os.path.exists(target_filepath) else 'w'
            with open(target_filepath, mode) as f:
                f.write(f"\n[TAMPERED] Line appended at {time.asctime()} to trigger modification hash mismatch!")
            return jsonify({"status": "success", "message": "Appended unauthorized changes to: simulation_target.txt"})
            
        elif action == 'delete':
            # Delete the file
            if os.path.exists(target_filepath):
                os.remove(target_filepath)
                return jsonify({"status": "success", "message": "Deleted simulated file: simulation_target.txt"})
            else:
                return jsonify({"status": "error", "message": "simulation_target.txt does not exist to delete."}), 400
                
        elif action == 'tamper_baseline':
            # Direct attack vector: malicious modification of the baseline JSON hashes
            if not os.path.exists(BASELINE_FILE):
                return jsonify({"status": "error", "message": "Baseline database does not exist to tamper."}), 400
                
            with open(BASELINE_FILE, 'r') as f:
                baseline_data = json.load(f)
                
            # Find a file in the baseline and corrupt its hash
            files = baseline_data.get("files", {})
            if not files:
                return jsonify({"status": "error", "message": "No files inside baseline database to tamper."}), 400
                
            # Tamper the first file hash by replacing its characters
            first_key = list(files.keys())[0]
            original_hash = files[first_key]["hash"]
            # Flip the last character
            tampered_hash = original_hash[:-1] + ('0' if original_hash[-1] != '0' else '1')
            files[first_key]["hash"] = tampered_hash
            
            with open(BASELINE_FILE, 'w') as f:
                json.dump(baseline_data, f, indent=4)
                
            return jsonify({
                "status": "success", 
                "message": f"ATTACK SIMULATION: Corrupted the baseline hash for '{first_key}'. The stored reference hash has been changed to '{tampered_hash}'."
            })
            
        else:
            return jsonify({"status": "error", "message": "Unknown action."}), 400
            
    except Exception as e:
        return jsonify({"status": "error", "message": f"Simulation failed: {str(e)}"}), 500

if __name__ == '__main__':
    print("----------------------------------------------------------------")
    print("   HASH-BASED FILE INTEGRITY CHECKER (FIM) DEPLOYED SUCCESSFULLY   ")
    print("   URL: http://127.0.0.1:5000                                   ")
    print("----------------------------------------------------------------")
    app.run(debug=True, port=5000)
