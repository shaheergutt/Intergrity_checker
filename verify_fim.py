"""
Kryptos File Integrity Monitor (FIM)
Automated API Verification Suite
Author: Pair Programmed with Antigravity AI
"""

import requests
import json
import time

BASE_URL = "http://127.0.0.1:5000"

def run_test_suite():
    print("================================================================")
    print("          KRYPTOS AUTOMATED INTEGRITY SCANNER VERIFICATION      ")
    print("================================================================\n")
    
    # 0. Clean up previous test residues
    print("[PRE-TEST] Cleaning up any previous simulation residues...")
    try:
        requests.post(f"{BASE_URL}/api/simulate/delete")
    except Exception:
        pass
        
    # 1. Test GET Config
    print("\n[TEST 1] Fetching initial server configuration...")
    try:
        r = requests.get(f"{BASE_URL}/api/config")
        r.raise_for_status()
        config = r.json()
        print(f" -> SUCCESS: Config loaded: {json.dumps(config['config'], indent=2)}")
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 2. Test POST Config with HMAC enabled
    print("\n[TEST 2] Updating configuration to SHA-256 with HMAC Baseline Protection...")
    payload = {
        "monitored_directory": "monitored_files",
        "algorithm": "sha256",
        "use_hmac": True,
        "hmac_key": "ProfessorAwesomeCryptoGradingKey!"
    }
    try:
        r = requests.post(f"{BASE_URL}/api/config", json=payload)
        r.raise_for_status()
        res = r.json()
        print(f" -> SUCCESS: Server response: {res['message']}")
        print(f" -> Active Config: {json.dumps(res['config'], indent=2)}")
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 3. Test Baseline Initialization
    print("\n[TEST 3] Initializing Cryptographic Baseline Database...")
    try:
        r = requests.post(f"{BASE_URL}/api/baseline/initialize")
        r.raise_for_status()
        res = r.json()
        print(f" -> SUCCESS: {res['message']}")
        print(f" -> Details: {json.dumps(res['details'], indent=2)}")
        assert res['details']['file_count'] >= 2, "Expected at least 2 default test files"
        assert res['details']['hmac_enabled'] is True, "Expected HMAC to be active"
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 4. Test Integrity Scan (Secure state)
    print("\n[TEST 4] Running initial integrity scan (Expected: SECURE)...")
    try:
        r = requests.get(f"{BASE_URL}/api/check")
        r.raise_for_status()
        res = r.json()
        print(f" -> Scan Status: {res['status']}")
        print(f" -> Message: {res['message']}")
        print(f" -> Execution Time: {res['execution_time_ms']} ms")
        assert res['status'] == 'SECURE', f"Expected status SECURE, got {res['status']}"
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 5. Test Threat Simulation: Creation
    print("\n[TEST 5] Simulating unauthorized file addition (Creating 'simulation_target.txt')...")
    try:
        r = requests.post(f"{BASE_URL}/api/simulate/create")
        r.raise_for_status()
        print(f" -> Simulation Response: {r.json()['message']}")
        
        # Immediate Scan
        print(" -> Scanning directory for changes...")
        r = requests.get(f"{BASE_URL}/api/check")
        res = r.json()
        print(f" -> Scan Status: {res['status']}")
        print(f" -> Created Files: {res['results']['created']}")
        assert res['status'] == 'WARNING', "Expected status WARNING after file creation"
        assert len(res['results']['created']) == 1, "Expected exactly 1 new file"
        assert res['results']['created'][0]['path'] == 'simulation_target.txt'
        
        # Add to baseline to test modification next
        print(" -> Adding created file to baseline...")
        requests.post(f"{BASE_URL}/api/baseline/initialize")
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 6. Test Threat Simulation: Modification
    print("\n[TEST 6] Simulating unauthorized file alteration (Editing 'simulation_target.txt')...")
    try:
        r = requests.post(f"{BASE_URL}/api/simulate/modify")
        r.raise_for_status()
        print(f" -> Simulation Response: {r.json()['message']}")
        
        # Immediate Scan
        print(" -> Scanning directory for changes...")
        r = requests.get(f"{BASE_URL}/api/check")
        res = r.json()
        print(f" -> Scan Status: {res['status']}")
        print(f" -> Modified Files: {res['results']['modified']}")
        assert res['status'] == 'WARNING', "Expected status WARNING after modification"
        assert len(res['results']['modified']) == 1, "Expected exactly 1 modified file"
        assert res['results']['modified'][0]['path'] == 'simulation_target.txt'
        
        # Save modified file to baseline to test deletion next
        print(" -> Updating baseline with modified file...")
        requests.post(f"{BASE_URL}/api/baseline/initialize")
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 7. Test Threat Simulation: Deletion
    print("\n[TEST 7] Simulating unauthorized file deletion (Removing 'simulation_target.txt')...")
    try:
        r = requests.post(f"{BASE_URL}/api/simulate/delete")
        r.raise_for_status()
        print(f" -> Simulation Response: {r.json()['message']}")
        
        # Immediate Scan
        print(" -> Scanning directory for changes...")
        r = requests.get(f"{BASE_URL}/api/check")
        res = r.json()
        print(f" -> Scan Status: {res['status']}")
        print(f" -> Deleted Files: {res['results']['deleted']}")
        assert res['status'] == 'WARNING', "Expected status WARNING after deletion"
        assert len(res['results']['deleted']) == 1, "Expected exactly 1 deleted file"
        assert res['results']['deleted'][0]['path'] == 'simulation_target.txt'
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 8. Test Direct Attack Simulation: Tampering with Baseline File (Proving HMAC)
    print("\n[TEST 8] Malicious Baseline Tampering Simulation (Testing HMAC Shield)...")
    try:
        r = requests.post(f"{BASE_URL}/api/simulate/tamper_baseline")
        r.raise_for_status()
        print(f" -> Attack Response: {r.json()['message']}")
        
        # Immediate Scan
        print(" -> Running scan on tampered baseline...")
        r = requests.get(f"{BASE_URL}/api/check")
        res = r.json()
        print(f" -> Scan Status: {res['status']}")
        print(f" -> Alarm Message: {res['message']}")
        assert res['status'] == 'COMPROMISED', f"Expected COMPROMISED due to signature mismatch, got {res['status']}"
        print(" -> SUCCESS: HMAC shield successfully detected the baseline alteration attack!")
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    # 9. Clean up and restore
    print("\n[TEST 9] Restoring system to secure state by re-initializing baseline...")
    try:
        r = requests.post(f"{BASE_URL}/api/baseline/initialize")
        r.raise_for_status()
        print(f" -> Re-initialization Response: {r.json()['message']}")
        
        # Final Scan
        r = requests.get(f"{BASE_URL}/api/check")
        res = r.json()
        print(f" -> Final Status: {res['status']}")
        assert res['status'] == 'SECURE', "Expected secure state restored"
    except Exception as e:
        print(f" -> FAIL: {str(e)}")
        return

    print("\n================================================================")
    print("  ALL TESTS PASSED! CRYTOGRAPHIC INTEGRITY ENGINE IS 100% SECURE ")
    print("================================================================\n")

if __name__ == "__main__":
    run_test_suite()
