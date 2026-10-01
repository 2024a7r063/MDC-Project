import os
import json
import hashlib
import subprocess
import platform

# Base directory where the anti-endpoint detector is installed
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Default directories monitored as endpoints
DEFAULT_FOLDERS = [
    os.path.join(BASE_DIR, "test_endpoint"),
    os.path.join(BASE_DIR, "test_endpoint_2")
]

# Config file tracking which folders are currently monitored
FOLDERS_CONFIG_FILE = os.path.join(BASE_DIR, "monitored_folders.json")

# Path to approved security baseline snapshot
BASELINE_FILE = os.path.join(BASE_DIR, "baseline.json")

# Optional simulation file for testing firewall drift without modifying OS settings
SIMULATED_FIREWALL_FILE = os.path.join(BASE_DIR, "simulated_firewall.json")


def get_monitored_folders():
    """
    Returns the list of absolute paths of all folders being monitored.
    If the configuration file does not exist, initializes it with DEFAULT_FOLDERS.
    """
    if os.path.exists(FOLDERS_CONFIG_FILE):
        try:
            with open(FOLDERS_CONFIG_FILE, "r", encoding="utf-8") as f:
                stored = json.load(f)
                resolved = []
                for p in stored:
                    full_p = p if os.path.isabs(p) else os.path.join(BASE_DIR, p)
                    if not os.path.exists(full_p):
                        os.makedirs(full_p, exist_ok=True)
                    resolved.append(full_p)
                if resolved:
                    return resolved
        except Exception:
            pass

    # Fallback to default folders
    for f in DEFAULT_FOLDERS:
        os.makedirs(f, exist_ok=True)
    save_monitored_folders(DEFAULT_FOLDERS)
    return DEFAULT_FOLDERS


def save_monitored_folders(folders):
    """
    Saves the list of monitored folders to monitored_folders.json.
    Stores folder names relative to BASE_DIR if possible for clean portability.
    """
    cleaned = []
    for f in folders:
        try:
            rel = os.path.relpath(f, BASE_DIR)
            if not rel.startswith(".."):
                cleaned.append(rel)
            else:
                cleaned.append(os.path.abspath(f))
        except Exception:
            cleaned.append(os.path.abspath(f))
            
    with open(FOLDERS_CONFIG_FILE, "w", encoding="utf-8") as file:
        json.dump(cleaned, file, indent=4)


def add_monitored_folder(folder_path):
    """
    Adds a new folder to the monitored list.
    Creates the folder if it does not already exist.
    """
    if not os.path.isabs(folder_path):
        folder_path = os.path.join(BASE_DIR, folder_path)
    
    os.makedirs(folder_path, exist_ok=True)
    current = get_monitored_folders()
    
    # Avoid duplicate paths
    norm_paths = [os.path.normcase(os.path.normpath(p)) for p in current]
    if os.path.normcase(os.path.normpath(folder_path)) not in norm_paths:
        current.append(os.path.abspath(folder_path))
        save_monitored_folders(current)
        return True, f"Added '{os.path.basename(folder_path)}' to monitored folders."
    return False, "Folder is already being monitored."


def remove_monitored_folder(folder_path):
    """
    Removes a folder from the monitored list.
    Ensures at least one folder remains monitored.
    """
    current = get_monitored_folders()
    if len(current) <= 1:
        return False, "At least one folder must remain monitored."
        
    target_norm = os.path.normcase(os.path.normpath(folder_path if os.path.isabs(folder_path) else os.path.join(BASE_DIR, folder_path)))
    new_list = [p for p in current if os.path.normcase(os.path.normpath(p)) != target_norm]
    
    if len(new_list) < len(current):
        save_monitored_folders(new_list)
        return True, "Folder removed from monitoring."
    return False, "Folder was not found in monitored list."


def calculate_file_hash(filepath):
    """
    Computes the SHA-256 hash of a file.
    In cybersecurity, SHA-256 serves as an immutable cryptographic digital fingerprint.
    Even a 1-bit alteration completely changes the hash.
    """
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def get_firewall_status():
    """
    Queries live Windows Firewall state for Domain, Private, and Public profiles.
    Also supports a simulated override for safe academic lab demos.
    Returns a dictionary:
    {
        "Domain": "ON" | "OFF",
        "Private": "ON" | "OFF",
        "Public": "ON" | "OFF",
        "source": "live" | "simulated"
    }
    """
    # 1. Check if a simulated firewall state is explicitly set for testing
    if os.path.exists(SIMULATED_FIREWALL_FILE):
        try:
            with open(SIMULATED_FIREWALL_FILE, "r", encoding="utf-8") as f:
                sim_data = json.load(f)
                sim_data["source"] = "simulated"
                return sim_data
        except Exception:
            pass

    # 2. Query Windows Defender Firewall via netsh
    profiles = {
        "Domain": "UNKNOWN",
        "Private": "UNKNOWN",
        "Public": "UNKNOWN",
        "source": "live"
    }

    if platform.system().lower() == "windows":
        try:
            # netsh advfirewall show allprofiles state is fast and does not require admin to read
            cmd = ["netsh", "advfirewall", "show", "allprofiles", "state"]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if res.returncode == 0:
                current_profile = None
                for line in res.stdout.splitlines():
                    line = line.strip()
                    if "Profile Settings:" in line:
                        current_profile = line.split()[0]
                    elif line.startswith("State") and current_profile:
                        state_val = line.split()[-1].upper()
                        if current_profile in profiles:
                            profiles[current_profile] = state_val
        except Exception:
            pass

    # If profiles couldn't be detected or running on non-Windows, provide clean defaults
    for k in ["Domain", "Private", "Public"]:
        if profiles[k] == "UNKNOWN":
            profiles[k] = "ON"

    return profiles


def set_simulated_firewall(profile_name, new_state):
    """
    Allows the user to simulate toggling the firewall ON/OFF for viva/demo testing.
    """
    current = get_firewall_status()
    current[profile_name] = new_state.upper()
    with open(SIMULATED_FIREWALL_FILE, "w", encoding="utf-8") as f:
        json.dump({
            "Domain": current.get("Domain", "ON"),
            "Private": current.get("Private", "ON"),
            "Public": current.get("Public", "ON")
        }, f, indent=4)


def reset_simulated_firewall():
    """Removes any simulated firewall override to return to live OS reading."""
    if os.path.exists(SIMULATED_FIREWALL_FILE):
        os.remove(SIMULATED_FIREWALL_FILE)


def scan_all_files(folders=None):
    """
    Recursively scans all monitored folders and their subdirectories.
    Returns a dictionary of:
    {
        "folder_name/relative_path.txt": {
            "folder": "folder_name",
            "rel_path": "relative_path.txt",
            "filename": "relative_path.txt",
            "full_path": "C:/...",
            "hash": "sha256..."
        }
    }
    """
    if folders is None:
        folders = get_monitored_folders()

    files_data = {}
    for folder_path in folders:
        if not os.path.exists(folder_path):
            continue
            
        folder_display = os.path.basename(folder_path)
        
        # os.walk allows full recursive discovery across all subfolders
        for root, _, filenames in os.walk(folder_path):
            for name in filenames:
                full_path = os.path.join(root, name)
                
                # Calculate relative path from this monitored folder root
                rel_path = os.path.relpath(full_path, folder_path).replace("\\", "/")
                
                # Unique key: folder_display/rel_path (e.g. "test_endpoint/config.txt")
                unique_key = f"{folder_display}/{rel_path}"
                
                try:
                    file_hash = calculate_file_hash(full_path)
                    files_data[unique_key] = {
                        "folder": folder_display,
                        "rel_path": rel_path,
                        "filename": name,
                        "display_path": unique_key,
                        "full_path": full_path,
                        "hash": file_hash
                    }
                except Exception:
                    # Skip unreadable or locked temporary files
                    continue

    return files_data


def get_file_risk(filename, status):
    """
    Evaluates individual file risk with cybersecurity rationale:
    
    1. UNCHANGED files are LOW risk (they match the approved baseline).
    
    2. HIGH Risk triggers:
       - Dangerous executable/script extensions (.exe, .bat, .cmd, .ps1, .vbs, .sh, .py, .dll, .reg, .msi):
         Adding (NEW) or MODIFIED executable scripts represents potential malware/intrusion injection.
       - Critical configuration/firewall keywords ('config', 'firewall', 'security', 'setting', 'policy')
         or config extensions (.conf, .ini, .env):
         Any NEW, MODIFIED, or DELETED security/firewall setting represents unauthorized posture change.
         
    3. MEDIUM Risk triggers:
       - Standard additions, modifications, or removals of regular documents/text files.
    """
    if status == "UNCHANGED":
        return "LOW", "Matches approved security baseline."

    fn = filename.lower()
    
    # 1. Dangerous scripts and executables
    dangerous_exts = (".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".py", ".dll", ".reg", ".msi", ".scr")
    is_script_or_binary = any(fn.endswith(ext) for ext in dangerous_exts)
    
    if is_script_or_binary:
        if status == "NEW":
            return "HIGH", "Unauthorized script/executable created on endpoint (potential backdoor or dropper)."
        elif status == "MODIFIED":
            return "HIGH", "Executable binary or script content was modified."
        elif status == "DELETED":
            return "MEDIUM", "Script or binary was deleted from endpoint."

    # 2. Critical security, firewall, and configuration files
    critical_keywords = ("config", "firewall", "security", "setting", "policy", "credential", "password", "token")
    is_critical_name = any(kw in fn for kw in critical_keywords)
    critical_exts = (".conf", ".ini", ".env", ".cfg", ".yaml", ".yml")
    is_critical_ext = any(fn.endswith(ext) for ext in critical_exts)
    
    if is_critical_name or is_critical_ext:
        if status == "NEW":
            return "HIGH", "New firewall/security configuration file introduced into endpoint."
        elif status == "MODIFIED":
            return "HIGH", "Critical configuration or firewall file modified (security policy altered)."
        elif status == "DELETED":
            return "HIGH", "Critical configuration or firewall file was deleted (service/protection lost)."

    # 3. Regular standard documents or data files
    if status == "NEW":
        return "MEDIUM", "New standard file added to monitored directory."
    elif status == "MODIFIED":
        return "MEDIUM", "Standard file content modified."
    elif status == "DELETED":
        return "MEDIUM", "Standard file deleted from endpoint."

    return "MEDIUM", "File drift detected."


def save_baseline(baseline_file=BASELINE_FILE):
    """
    Captures the current state of files across ALL monitored folders
    AND the live Windows Firewall profile state into baseline.json.
    """
    monitored_folders = get_monitored_folders()
    current_files = scan_all_files(monitored_folders)
    current_firewall = get_firewall_status()

    # Clean folder names for display
    folder_names = [os.path.basename(f) for f in monitored_folders]

    baseline_data = {
        "version": 2,
        "monitored_folders": folder_names,
        "firewall": {
            "Domain": current_firewall.get("Domain", "ON"),
            "Private": current_firewall.get("Private", "ON"),
            "Public": current_firewall.get("Public", "ON")
        },
        "files": current_files
    }

    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=4)

    return baseline_data


def load_baseline(baseline_file=BASELINE_FILE):
    """
    Loads baseline from baseline.json.
    Includes automatic backward compatibility if an older v1 baseline exists.
    """
    if not os.path.exists(baseline_file):
        return None

    try:
        with open(baseline_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Handle backward compatibility: older format was { "file.txt": "hash", ... }
        if "version" not in data and "files" not in data:
            adapted_files = {}
            for fname, fhash in data.items():
                if isinstance(fhash, str):
                    key = f"test_endpoint/{fname}"
                    adapted_files[key] = {
                        "folder": "test_endpoint",
                        "rel_path": fname,
                        "filename": fname,
                        "display_path": key,
                        "full_path": os.path.join(BASE_DIR, "test_endpoint", fname),
                        "hash": fhash
                    }
            return {
                "version": 1,
                "monitored_folders": ["test_endpoint"],
                "firewall": {
                    "Domain": "ON",
                    "Private": "ON",
                    "Public": "ON"
                },
                "files": adapted_files
            }

        return data
    except Exception:
        return None


def compare_firewall(baseline_firewall, current_firewall):
    """
    Compares baseline firewall profile state against current state.
    Detects if any profile was turned OFF or altered.
    """
    drift_detected = False
    reasons = []
    profile_details = []

    profiles_to_check = ["Domain", "Private", "Public"]
    
    for prof in profiles_to_check:
        base_state = baseline_firewall.get(prof, "ON")
        curr_state = current_firewall.get(prof, "ON")
        
        is_disabled = (curr_state == "OFF")
        state_changed = (base_state != curr_state)
        
        detail = {
            "profile": prof,
            "baseline": base_state,
            "current": curr_state,
            "changed": state_changed,
            "is_disabled": is_disabled
        }
        profile_details.append(detail)

        if is_disabled and base_state == "ON":
            drift_detected = True
            reasons.append(f"Windows Firewall {prof} profile has been DISABLED (OFF)!")
        elif state_changed:
            drift_detected = True
            reasons.append(f"Windows Firewall {prof} profile state drifted from {base_state} to {curr_state}.")

    risk = "HIGH" if drift_detected else "LOW"

    return {
        "drift_detected": drift_detected,
        "risk": risk,
        "reasons": reasons,
        "profiles": profile_details,
        "source": current_firewall.get("source", "live")
    }


def compare_drift(baseline_file=BASELINE_FILE):
    """
    Comprehensive drift comparison:
    1. Scans all files across all monitored folders recursively.
    2. Checks Windows Firewall profile state.
    3. Categorizes drift (NEW, MODIFIED, DELETED, UNCHANGED).
    4. Evaluates risk with clear explanations.
    """
    baseline_data = load_baseline(baseline_file)

    if baseline_data is None:
        return {
            "error": "No baseline found! Please click 'Create Baseline' first to snapshot the safe endpoint state."
        }

    baseline_files = baseline_data.get("files", {})
    baseline_firewall = baseline_data.get("firewall", {"Domain": "ON", "Private": "ON", "Public": "ON"})

    current_folders = get_monitored_folders()
    current_files = scan_all_files(current_folders)
    current_firewall = get_firewall_status()

    # Step A: Evaluate Firewall Drift
    firewall_comparison = compare_firewall(baseline_firewall, current_firewall)

    # Step B: Compare Files
    results = []
    new_count = 0
    modified_count = 0
    deleted_count = 0
    unchanged_count = 0

    # 1. Check current files against baseline
    for key, file_info in current_files.items():
        curr_hash = file_info["hash"]
        display_path = file_info["display_path"]
        fname = file_info["filename"]
        folder = file_info["folder"]

        if key not in baseline_files:
            # Also check if filename alone matched in old v1 baseline
            alt_key = f"test_endpoint/{fname}"
            if alt_key in baseline_files and len(baseline_files) <= 3:
                base_hash = baseline_files[alt_key]["hash"]
                if curr_hash == base_hash:
                    status = "UNCHANGED"
                    unchanged_count += 1
                else:
                    status = "MODIFIED"
                    modified_count += 1
                risk, reason = get_file_risk(fname, status)
                results.append({
                    "folder": folder,
                    "filename": fname,
                    "display_path": display_path,
                    "status": status,
                    "risk": risk,
                    "reason": reason,
                    "current_hash": curr_hash,
                    "baseline_hash": base_hash
                })
                continue

            status = "NEW"
            risk, reason = get_file_risk(fname, status)
            new_count += 1
            results.append({
                "folder": folder,
                "filename": fname,
                "display_path": display_path,
                "status": status,
                "risk": risk,
                "reason": reason,
                "current_hash": curr_hash,
                "baseline_hash": "None (New)"
            })
        else:
            base_hash = baseline_files[key]["hash"]
            if curr_hash == base_hash:
                status = "UNCHANGED"
                unchanged_count += 1
            else:
                status = "MODIFIED"
                modified_count += 1
                
            risk, reason = get_file_risk(fname, status)
            results.append({
                "folder": folder,
                "filename": fname,
                "display_path": display_path,
                "status": status,
                "risk": risk,
                "reason": reason,
                "current_hash": curr_hash,
                "baseline_hash": base_hash
            })

    # 2. Check for deleted files (existed in baseline but absent now)
    for key, base_info in baseline_files.items():
        if key not in current_files:
            fname = base_info.get("filename", os.path.basename(key))
            folder = base_info.get("folder", "monitored")
            status = "DELETED"
            risk, reason = get_file_risk(fname, status)
            deleted_count += 1
            results.append({
                "folder": folder,
                "filename": fname,
                "display_path": key,
                "status": status,
                "risk": risk,
                "reason": reason,
                "current_hash": "Missing (Deleted)",
                "baseline_hash": base_info.get("hash", "Unknown")
            })

    # Step C: Overall Risk Calculation
    overall_risk = "LOW"
    risk_reasons = []

    has_high_file_risk = any(item["risk"] == "HIGH" for item in results)
    has_medium_file_risk = any(item["risk"] == "MEDIUM" for item in results)

    # Firewall check has supreme security priority
    if firewall_comparison["drift_detected"]:
        overall_risk = "HIGH"
        risk_reasons.extend(firewall_comparison["reasons"])

    if has_high_file_risk:
        overall_risk = "HIGH"
        high_files = [item["filename"] for item in results if item["risk"] == "HIGH"]
        risk_reasons.append(f"Critical/Dangerous file drift detected in: {', '.join(high_files[:3])}.")
    elif has_medium_file_risk and overall_risk != "HIGH":
        overall_risk = "MEDIUM"
        risk_reasons.append("Non-critical file additions, edits, or removals detected across monitored folders.")

    if not risk_reasons:
        overall_risk = "LOW"
        risk_reasons.append("All monitored folders and Windows Firewall profiles match the approved security baseline.")

    # Distinct monitored folder summary for UI
    folder_summaries = []
    for f in current_folders:
        bname = os.path.basename(f)
        count = sum(1 for item in results if item["folder"] == bname and item["status"] != "DELETED")
        folder_summaries.append({
            "name": bname,
            "path": f,
            "active_files": count
        })

    return {
        "results": results,
        "total_files": len(current_files),
        "new_count": new_count,
        "modified_count": modified_count,
        "deleted_count": deleted_count,
        "unchanged_count": unchanged_count,
        "overall_risk": overall_risk,
        "overall_reason": " ".join(risk_reasons),
        "firewall": firewall_comparison,
        "monitored_folders": folder_summaries
    }
