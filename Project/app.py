from flask import Flask, render_template, request, redirect, url_for, flash
import scanner
import os

app = Flask(__name__)
# Secret key needed by Flask for flash notification messages
app.secret_key = "cybersecurity_drift_detector_secret"

# Global variable storing the most recent scan results
latest_scan = None


@app.route("/")
def index():
    """
    Main dashboard page.
    Loads baseline status, active monitored folders, live firewall status,
    and displays the latest scan results (if any).
    """
    baseline_data = scanner.load_baseline()
    
    baseline_exists = False
    baseline_file_count = 0
    baseline_folders = []
    baseline_firewall = {}
    
    if baseline_data is not None:
        baseline_exists = True
        baseline_file_count = len(baseline_data.get("files", {}))
        baseline_folders = baseline_data.get("monitored_folders", [])
        baseline_firewall = baseline_data.get("firewall", {})

    monitored_folders_paths = scanner.get_monitored_folders()
    monitored_folders_info = []
    for f in monitored_folders_paths:
        bname = os.path.basename(f)
        # Count files currently inside folder
        file_count = 0
        if os.path.exists(f):
            for _, _, files in os.walk(f):
                file_count += len(files)
        monitored_folders_info.append({
            "name": bname,
            "path": f,
            "count": file_count
        })

    live_firewall = scanner.get_firewall_status()

    return render_template(
        "index.html",
        baseline_exists=baseline_exists,
        baseline_file_count=baseline_file_count,
        baseline_folders=baseline_folders,
        baseline_firewall=baseline_firewall,
        monitored_folders=monitored_folders_info,
        live_firewall=live_firewall,
        scan_data=latest_scan
    )


@app.route("/create-baseline", methods=["POST"])
def create_baseline_route():
    """
    Creates an approved security baseline snapshot:
    - Hashes all files across all monitored folders recursively
    - Records the current Windows Firewall profile states (Domain, Private, Public)
    """
    global latest_scan
    
    saved_baseline = scanner.save_baseline()
    file_count = len(saved_baseline.get("files", {}))
    folder_count = len(saved_baseline.get("monitored_folders", []))
    
    # Reset previous scan view since a new reference baseline is active
    latest_scan = None
    
    flash(
        f"Approved security baseline created! {file_count} files recorded across {folder_count} monitored folders. Windows Firewall profile states captured.",
        "success"
    )
    return redirect(url_for("index"))


@app.route("/scan", methods=["POST"])
def scan_endpoint_route():
    """
    Scans the endpoint:
    - Compares files across all monitored folders against baseline hashes
    - Checks live Windows Firewall profile states against baseline
    - Evaluates cybersecurity risk (LOW, MEDIUM, HIGH)
    """
    global latest_scan
    
    scan_result = scanner.compare_drift()
    
    if "error" in scan_result:
        flash(scan_result["error"], "danger")
        return redirect(url_for("index"))
        
    latest_scan = scan_result
    
    # Context-aware alert flash
    if scan_result["overall_risk"] == "HIGH":
        flash("🚨 High-risk endpoint drift detected! Check the alerts below immediately.", "danger")
    elif scan_result["overall_risk"] == "MEDIUM":
        flash("⚠️ Medium-risk file modifications or additions detected.", "warning")
    else:
        flash("✅ Endpoint scan completed! All files and firewall settings match the baseline.", "success")
        
    return redirect(url_for("index"))


@app.route("/add-folder", methods=["POST"])
def add_folder_route():
    """
    Adds a new directory to the monitored folders list.
    Supports monitoring multiple folders on the endpoint.
    """
    folder_name = request.form.get("folder_name", "").strip()
    if not folder_name:
        flash("Please enter a valid folder name or path.", "danger")
        return redirect(url_for("index"))
        
    success, msg = scanner.add_monitored_folder(folder_name)
    flash(msg, "info" if success else "warning")
    return redirect(url_for("index"))


@app.route("/remove-folder", methods=["POST"])
def remove_folder_route():
    """
    Removes a directory from the monitored folders list.
    """
    folder_name = request.form.get("folder_name", "").strip()
    success, msg = scanner.remove_monitored_folder(folder_name)
    flash(msg, "info" if success else "warning")
    return redirect(url_for("index"))


@app.route("/simulate-firewall-toggle", methods=["POST"])
def simulate_firewall_toggle_route():
    """
    Simulates toggling a firewall profile (or resetting to live OS reading)
    for safe academic lab tests and viva demonstrations.
    """
    action = request.form.get("action", "toggle")
    profile = request.form.get("profile", "Private")
    
    if action == "reset":
        scanner.reset_simulated_firewall()
        flash("Firewall state reset to live Windows Defender readings.", "info")
    else:
        current_state = scanner.get_firewall_status().get(profile, "ON")
        new_state = "OFF" if current_state == "ON" else "ON"
        scanner.set_simulated_firewall(profile, new_state)
        flash(f"Simulated Windows Firewall {profile} profile set to {new_state} for testing.", "warning")
        
    return redirect(url_for("index"))


if __name__ == "__main__":
    print("Starting Endpoint Drift Detector prototype...")
    print("Access the dashboard at: http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
