import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from pynput.mouse import Listener
import time
import pytesseract
from pytesseract import Output
from PIL import Image
import re
import csv
import pyautogui
import threading
import os
import sys
import requests
import configparser

# Patterns for nodes and mobs
item_patterns = [
    re.compile(r"You finished cutting down (.+?)\."),
    re.compile(r"You finished mining (.+?)\."),
    re.compile(r"You finished harvesting (.+?)\."),
]
mob_pattern = re.compile(r"(.+?) (?:is .*?|eyes you .*?)\.")

location_pattern = re.compile(r"Your location:\s([\d.-]+)\s([\d.-]+)\s([\d.-]+)")

# Global variables
config_file = "config.ini"
monitor_region = None
node_csv_file = ""
mob_csv_file = ""
stop_monitoring = False
api_key = ""
enable_api_upload = False
enable_node_tracking = True
enable_mob_tracking = False
log_queue = []
config = configparser.ConfigParser()

# API Endpoint
API_ENDPOINT = "https://shalazam.info/api/v1/resources"


def setup_tesseract():
    """Configure pytesseract to use the embedded Tesseract binary."""
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(__file__)

    if sys.platform.startswith("win"):
        tesseract_binary = os.path.join(base_path, "tesseract", "bin", "tesseract.exe")
    elif sys.platform.startswith("linux"):
        tesseract_binary = os.path.join(base_path, "tesseract", "bin", "tesseract")
    else:
        tesseract_binary = "tesseract"

    tessdata_folder = os.path.join(base_path, "tesseract", "tessdata")
    if os.path.exists(tessdata_folder):
        os.environ["TESSDATA_PREFIX"] = tessdata_folder

    pytesseract.pytesseract.tesseract_cmd = tesseract_binary


def log_message(message):
    """Add a message to the scrolling info window."""
    if "info_window" in globals():
        info_window.insert(tk.END, f"{message}\n")
        info_window.see(tk.END)
    else:
        print(message)


def flush_log_queue():
    """Flush the queued log messages into the GUI."""
    for message in log_queue:
        info_window.insert(tk.END, f"{message}\n")
    info_window.see(tk.END)
    log_queue.clear()


def load_config():
    """Load configuration from the config.ini file."""
    global config, api_key, monitor_region, node_csv_file, mob_csv_file

    if os.path.exists(config_file):
        config.read(config_file)
        api_key = config.get("Settings", "APIKey", fallback="")
        monitor_region_str = config.get("Settings", "MonitorRegion", fallback="")
        node_csv_file = config.get("Settings", "NodeCSVFile", fallback="")
        mob_csv_file = config.get("Settings", "MobCSVFile", fallback="")

        if monitor_region_str:
            try:
                global monitor_region
                monitor_region = eval(monitor_region_str)
                log_message(f"Loaded monitor region: {monitor_region}")
            except Exception as e:
                log_message(f"Failed to load monitor region: {e}")
                monitor_region = None


def save_config():
    """Save configuration to the config.ini file."""
    global api_key, monitor_region, node_csv_file, mob_csv_file

    config["Settings"] = {
        "APIKey": api_key,
        "MonitorRegion": str(monitor_region) if monitor_region else "",
        "NodeCSVFile": node_csv_file,
        "MobCSVFile": mob_csv_file,
        "EnableAPIUpload": str(enable_api_upload.get()),  # Use .get() to extract boolean
        "EnableNodeTracking": str(enable_node_tracking.get()),
        "EnableMobTracking": str(enable_mob_tracking.get()),
    }
    with open(config_file, "w") as file:
        config.write(file)
    log_message("Configuration saved.")


def toggle_feature(feature):
    """Toggle the state of a feature."""
    global enable_api_upload, enable_node_tracking, enable_mob_tracking
    if feature == "api":
        enable_api_upload = not enable_api_upload
    elif feature == "node":
        enable_node_tracking = not enable_node_tracking
    elif feature == "mob":
        enable_mob_tracking = not enable_mob_tracking
    save_config()


def set_file_location(file_type):
    """Set the file location for nodes or mobs."""
    global node_csv_file, mob_csv_file
    file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
    if file_path:
        if file_type == "node":
            node_csv_file = file_path
            log_message(f"Node CSV file set to: {node_csv_file}")
        elif file_type == "mob":
            mob_csv_file = file_path
            log_message(f"Mob CSV file set to: {mob_csv_file}")
        save_config()


def upload_to_api(item, x, y, z):
    """Send a node to the API if the API key is present."""
    global api_key
    if not api_key:
        log_message("No API key provided. Skipping API upload.")
        return

    payload = {
        "resource": {
            "loc_x": x,
            "loc_y": y,
            "loc_z": z,
            "name": item,
        }
    }
    headers = {"Authorization": api_key}

    try:
        response = requests.post(API_ENDPOINT, json=payload, headers=headers)
        log_message(f"Uploaded {item} to API: {response.status_code} {response.text}")
    except Exception as e:
        log_message(f"Error uploading to API: {e}")


def is_unique(existing_entries, new_entry, threshold=10):
    """Check if a new entry (item + coordinates) is unique."""
    new_item, new_coords = new_entry[0], new_entry[1:]
    for existing_item, *existing_coords in existing_entries:
        if new_item == existing_item and all(
            abs(float(a) - float(b)) <= threshold
            for a, b in zip(existing_coords, new_coords)
        ):
            return False
    return True


def process_text(text, existing_entries, threshold=10):
    """Parse the text for matching data pairs and check for duplicates."""
    lines = text.splitlines()
    data_pairs = []

    for i in range(len(lines) - 1):
        item = None
        for pattern in item_patterns:
            match_item = pattern.search(lines[i])
            if match_item:
                item = match_item.group(1)
                break

        match_location = location_pattern.search(lines[i + 1])

        if item and match_location:
            location = match_location.groups()
            new_entry = (item, *location)
            if is_unique(existing_entries, new_entry, threshold):
                data_pairs.append(new_entry)
                existing_entries.append(new_entry)
    return data_pairs


def process_mob_data(text, existing_entries, writer, threshold=10):
    """Parse the text for mob data, deduplicate, and write immediately."""
    lines = text.splitlines()
    combined_entries = []
    current_mob_info = []
    current_location = None

    for line in lines:
        line = line.strip()  # Remove extra whitespace
        if not line:  # Skip blank lines
            continue
        if "Your location:" in line:
            # If we already have mob info, save the combined entry
            if current_mob_info and current_location:
                combined_entries.append((current_mob_info, current_location))
            current_location = line  # Start a new location
            current_mob_info = []  # Reset mob info
        else:
            # Append any non-location lines to mob info
            current_mob_info.append(line)

    # Add the last entry if we have leftover data
    if current_mob_info and current_location:
        combined_entries.append((current_mob_info, current_location))

    mob_data = []

    for mob_info, location_line in combined_entries:
        match_location = location_pattern.search(location_line)
        if not match_location:
            continue
        location = match_location.groups()  # Extract X, Y, Z

        # Combine all mob-related lines into a single string
        mob_info_text = " ".join(mob_info)
        match_mob = mob_pattern.search(mob_info_text)

        if match_mob:
            mob_name = match_mob.group(1)
            new_entry = (mob_name, *location)

            if is_unique(existing_entries, new_entry, threshold):
                mob_data.append(new_entry)
                existing_entries.append(new_entry)
                writer.writerow(new_entry)  # Write immediately
                log_message(f"Mob Data Captured: {new_entry}")

    return mob_data


def monitor_screen():
    """Monitor the selected screen region for changes."""
    global stop_monitoring, node_csv_file, mob_csv_file

    if enable_node_tracking and not node_csv_file:
        messagebox.showerror("Error", "Node CSV file is not set.")
        return
    if enable_mob_tracking and not mob_csv_file:
        messagebox.showerror("Error", "Mob CSV file is not set.")
        return

    confirm_files = []
    if enable_node_tracking:
        confirm_files.append(f"Node CSV: {node_csv_file}")
    if enable_mob_tracking:
        confirm_files.append(f"Mob CSV: {mob_csv_file}")

    if confirm_files:
        if not messagebox.askyesno("Confirm File Usage", "\n".join(confirm_files)):
            return

    stop_monitoring = False
    node_entries = []
    mob_entries = []

    log_message("Monitoring started.")  # Start message

    with open(node_csv_file, mode="a", newline="") as node_file, open(mob_csv_file, mode="a", newline="") as mob_file:
        node_writer = csv.writer(node_file)
        mob_writer = csv.writer(mob_file)

        try:
            while not stop_monitoring:
                screenshot = pyautogui.screenshot(region=(monitor_region["left"], monitor_region["top"],
                                                          monitor_region["width"], monitor_region["height"]))
                text = pytesseract.image_to_string(screenshot, config="--psm 6", output_type=Output.STRING)

                # Node Tracking
                if enable_node_tracking:
                    node_data = process_text(text, node_entries)
                    for row in node_data:
                        node_writer.writerow(row)
                        log_message(f"Node Data Captured: {row}")
                        if enable_api_upload:
                            upload_to_api(row[0], float(row[1]), float(row[2]), float(row[3]))

                # Mob Tracking
                if enable_mob_tracking:
                    process_mob_data(text, mob_entries, mob_writer)  # Write immediately

                time.sleep(1)

        except Exception as e:
            log_message(f"An error occurred: {e}")

        finally:
            log_message("Monitoring stopped.")  # Stop message


def start_monitoring_thread():
    """Start monitoring in a separate thread."""
    monitoring_thread = threading.Thread(target=monitor_screen)
    monitoring_thread.daemon = True
    monitoring_thread.start()


def stop_monitor():
    """Signal to stop monitoring."""
    global stop_monitoring
    stop_monitoring = True


def select_region():
    """Allow the user to specify the region by clicking two points."""
    global monitor_region

    def on_click(x, y, button, pressed):
        """Handle mouse clicks."""
        if pressed:
            recorded_positions.append((x, y))
            if len(recorded_positions) == 1:
                log_message("Click on the bottom-right corner of the region.")
            elif len(recorded_positions) == 2:
                finalize_region()

    def finalize_region():
        """Calculate the region and show the final confirmation."""
        top_left = recorded_positions[0]
        bottom_right = recorded_positions[1]
        left = min(top_left[0], bottom_right[0])
        top = min(top_left[1], bottom_right[1])
        right = max(top_left[0], bottom_right[0])
        bottom = max(top_left[1], bottom_right[1])

        global monitor_region
        monitor_region = {
            "top": top,
            "left": left,
            "width": right - left,
            "height": bottom - top,
        }
        log_message(f"Region selected: {monitor_region}")
        listener.stop()
        save_config()  # Save the new monitor region

    log_message("Click on the top-left corner of the region.")
    recorded_positions = []
    listener = Listener(on_click=on_click)
    listener.start()


def save_api_key():
    """Save the API key from the input field."""
    global api_key
    api_key = api_key_entry.get()
    log_message("API key updated.")
    save_config()  # Save the updated API key


def create_gui():
    """Create the GUI for the application."""
    global root, info_window, api_key_entry, enable_api_upload, enable_node_tracking, enable_mob_tracking

    root = tk.Tk()
    root.title("Node Tracker")

    # Read config values as Python booleans
    enable_api_upload_value = config.getboolean("Settings", "EnableAPIUpload", fallback=False)
    enable_node_tracking_value = config.getboolean("Settings", "EnableNodeTracking", fallback=True)
    enable_mob_tracking_value = config.getboolean("Settings", "EnableMobTracking", fallback=False)

    # Initialize BooleanVars
    enable_api_upload = tk.BooleanVar(value=enable_api_upload_value)
    enable_node_tracking = tk.BooleanVar(value=enable_node_tracking_value)
    enable_mob_tracking = tk.BooleanVar(value=enable_mob_tracking_value)

    tab_control = ttk.Notebook(root)
    main_tab = ttk.Frame(tab_control)
    settings_tab = ttk.Frame(tab_control)

    tab_control.add(main_tab, text="Main")
    tab_control.add(settings_tab, text="Settings")
    tab_control.pack(expand=1, fill="both")

    # Main Tab
    tk.Label(main_tab, text="Pantheon Node Tracker", font=("Arial", 16)).pack(pady=10)

    tk.Button(main_tab, text="Select Region", command=select_region, width=20).pack(pady=5)
    tk.Button(main_tab, text="Start Monitoring", command=start_monitoring_thread, width=20).pack(pady=5)
    tk.Button(main_tab, text="Stop Monitoring", command=stop_monitor, width=20).pack(pady=5)
    tk.Button(main_tab, text="Exit", command=root.quit, width=20).pack(pady=5)

    info_window = scrolledtext.ScrolledText(main_tab, width=50, height=15, wrap=tk.WORD)
    info_window.pack(pady=10)
    info_window.insert(tk.END, "Welcome to the Node Tracking Tool!\n")

    # Flush any log messages queued before GUI was initialized
    flush_log_queue()

    # Settings Tab
    create_settings_tab(settings_tab)

    root.mainloop()


def create_settings_tab(tab):
    """Create the settings tab in the GUI."""
    global api_key_entry

    tk.Label(tab, text="API Key", font=("Arial", 12)).pack(pady=5)
    api_key_entry = tk.Entry(tab, width=40, show="*")
    api_key_entry.insert(0, api_key)
    api_key_entry.pack(pady=5)
    tk.Button(tab, text="Save API Key", command=save_api_key).pack(pady=10)

    # Toggles
    tk.Label(tab, text="Feature Toggles", font=("Arial", 12)).pack(pady=5)
    tk.Checkbutton(
        tab, text="Enable API Upload", variable=enable_api_upload,
        command=lambda: save_config()
    ).pack(pady=5)
    tk.Checkbutton(
        tab, text="Enable Node Tracking", variable=enable_node_tracking,
        command=lambda: save_config()
    ).pack(pady=5)
    tk.Checkbutton(
        tab, text="Enable Mob Tracking", variable=enable_mob_tracking,
        command=lambda: save_config()
    ).pack(pady=5)

    # File Locations
    tk.Label(tab, text="File Locations", font=("Arial", 12)).pack(pady=5)
    tk.Button(tab, text="Set Node CSV File", command=lambda: set_file_location("node")).pack(pady=5)
    tk.Button(tab, text="Set Mob CSV File", command=lambda: set_file_location("mob")).pack(pady=5)


if __name__ == "__main__":
    setup_tesseract()
    load_config()  # Load configuration on startup
    create_gui()
