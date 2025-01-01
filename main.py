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

# Patterns for nodes, mobs, and zones
item_patterns = [
    re.compile(r"You finished cutting down (.+?)\."),
    re.compile(r"You finished mining (.+?)\."),
    re.compile(r"You finished harvesting (.+?)\."),
]
mob_pattern = re.compile(r"^(?!You\b)(.+?) (?:is .*?|eyes you.*?|acknowledges you.*?|can.*?|observes you.*?)\.")

location_pattern = re.compile(r"Your location:\s([\d.-]+)\s([\d.-]+)\s([\d.-]+)")

zone_pattern = re.compile(r"You are in (.+)\.")

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
enable_loc_auto_click = False
loc_button_coords = None
last_loc_click_time = 0
screenshot_rate = 5

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
    global config, api_key, monitor_region, node_csv_file, mob_csv_file, enable_loc_auto_click, loc_button_coords, screenshot_rate

    if os.path.exists(config_file):
        config.read(config_file)
        api_key = config.get("Settings", "APIKey", fallback="")
        monitor_region_str = config.get("Settings", "MonitorRegion", fallback="")
        node_csv_file = config.get("Settings", "NodeCSVFile", fallback="")
        mob_csv_file = config.get("Settings", "MobCSVFile", fallback="")
        enable_loc_auto_click = config.getboolean("Settings", "EnableLocAutoClick", fallback=False)
        loc_button_coords = eval(config.get("Settings", "LocButtonCoords", fallback="None"))
        screenshot_rate = config.getint("Settings", "ScreenshotRate", fallback=5)  # Default to 5 per second

        if monitor_region_str:
            try:
                global monitor_region
                monitor_region = eval(monitor_region_str)
                log_message(f"Loaded monitor region: {monitor_region}")
            except Exception as e:
                log_message(f"Failed to load monitor region: {e}")
                monitor_region = None


def save_config():
    global api_key, monitor_region, node_csv_file, mob_csv_file, enable_loc_auto_click, loc_button_coords, screenshot_rate

    config["Settings"] = {
        "APIKey": api_key,
        "MonitorRegion": str(monitor_region) if monitor_region else "",
        "NodeCSVFile": node_csv_file,
        "MobCSVFile": mob_csv_file,
        "EnableAPIUpload": str(enable_api_upload.get()),
        "EnableNodeTracking": str(enable_node_tracking.get()),
        "EnableMobTracking": str(enable_mob_tracking.get()),
        "EnableLocAutoClick": str(enable_loc_auto_click),
        "LocButtonCoords": str(loc_button_coords),
        "ScreenshotRate": str(screenshot_rate),  # Save screenshot rate
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


def toggle_loc_auto_click(value):
    """Toggle the Loc Auto Click feature based on the checkbox."""
    global enable_loc_auto_click
    enable_loc_auto_click = value.get()  # Extract the boolean value from the Tkinter variable
    log_message(f"Loc Auto Click toggled to: {enable_loc_auto_click}")
    save_config()  # Save the updated state to the config file


def set_loc_button_location():
    global loc_button_coords

    def on_click(x, y, button, pressed):
        if pressed:
            global loc_button_coords
            loc_button_coords = (x, y)
            log_message(f"/loc button location set to: {loc_button_coords}")
            save_config()
            listener.stop()

    log_message("Click on the /loc button to set its location.")
    listener = Listener(on_click=on_click)
    listener.start()


def adjust_screenshot_rate(value):
    """Adjust the number of screenshots taken per second and save to config."""
    global screenshot_rate
    screenshot_rate = value
    log_message(f"Screenshot rate set to: {screenshot_rate} per second")
    save_config()  # Save the updated rate to the config file


def loc_auto_click():
    global last_loc_click_time, loc_button_coords

    if not enable_loc_auto_click or not loc_button_coords:
        log_message("Loc auto click is disabled or button location is not set.")
        return

    current_time = time.time()
    if current_time - last_loc_click_time >= 3:  # Ensure 3 seconds between clicks
        pyautogui.click(loc_button_coords)
        last_loc_click_time = current_time
        log_message("/loc button clicked automatically.")
    else:
        log_message("Cooldown active. Skipping loc click.")


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

    try:
        # Ensure these are valid floats
        loc_x = float(x)
        loc_y = float(y)
        loc_z = float(z)
    except (TypeError, ValueError) as e:
        log_message(f"Invalid coordinates detected: {e}. Skipping upload.")
        return

    # Construct the payload (zone name is not uploaded to the API)
    payload = {
        "resource": {
            "loc_x": loc_x,
            "loc_y": loc_y,
            "loc_z": loc_z,
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
    """Check if a new entry (mob name + coordinates) is unique."""
    new_item = new_entry[0]  # Mob name
    new_coords = new_entry[1:4]  # X, Y, Z (exclude zone name)

    for existing_item, *existing_coords, _ in existing_entries:  # Ignore zone in comparison
        if new_item == existing_item and all(
            abs(float(a) - float(b)) <= threshold
            for a, b in zip(existing_coords[:3], new_coords)  # Compare only X, Y, Z
        ):
            return False
    return True


def process_text(text, existing_entries, threshold=10):
    global enable_loc_auto_click

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    # log_message(f"Processing text: {lines}")  # Debug: log the extracted lines

    zone_name = None

    # Extract zone name (if available)
    for line in lines:
        match_zone = zone_pattern.search(line)
        if match_zone:
            zone_name = match_zone.group(1)

    data_pairs = []

    # Check if the last line matches the condition
    if lines and enable_loc_auto_click:
        last_line = lines[-1]
        # log_message(f"Last line for evaluation: {last_line}")
        if last_line.startswith("You finished"):
            log_message(f"Triggering loc auto click for last line: {last_line}")
            loc_auto_click()  # Trigger the /loc auto-click

    # Process other lines for data extraction
    for i in range(len(lines) - 1):
        item = None
        for pattern in item_patterns:
            match_item = pattern.search(lines[i])
            if match_item:
                item = match_item.group(1)
                break

        match_location = location_pattern.search(lines[i + 1]) if i < len(lines) - 1 else None

        if item and match_location:
            location = match_location.groups()
            new_entry = (item, *location, zone_name)
            if is_unique(existing_entries, new_entry, threshold):
                data_pairs.append(new_entry)
                existing_entries.append(new_entry)
    return data_pairs


def process_mob_data(text, existing_entries, writer, file_object, threshold=10):
    """Parse the text for mob data, deduplicate, and write immediately."""
    lines = text.splitlines()
    zone_name = None

    # Extract zone name (search all lines)
    for line in lines:
        match_zone = zone_pattern.search(line)
        if match_zone:
            zone_name = match_zone.group(1)

    mob_data = []
    current_location = None
    current_mob_info = []

    for line in lines:
        line = line.strip()  # Remove extra whitespace

        if not line:  # Skip blank lines
            continue

        # Match location
        match_location = location_pattern.search(line)
        if match_location:
            current_location = match_location.groups()
            continue
        # Match mob data
        match_mob = mob_pattern.search(line)
        if match_mob:
            mob_name = match_mob.group(1)
            if current_location:
                new_entry = (mob_name, *current_location, zone_name)  # Append zone name

                # Deduplicate entries
                if is_unique(existing_entries, new_entry, threshold):
                    mob_data.append(new_entry)
                    existing_entries.append(new_entry)
                    writer.writerow(new_entry)  # Write immediately
                    file_object.flush()  # Flush the file object to prevent data loss
                    #log_message(f"Mob Data Captured: {mob_name} at {current_location}")

    return mob_data


def monitor_screen():
    """Monitor the selected screen region for changes."""
    global stop_monitoring, node_csv_file, mob_csv_file, screenshot_rate

    if enable_node_tracking and not node_csv_file:
        messagebox.showerror("Error", "Node CSV file is not set.")
        return
    if enable_mob_tracking and not mob_csv_file:
        messagebox.showerror("Error", "Mob CSV file is not set.")
        return

    stop_monitoring = False
    node_entries = []
    mob_entries = []

    log_message("Monitoring started.")

    with open(node_csv_file, mode="a", newline="") as node_file, open(mob_csv_file, mode="a", newline="") as mob_file:
        node_writer = csv.writer(node_file)
        mob_writer = csv.writer(mob_file)

        # Write headers if the files are empty
        if os.stat(node_csv_file).st_size == 0:
            node_writer.writerow(["Node Name", "X", "Y", "Z", "Zone Name"])
        if os.stat(mob_csv_file).st_size == 0:
            mob_writer.writerow(["Mob Name", "X", "Y", "Z", "Zone Name"])

        try:
            while not stop_monitoring:
                start_time = time.time()

                # Take a screenshot of the monitored region
                screenshot = pyautogui.screenshot(region=(monitor_region["left"], monitor_region["top"],
                                                          monitor_region["width"], monitor_region["height"]))
                text = pytesseract.image_to_string(
                    screenshot,
                    config='--psm 6 --oem 3 -c tessedit_char_whitelist="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-:(),\' "',
                    output_type=Output.STRING
                )
                screenshot.close()
                del screenshot

                # Node Tracking
                if enable_node_tracking:
                    node_data = process_text(text, node_entries)
                    for row in node_data:
                        node_writer.writerow(row)  # Save zone name to CSV
                        node_file.flush()  # Flush node file to prevent data loss
                        log_message(f"Node Data Captured: {row}")
                        if enable_api_upload:
                            upload_to_api(row[0], row[1], row[2], row[3])  # Exclude zone

                # Mob Tracking
                if enable_mob_tracking:
                    mob_data = process_mob_data(text, mob_entries, mob_writer, mob_file)
                    for row in mob_data:
                        log_message(f"Mob Data Captured: {row}")
                        # No upload to API for mob data

                # Adjust for screenshot rate
                elapsed_time = time.time() - start_time
                sleep_time = max(0, 1 / screenshot_rate - elapsed_time)
                time.sleep(sleep_time)

        except Exception as e:
            log_message(f"An error occurred: {e}")

        finally:
            log_message("Monitoring stopped.")


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


def manual_test_loc_click():
    """Manual test for /loc button click functionality."""
    if loc_button_coords:
        log_message("Manually triggering /loc button click.")
        pyautogui.click(loc_button_coords)
    else:
        log_message("No /loc button location set. Please set it first.")


def create_gui():
    """Create the GUI for the application."""
    global root, info_window, api_key_entry, enable_api_upload, enable_node_tracking, enable_mob_tracking

    root = tk.Tk()
    root.title("Node Tracker")
    root.geometry("350x400")
    root.minsize(350, 400)

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

    tk.Button(main_tab, text="Select Region", command=select_region, width=20).pack(
        pady=5)
    tk.Button(main_tab, text="Start Monitoring", command=start_monitoring_thread,
              width=10).pack(pady=5)
    tk.Button(main_tab, text="Stop Monitoring", command=stop_monitor, width=10).pack(
        pady=5)
    tk.Button(main_tab, text="Exit", command=root.quit, width=10).pack(pady=5)

    info_window = scrolledtext.ScrolledText(main_tab, wrap=tk.WORD)
    info_window.pack(expand=True, fill='both', pady=10)  # Allow dynamic resizing
    info_window.insert(tk.END, "Welcome to the Node Tracking Tool!\n")

    # Flush any log messages queued before GUI was initialized
    flush_log_queue()

    # Settings Tab
    create_settings_tab(settings_tab)

    root.mainloop()


def create_settings_tab(tab_control):
    global api_key_entry, enable_loc_auto_click_var, screenshot_rate_var

    # Create a canvas and scrollbar
    settings_canvas = tk.Canvas(tab_control, width=350, height=400, highlightthickness=0)
    settings_scrollbar = tk.Scrollbar(tab_control, orient="vertical", command=settings_canvas.yview)
    settings_frame = ttk.Frame(settings_canvas)

    # Configure the scrollbar
    settings_canvas.configure(yscrollcommand=settings_scrollbar.set)
    settings_canvas.create_window((0, 0), window=settings_frame, anchor="nw")

    # Bind mouse wheel scrolling
    def on_mouse_wheel(event):
        settings_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    settings_canvas.bind_all("<MouseWheel>", on_mouse_wheel)  # Windows and MacOS
    settings_canvas.bind_all("<Button-4>", on_mouse_wheel)   # Linux scroll up
    settings_canvas.bind_all("<Button-5>", on_mouse_wheel)   # Linux scroll down

    # Adjust scroll region dynamically
    settings_frame.bind(
        "<Configure>", lambda e: settings_canvas.configure(scrollregion=settings_canvas.bbox("all"))
    )

    settings_canvas.pack(side="left", fill="both", expand=True)
    settings_scrollbar.pack(side="right", fill="y")

    # Add settings widgets to the settings frame
    tk.Label(settings_frame, text="API Key", font=("Arial", 12)).pack(pady=5)
    api_key_entry = tk.Entry(settings_frame, width=40, show="*")
    api_key_entry.insert(0, api_key)
    api_key_entry.pack(pady=5)
    tk.Button(settings_frame, text="Save API Key", command=save_api_key).pack(pady=10)

    # Toggles
    tk.Label(settings_frame, text="Feature Toggles", font=("Arial", 12)).pack(pady=5)
    enable_loc_auto_click_var = tk.BooleanVar(value=enable_loc_auto_click)  # Sync with loaded config
    tk.Checkbutton(
        settings_frame, text="Enable API Upload", variable=enable_api_upload,
        command=lambda: save_config()
    ).pack(pady=5)
    tk.Checkbutton(
        settings_frame, text="Enable Node Tracking", variable=enable_node_tracking,
        command=lambda: save_config()
    ).pack(pady=5)
    tk.Checkbutton(
        settings_frame, text="Enable Mob Tracking", variable=enable_mob_tracking,
        command=lambda: save_config()
    ).pack(pady=5)
    tk.Checkbutton(
        settings_frame, text="Enable Loc Auto Click", variable=enable_loc_auto_click_var,
        command=lambda: toggle_loc_auto_click(enable_loc_auto_click_var)
    ).pack(pady=5)

    # Screenshot Rate Slider
    tk.Label(settings_frame, text="Screenshots per Second", font=("Arial", 12)).pack(pady=5)
    screenshot_rate_var = tk.IntVar(value=screenshot_rate)  # Sync slider with loaded config
    tk.Scale(
        settings_frame, from_=1, to=30, orient="horizontal",
        variable=screenshot_rate_var,
        command=lambda val: adjust_screenshot_rate(int(val))
    ).pack(pady=5)

    # File Locations
    tk.Label(settings_frame, text="File Locations", font=("Arial", 12)).pack(pady=5)
    tk.Button(settings_frame, text="Set Node CSV File", command=lambda: set_file_location("node")).pack(pady=5)
    tk.Button(settings_frame, text="Set Mob CSV File", command=lambda: set_file_location("mob")).pack(pady=5)

    # Loc Button Location
    tk.Label(settings_frame, text="/loc Button", font=("Arial", 12)).pack(pady=5)
    tk.Button(settings_frame, text="Set /loc Button Location", command=set_loc_button_location).pack(pady=5)
    tk.Button(settings_frame, text="Test /loc Button Click", command=manual_test_loc_click).pack(pady=5)


if __name__ == "__main__":
    setup_tesseract()
    load_config()  # Load configuration on startup
    create_gui()
