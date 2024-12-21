# node_tracker.py
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
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

# Updated item patterns
item_patterns = [
    re.compile(r"You finished cutting down (.+?)\."),
    re.compile(r"You finished mining (.+?)\."),
    re.compile(r"You finished harvesting (.+?)\."),
]
location_pattern = re.compile(r"Your location:\s([\d.-]+)\s([\d.-]+)\s([\d.-]+)\s([\d.-]+)")

# Global variables
monitor_region = None
csv_file = "collected_data.csv"
stop_monitoring = False


def setup_tesseract():
    """Configure pytesseract to use the embedded Tesseract binary."""
    # Detect if running under PyInstaller
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(__file__)

    # Windows vs. Linux binary
    if sys.platform.startswith("win"):
        tesseract_binary = os.path.join(base_path, "tesseract", "bin",
                                        "tesseract.exe")
    elif sys.platform.startswith("linux"):
        tesseract_binary = os.path.join(base_path, "tesseract", "bin",
                                        "tesseract")
    else:
        # Fallback or handle Mac if needed
        tesseract_binary = "tesseract"

    # If you included tessdata, point TESSDATA_PREFIX to it
    tessdata_folder = os.path.join(base_path, "tesseract", "tessdata")
    if os.path.exists(tessdata_folder):
        os.environ["TESSDATA_PREFIX"] = os.path.join(base_path, "tesseract")

    pytesseract.pytesseract.tesseract_cmd = tesseract_binary


def log_message(message):
    """Add a message to the scrolling info window."""
    info_window.insert(tk.END, f"{message}\n")
    info_window.see(tk.END)  # Scroll to the latest entry


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

    log_message("Click on the top-left corner of the region.")
    recorded_positions = []
    listener = Listener(on_click=on_click)
    listener.start()


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


def monitor_screen():
    """Monitor the selected screen region for changes."""
    global stop_monitoring, csv_file

    # Ask user where to save the CSV file
    csv_file = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv")],
    )
    if not csv_file:
        return  # User canceled

    is_new_file = not os.path.exists(csv_file)
    stop_monitoring = False
    existing_entries = []

    # Read existing entries if file already exists
    if not is_new_file:
        with open(csv_file, mode="r") as file:
            reader = csv.reader(file)
            try:
                header = next(reader)
            except StopIteration:
                header = None
            for row in reader:
                if row:  # Avoid blank rows
                    existing_entries.append(row)

    with open(csv_file, mode="a", newline="") as file:
        writer = csv.writer(file)
        if is_new_file:
            writer.writerow(["Item", "X", "Y", "Z"])

        try:
            while not stop_monitoring:
                screenshot = pyautogui.screenshot(
                    region=(
                        monitor_region["left"],
                        monitor_region["top"],
                        monitor_region["width"],
                        monitor_region["height"],
                    )
                )

                # Extract text
                text = pytesseract.image_to_string(
                    screenshot, config="--psm 6", output_type=Output.STRING
                )

                # Parse text
                data = process_text(text, existing_entries, threshold=10)
                for row in data:
                    writer.writerow(row)
                    file.flush()
                    log_message(f"Data captured: {row}")

                time.sleep(1)
            log_message("Monitoring stopped.")
        except Exception as e:
            log_message(f"An error occurred: {e}")


def start_monitoring_thread():
    """Start monitoring in a separate thread."""
    monitoring_thread = threading.Thread(target=monitor_screen)
    monitoring_thread.daemon = True
    monitoring_thread.start()


def stop_monitor():
    """Signal to stop monitoring."""
    global stop_monitoring
    stop_monitoring = True


def create_gui():
    """Create the GUI for the application."""
    global root, info_window
    root = tk.Tk()
    root.title("Node Tracker")

    tk.Label(root, text="Pantheon Node Tracker", font=("Arial", 16)).pack(pady=10)

    tk.Button(
        root, text="Select Region", command=select_region, width=20
    ).pack(pady=5)
    tk.Button(
        root, text="Start Monitoring", command=start_monitoring_thread, width=20
    ).pack(pady=5)
    tk.Button(root, text="Stop Monitoring", command=stop_monitor, width=20).pack(
        pady=5
    )
    tk.Button(root, text="Exit", command=root.quit, width=20).pack(pady=5)

    info_window = scrolledtext.ScrolledText(root, width=50, height=15,
                                            wrap=tk.WORD)
    info_window.pack(pady=10)
    info_window.insert(tk.END, "Welcome to the Node Tracking Tool!\n")

    root.mainloop()


if __name__ == "__main__":
    # IMPORTANT: Call setup_tesseract() so pytesseract knows where the
    # embedded Tesseract is located (either Windows or Linux).
    setup_tesseract()
    create_gui()
