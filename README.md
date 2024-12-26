# Pantheon Node & Mob Tracker

A Python-based tool for tracking resource nodes and mob locations in Pantheon using OCR and in-game macros. The script captures in-game data displayed on your screen and organizes it into CSV files. Additionally, it provides the option to upload resource node data to a REST API.

---

## Features

- **Node Tracking**: Captures harvested node data (e.g., wood, minerals) with location coordinates.
- **Mob Tracking**: Records mob locations in the game world.
- **CSV Output**: Saves node and mob data into separate CSV files.
- **API Upload**: Optionally uploads node data to a configurable API.
- **Configurable**: Settings such as monitor region, API key, and CSV file locations are saved in a configuration file for easy reloading.
- **GUI Interface**: User-friendly interface for setting up, starting, and stopping the tracking process.

---

## Requirements

### Software
- Python 3.8+
- `pytesseract` (Tesseract OCR)
- `pynput` (for mouse input)
- `pyautogui` (for screenshots)
- `Pillow` (for image processing)
- `requests` (for API interaction)

### Tesseract OCR
Make sure Tesseract is installed and accessible on your system:
- **Windows**: [Download Tesseract](https://github.com/UB-Mannheim/tesseract/wiki)
- **Linux**: Install via your package manager (e.g., `sudo apt install tesseract-ocr`).

---

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/yourusername/pantheon-tracker.git
   cd pantheon-tracker
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Setup Tesseract**:
   - Ensure Tesseract is installed.
   - Update the `setup_tesseract` function in `main.py` if Tesseract's path differs on your system.

---

## Usage

### GUI Interface

1. **Run the Script**:
   ```bash
   python main.py
   ```

2. **Select Region**:
   - Click the "Select Region" button in the GUI.
   - Click the top-left and bottom-right corners of the area where the game displays `Your location` and mob/node messages.

3. **Set File Locations**:
   - Use the Settings tab to specify CSV file paths for node and mob data.

4. **Enable/Disable Features**:
   - Use the checkboxes in the Settings tab to enable or disable API uploads, node tracking, and mob tracking.

5. **Start Monitoring**:
   - Click "Start Monitoring" to begin capturing data.

6. **Stop Monitoring**:
   - Click "Stop Monitoring" to end data capture.

---

## Configuration File

The script generates a `config.ini` file to save your settings, such as:
- **API Key**: For uploading node data to an API.
- **Monitor Region**: The selected screen region for OCR.
- **File Paths**: Paths for node and mob CSV files.
- **Feature Toggles**: Enable or disable API upload, node tracking, or mob tracking.

---

## In-Game Macro Setup

### For Mob Tracking:
Create a macro in-game:
```plaintext
/loc
/con
/loc
```

### For Node Harvesting:
Use a simple macro:
```plaintext
/loc
```

---

## API Integration

### Endpoint
- **URL**: `https://shalazam.info/api/v1/resources`
- **Method**: `POST`
- **Authorization**: Use an API key in the `Authorization` header.

### Payload
```json
{
    "resource": {
        "loc_x": 3000,
        "loc_y": 2000,
        "loc_z": 500,
        "name": "Apple Tree"
    }
}
```

---

## Example Output

### Node Data (`nodes.csv`)
| Item          | X      | Y      | Z      |
|---------------|--------|--------|--------|
| Apple Tree    | 3230.8 | 472.39 | 3672.02|

### Mob Data (`mobs.csv`)
| Mob Name               | X      | Y      | Z      |
|------------------------|--------|--------|--------|
| Fire Beetle Hatchling  | 3230.8 | 472.39 | 3672.02|

---

## Troubleshooting

- **Tesseract Not Found**:
  - Ensure Tesseract OCR is installed and its path is configured correctly in the `setup_tesseract` function.

- **Duplicate Entries**:
  - The script checks for duplicates using a threshold of ±10 units in coordinates.

- **Screen Region Issues**:
  - Use the "Select Region" feature to set the correct OCR area.

---

## Contributions

Feel free to submit issues or pull requests to improve this project.

---

## License

This project is licensed under the MIT License.
