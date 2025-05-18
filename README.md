<img src="https://github.com/teacupuk/multiviewer/blob/main/app_icon.png?raw=true" alt="logo" width="100"/>

# Multiviewer

**Multiviewer** is a cross-platform multicast testing application with a modern PyQt GUI. It allows you to listen to multicast streams, visualize incoming packet sources, and route them to standard output, log files, or directly into VLC for playback.

---

## ✨ Features

- 🖥️ **GUI-based multicast listener** using PyQt5
- 📡 Listen to user-defined multicast groups and ports
- 🔌 Select specific local interface IP for joining multicast
- 🔊 Output options:
  - Standard Output
  - Log File
  - VLC (for real-time playback)
- 📚 Address Book for saving and loading multicast stream configurations
- 📊 Packet Visualizer tab showing live per-IP packet stats
- ⚙️ Configurable settings (VLC path, log path, OS-specific defaults)

---

## 🛠️ Installation

### Prerequisites

- Python 3.8+
- VLC Media Player (if using VLC output)
- Recommended: Create and activate a virtual environment

### Requirements

Install Python dependencies:

```bash
pip install -r requirements.txt
```

### Build as macOS App (optional)

To build the app as a standalone macOS application using `py2app`, use the provided `setup.py` script:

```bash
pip install py2app
python setup.py py2app
```

This will generate a `.app` bundle inside the `dist` directory. The app will include:

- Application icon (`app_icon.png`)
- Settings and address book files
- Required modules (`psutil`, `PyQt5`, etc.)

Make sure you are running this on macOS with Python 3 and the required dependencies installed.

---

## 🚀 Usage

```bash
python multiviewer.py
```

### Main Interface

- **Multicast Group / Port** – Define the target stream.
- **Interface IP** – Select which interface to bind to.
- **Output Mode** – Choose between VLC, stdout, or log file.

### Tabs

- **Log** – Displays live received data or messages.
- **Packet Visualizer** – Aggregated stats by source IP (packet count and byte size).

---

## 📁 Configuration Files

- `settings.json` – Stores user preferences like VLC path, output mode, etc.
- `address_book.json` – Holds saved multicast targets for quick access.

Both are automatically created and managed through the GUI.

---

## 📓 Address Book

Use the **Address Book** button to add, edit, or delete multicast targets (name, group IP, port). Double-click any entry to load it into the main form.

---

## ⚙️ Settings

Use the **Settings** dialog to configure:

- Address book file path
- Log file location
- OS (used for default VLC path)
- VLC executable path

---

## 🧪 Example Usage

- Stream from `239.0.0.1:5004` on interface `192.168.1.10`
- Route packets to VLC for real-time audio/video

---

## 🧹 Logs and Output

- Log output appears in the Log tab.
- If "Log File" output is selected, messages are written to the path specified in Settings.
- VLC output is streamed directly via stdin to VLC.

---

## 🧩 Known Limitations

- VLC streaming assumes uncompressed UDP-compatible input.
- VLC executable must be explicitly set if not on standard path.
- Only supports IPv4 multicast.

---

## 🧑‍💻 Developer Notes

To extend or contribute, see:

- `MulticastListenerApp` – Main window and core logic
- `SettingsDialog`, `AddressBookDialog` – GUI components
- `PacketVisualizerTab` – Live per-IP traffic statistics

---

## 📜 License

GPL-3.0 License. See `LICENSE` file for details.
