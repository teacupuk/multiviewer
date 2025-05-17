import socket
import struct
import subprocess
import threading
import psutil
import json
import os

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QRadioButton,
    QPushButton, QTextEdit, QVBoxLayout, QHBoxLayout,
    QFormLayout, QComboBox, QDialog, QListWidget, QInputDialog,
    QGroupBox, QFileDialog, QTabWidget, QTableWidget, QTableWidgetItem
)
from datetime import datetime
from collections import defaultdict

ADDRESS_BOOK_FILE = "address_book.json"
SETTINGS_FILE = "settings.json"
MAX_LOG_LINES = 1000

def get_private_ip_addresses():
    private_ips = []
    for iface_name, iface_addrs in psutil.net_if_addrs().items():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET:
                ip = addr.address
                if ip.startswith("10.") or ip.startswith("172.") or ip.startswith("192.168."):
                    private_ips.append(ip)
    return private_ips

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

class PacketVisualizerTab(QWidget):
    def __init__(self):
        super().__init__()

        self.packet_data = defaultdict(lambda: {'count': 0, 'bytes': 0})  # Store packets per source IP
        self.initUI()

    def initUI(self):
        self.setLayout(QVBoxLayout())

        # Table to display packet data
        self.packet_table = QTableWidget(self)
        self.packet_table.setColumnCount(3)
        self.packet_table.setHorizontalHeaderLabels(["Source IP", "Packets", "Bytes"])
        self.layout().addWidget(self.packet_table)

        # Refresh button
        refresh_button = QPushButton("Refresh", self)
        refresh_button.clicked.connect(self.refresh_table)
        self.layout().addWidget(refresh_button)

    def update_table(self, source_ip, packet_size):
        """Update packet data with new packet info"""
        if source_ip in self.packet_data:
            self.packet_data[source_ip]['count'] += 1
            self.packet_data[source_ip]['bytes'] += packet_size
        else:
            self.packet_data[source_ip] = {'count': 1, 'bytes': packet_size}
        self.refresh_table()

    def refresh_table(self):
        """Refresh the table with updated packet data"""
        self.packet_table.setRowCount(len(self.packet_data))  # Set the number of rows

        row = 0
        for source_ip, data in self.packet_data.items():
            self.packet_table.setItem(row, 0, QTableWidgetItem(source_ip))
            self.packet_table.setItem(row, 1, QTableWidgetItem(str(data['count'])))
            self.packet_table.setItem(row, 2, QTableWidgetItem(str(data['bytes'])))
            row += 1

class AddressBookDialog(QDialog):
    def __init__(self, parent, load_callback):
        super().__init__(parent)
        self.setWindowTitle("Address Book")
        self.load_callback = load_callback
        self.layout = QVBoxLayout()
        self.address_list = QListWidget()
        self.layout.addWidget(self.address_list)

        btn_layout = QHBoxLayout()
        self.add_btn = QPushButton("Add")
        self.edit_btn = QPushButton("Edit")
        self.delete_btn = QPushButton("Delete")

        btn_layout.addWidget(self.add_btn)
        btn_layout.addWidget(self.edit_btn)
        btn_layout.addWidget(self.delete_btn)
        self.layout.addLayout(btn_layout)

        self.setLayout(self.layout)

        self.add_btn.clicked.connect(self.add_entry)
        self.edit_btn.clicked.connect(self.edit_entry)
        self.delete_btn.clicked.connect(self.delete_entry)
        self.address_list.itemDoubleClicked.connect(self.load_entry)

        self.load_address_book()

    def load_address_book(self):
        self.address_list.clear()
        if os.path.exists(ADDRESS_BOOK_FILE):
            with open(ADDRESS_BOOK_FILE, "r") as f:
                self.entries = json.load(f)
                # Sort entries alphabetically by name
                self.entries.sort(key=lambda entry: entry['name'].lower())
                for entry in self.entries:
                    self.address_list.addItem(f"{entry['name']} ({entry['group']}:{entry['port']})")
        else:
            self.entries = []

    def save_address_book(self):
        with open(ADDRESS_BOOK_FILE, "w") as f:
            json.dump(self.entries, f, indent=2)

    def add_entry(self):
        name, ok1 = QInputDialog.getText(self, "Add Entry", "Name:")
        if not ok1 or not name:
            return
        group, ok2 = QInputDialog.getText(self, "Add Entry", "Group IP:")
        if not ok2 or not group:
            return
        port, ok3 = QInputDialog.getInt(self, "Add Entry", "Port:", 5004, 1, 65535)
        if not ok3:
            return
        self.entries.append({"name": name, "group": group, "port": port})
        # Sort after adding an entry
        self.entries.sort(key=lambda entry: entry['name'].lower())
        self.save_address_book()
        self.load_address_book()

    def edit_entry(self):
        row = self.address_list.currentRow()
        if row < 0:
            return
        entry = self.entries[row]
        name, ok1 = QInputDialog.getText(self, "Edit Entry", "Name:", text=entry["name"])
        if not ok1 or not name:
            return
        group, ok2 = QInputDialog.getText(self, "Edit Entry", "Group IP:", text=entry["group"])
        if not ok2 or not group:
            return
        port, ok3 = QInputDialog.getInt(self, "Edit Entry", "Port:", value=entry["port"])
        if not ok3:
            return
        self.entries[row] = {"name": name, "group": group, "port": port}
        # Sort after editing an entry
        self.entries.sort(key=lambda entry: entry['name'].lower())
        self.save_address_book()
        self.load_address_book()

    def delete_entry(self):
        row = self.address_list.currentRow()
        if row >= 0:
            del self.entries[row]
            # Sort after deleting an entry
            self.entries.sort(key=lambda entry: entry['name'].lower())
            self.save_address_book()
            self.load_address_book()

    def load_entry(self, item):
        index = self.address_list.currentRow()
        if index >= 0:
            entry = self.entries[index]
            self.load_callback(entry["group"], entry["port"])
            self.accept()

class SettingsDialog(QDialog):
    def __init__(self, current_settings, on_save_callback):
        super().__init__()
        self.setWindowTitle("Settings")
        self.resize(400, 100)
        self.settings = current_settings
        self.on_save_callback = on_save_callback

        layout = QFormLayout()

        # Address Book
        self.address_book_path_edit = QLineEdit(self.settings.get("address_book_path", "address_book.json"))
        ab_browse_btn = QPushButton("Browse")
        ab_browse_btn.clicked.connect(self.browse_file)
        ab_layout = QHBoxLayout()
        ab_layout.addWidget(self.address_book_path_edit)
        ab_layout.addWidget(ab_browse_btn)
        layout.addRow("Address Book File:", ab_layout)

        # Log File
        self.log_file_path_edit = QLineEdit(self.settings.get("log_file_path", "listener.log"))
        log_browse_btn = QPushButton("Browse")
        log_browse_btn.clicked.connect(self.browse_log_file)
        log_layout = QHBoxLayout()
        log_layout.addWidget(self.log_file_path_edit)
        log_layout.addWidget(log_browse_btn)
        layout.addRow("Log File:", log_layout)

        # OS Selector
        self.os_combo = QComboBox()
        self.os_combo.addItems(["Windows", "macOS", "Linux"])
        self.os_combo.setCurrentText(self.settings.get("os", "Windows"))
        self.os_combo.currentTextChanged.connect(self.set_default_vlc_path)
        layout.addRow("Operating System:", self.os_combo)

        # VLC Path
        self.vlc_path_edit = QLineEdit(self.settings.get("vlc_path", ""))
        vlc_browse_btn = QPushButton("Browse")
        vlc_browse_btn.clicked.connect(self.browse_vlc_file)
        vlc_layout = QHBoxLayout()
        vlc_layout.addWidget(self.vlc_path_edit)
        vlc_layout.addWidget(vlc_browse_btn)
        layout.addRow("VLC Executable Path:", vlc_layout)

        save_button = QPushButton("Save")
        save_button.clicked.connect(self.save_settings)
        layout.addRow(save_button)

        self.setLayout(layout)

        # Set initial VLC path if not already set
        if not self.vlc_path_edit.text():
            self.set_default_vlc_path(self.os_combo.currentText())

    def browse_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Select Address Book File", "", "JSON Files (*.json)")
        if path:
            self.address_book_path_edit.setText(path)

    def browse_log_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Select Log File", "", "Log Files (*.log);;All Files (*)")
        if path:
            self.log_file_path_edit.setText(path)

    def browse_vlc_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select VLC Executable")
        if path:
            self.vlc_path_edit.setText(path)

    def set_default_vlc_path(self, os_name):
        default_paths = {
            "Windows": "C:\\Program Files\\VideoLAN\\VLC\\vlc.exe",
            "macOS": "/Applications/VLC.app/Contents/MacOS/VLC",
            "Linux": "/usr/bin/vlc"
        }
        self.vlc_path_edit.setText(default_paths.get(os_name, ""))

    def save_settings(self):
        self.settings["address_book_path"] = self.address_book_path_edit.text()
        self.settings["log_file_path"] = self.log_file_path_edit.text()
        self.settings["os"] = self.os_combo.currentText()
        self.settings["vlc_path"] = self.vlc_path_edit.text()
        save_settings(self.settings)
        self.on_save_callback(self.settings)
        self.accept()

class MulticastListenerApp(QWidget):
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.settings = load_settings()
        self.address_book_path = self.settings.get("address_book_path", "address_book.json")
        self.group = self.settings.get("group", '239.0.0.1')  # Load saved group or default
        self.port = self.settings.get("port", 5004)  # Load saved port or default
        self.output = self.settings.get("output", 'stdout')  # Load saved output or default
        self.interface_ip = '0.0.0.0'
        self.listener_thread = None
        self.listener_running = False
        self.initUI()

        # Connect the signal to the update_log slot
        self.log_signal.connect(self.update_log)

    def initUI(self):
        self.setWindowTitle("Multicast Listener")
        self.setGeometry(100, 100, 600, 500)

        main_layout = QVBoxLayout()

        # Multicast Configuration Group
        multicast_group = QGroupBox("Multicast Configuration", self)
        multicast_layout = QFormLayout()

        self.group_entry = QLineEdit(self.group)
        multicast_layout.addRow("Multicast Group:", self.group_entry)

        self.port_entry = QLineEdit(str(self.port))
        multicast_layout.addRow("Port:", self.port_entry)

        self.interface_selector = QComboBox()
        private_ips = get_private_ip_addresses()
        if not private_ips:
            private_ips = ['0.0.0.0']
        self.interface_selector.addItems(private_ips)
        multicast_layout.addRow("Interface IP:", self.interface_selector)

        multicast_group.setLayout(multicast_layout)
        main_layout.addWidget(multicast_group)

        # Output Configuration Group
        output_group = QGroupBox("Output Configuration", self)
        output_layout = QHBoxLayout()

        self.output_vlc_radio = QRadioButton("VLC")
        self.output_stdout_radio = QRadioButton("Stdout")
        self.output_file_radio = QRadioButton("Log File")

        # Set the last used output option as checked
        if self.output == 'vlc':
            self.output_vlc_radio.setChecked(True)
        elif self.output == 'stdout':
            self.output_stdout_radio.setChecked(True)
        elif self.output == 'logfile':
            self.output_file_radio.setChecked(True)

        output_layout.addWidget(self.output_vlc_radio)
        output_layout.addWidget(self.output_stdout_radio)
        output_layout.addWidget(self.output_file_radio)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)

        # Control Buttons (Address Book and Settings on the same row)
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.address_book_button = QPushButton("Address Book")
        self.settings_button = QPushButton("Settings")
        self.stop_button.setEnabled(False)

        self.start_button.clicked.connect(self.start_listener)
        self.stop_button.clicked.connect(self.stop_listener)
        self.address_book_button.clicked.connect(self.open_address_book)
        self.settings_button.clicked.connect(self.open_settings_dialog)

        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        button_layout.addWidget(self.address_book_button)
        button_layout.addWidget(self.settings_button)  # Add settings button on the same row
        main_layout.addLayout(button_layout)

        # Tabs for Log and Packet Visualizer
        self.tabs = QTabWidget(self)

        # --- Log Tab ---
        self.log_text = QTextEdit(self)
        self.log_text.setReadOnly(True)
        self.log_text.setMinimumHeight(200)
        log_tab = QWidget()
        log_layout = QVBoxLayout()
        log_layout.addWidget(self.log_text)
        log_tab.setLayout(log_layout)
        self.tabs.addTab(log_tab, "Log")

        # --- Packet Visualizer Tab ---
        self.packet_visualizer_tab = PacketVisualizerTab()  # Add packet visualizer tab
        self.tabs.addTab(self.packet_visualizer_tab, "Packet Visualizer")

        main_layout.addWidget(self.tabs)

        self.setLayout(main_layout)

    def open_settings_dialog(self):
        def on_save(new_settings):
            self.settings = new_settings
            self.address_book_path = new_settings.get("address_book_path", "address_book.json")
            self.log_message("Settings updated.")

        dialog = SettingsDialog(self.settings, on_save)
        dialog.exec_()

    def log_message(self, message):
        # Emit the signal to update the log in the main thread
        self.log_signal.emit(message)

        # If output is to log file, append the message to the file
        if self.output == 'logfile':
            log_path = self.settings.get("log_file_path", "listener.log")
            try:
                with open(log_path, "a") as f:
                    f.write(message + "\n")
            except Exception as e:
                self.log_signal.emit(f"[Log File Error] {str(e)}")

    def update_log(self, message):
        self.log_text.append(message)
        self.log_text.moveCursor(self.log_text.textCursor().End)

        # Keep the log at a fixed number of lines
        document = self.log_text.document()
        num_lines = document.blockCount()
        
        if num_lines > MAX_LOG_LINES:
            cursor = self.log_text.textCursor()
            cursor.movePosition(cursor.StartOfBlock)  # Move to the beginning of the first line
            cursor.select(cursor.BlockUnderCursor)  # Select the first line
            cursor.removeSelectedText()  # Remove the first line

    def start_listener(self):
        self.group = self.group_entry.text()
        self.port = int(self.port_entry.text())
        self.interface_ip = self.interface_selector.currentText()

        if self.output_vlc_radio.isChecked():
            self.output = 'vlc'
        elif self.output_stdout_radio.isChecked():
            self.output = 'stdout'
        else:
            self.output = 'logfile'

        # Save updated settings (group, port, output) to the settings file
        self.settings["group"] = self.group
        self.settings["port"] = self.port
        self.settings["output"] = self.output
        save_settings(self.settings)

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.log_message(f"Listening on {self.group}:{self.port} via {self.interface_ip} (Output: {self.output})")

        self.listener_running = True
        self.listener_thread = threading.Thread(target=self.listen)
        self.listener_thread.start()

    def stop_listener(self):
        self.listener_running = False
        if self.listener_thread:
            self.listener_thread.join()

        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_message("Listener stopped.")

    def listen(self):
        BUFFER_SIZE = 4096
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.port))

        mreq = struct.pack('4s4s', socket.inet_aton(self.group), socket.inet_aton(self.interface_ip))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        if self.output == 'vlc':
            vlc_path = self.settings.get("vlc_path", "")
            if not vlc_path or not os.path.exists(vlc_path):
                self.log_message("VLC path is invalid or not set in settings.")
                return

            vlc_process = subprocess.Popen(
                [vlc_path, "-", "--play-and-exit"],
                stdin=subprocess.PIPE
            )

            if self.settings.get("os") == "macOS":
                subprocess.run(["osascript", "-e", 'tell application "VLC" to activate'])

            try:
                while self.listener_running:
                    data, _ = sock.recvfrom(BUFFER_SIZE)
                    vlc_process.stdin.write(data)
                    vlc_process.stdin.flush()
            except Exception as e:
                self.log_message(f"Error: {str(e)}")
            finally:
                if vlc_process.stdin:
                    vlc_process.stdin.close()
                vlc_process.wait()
        else:
            try:
                while self.listener_running:
                    data, addr = sock.recvfrom(BUFFER_SIZE)
                    self.log_message(f"{data}")
                    self.packet_visualizer_tab.update_table(addr[0], len(data))
            except Exception as e:
                self.log_message(f"Error: {str(e)}")

        sock.close()

    def open_address_book(self):
        dialog = AddressBookDialog(self, self.load_address_book_entry)
        dialog.exec_()

    def load_address_book_entry(self, group, port):
        self.group = group
        self.port = port
        self.group_entry.setText(group)
        self.port_entry.setText(str(port))

if __name__ == '__main__':
    app = QApplication([])
    window = MulticastListenerApp()
    window.show()
    app.exec_()