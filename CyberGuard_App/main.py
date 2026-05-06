import sys
import requests
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import *

STYLE_SHEET = """
QMainWindow { background-color: #0f172a; }
QTabWidget::pane { border: 1px solid #1e293b; background: #0f172a; border-radius: 12px; margin-top: -5px; }
QTabBar::tab {
    background: #1e293b; color: #94a3b8; padding: 14px 40px;
    border-top-left-radius: 12px; border-top-right-radius: 12px;
    margin-right: 4px; font-weight: 600; font-size: 13px;
}
QTabBar::tab:selected { background: #3b82f6; color: white; }
QTabBar::tab:hover:!selected { background: #334155; }
#ConnPanel { background-color: #1e293b; border-bottom: 1px solid #334155; padding: 15px 25px; }
#StatCard {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #1e293b, stop:1 #0f172a);
    border-radius: 16px; border: 1px solid #334155; padding: 25px;
}
#StatCard:hover { border: 1px solid #3b82f6; }
QLabel { color: #f8fafc; font-family: 'Segoe UI', sans-serif; }
#Header { font-size: 15px; text-transform: uppercase; letter-spacing: 1.2px; color: #60a5fa; font-weight: 800; }
#ValueLarge { font-size: 36px; font-weight: 800; color: #ffffff; }
#SpeedValue { font-size: 18px; color: #38bdf8; font-weight: 600; }
QLineEdit {
    background-color: #0f172a; border: 1px solid #334155; border-radius: 8px;
    padding: 10px 15px; color: white; selection-background-color: #3b82f6;
}
#SearchInput {
    background-color: #1e293b; border: 1px solid #334155; border-radius: 10px;
    padding: 10px 20px; color: white; font-size: 14px; min-width: 400px;
}
QPushButton {
    background-color: #3b82f6; color: white; border-radius: 8px;
    padding: 12px 28px; font-weight: 700; font-size: 13px;
}
QPushButton:hover { background-color: #2563eb; }
#ControlBtn { background-color: #334155; color: white; border-radius: 8px; padding: 10px 20px; font-weight: bold; font-size: 12px; }
#ControlBtn:checked { background-color: #ef4444; }
QProgressBar { background-color: #334155; border-radius: 6px; text-align: center; color: transparent; height: 10px; border: none; margin-top: 15px; }
QProgressBar::chunk { background-color: #3b82f6; border-radius: 6px; }
QTableWidget { background-color: #0f172a; color: #e2e8f0; gridline-color: #1e293b; border: none; font-size: 14px; outline: none; }
QHeaderView::section { background-color: #1e293b; color: #e2e8f0; padding: 15px; border: none; font-weight: 700; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }
"""

class DataFetcher(QThread):
    stats_signal = pyqtSignal(dict)
    packets_signal = pyqtSignal(list)
    conns_signal = pyqtSignal(list)
    error_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.server_url = ""
        self.active = False

    def set_url(self, url):
        self.server_url = url.strip().rstrip('/')

    def run(self):
        while True:
            if not self.active or not self.server_url:
                self.msleep(500)
                continue
            try:
                s = requests.get(f"{self.server_url}/stats", timeout=1).json()
                self.stats_signal.emit(s)
                p = requests.get(f"{self.server_url}/packets", timeout=1).json()
                if p: self.packets_signal.emit(p)
                c = requests.get(f"{self.server_url}/connections", timeout=1).json()
                if c: self.conns_signal.emit(c)
                self.error_signal.emit("OK")
            except Exception:
                self.error_signal.emit("ERR")
            self.msleep(1000)

class CyberGuardClient(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CYBERGUARD | Remote Monitoring System")
        self.resize(1200, 900)
        self.setStyleSheet(STYLE_SHEET)
        self.traffic_paused = False
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        self.main_layout = QVBoxLayout(main_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)
        self.init_conn_panel()
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)
        self.init_dashboard()
        self.init_traffic_tab()
        self.init_conn_tab()
        self.fetcher = DataFetcher()
        self.fetcher.stats_signal.connect(self.update_stats)
        self.fetcher.packets_signal.connect(self.update_packets)
        self.fetcher.conns_signal.connect(self.update_conns)
        self.fetcher.error_signal.connect(self.update_status)
        self.fetcher.start()

    def init_conn_panel(self):
        panel = QFrame(); panel.setObjectName("ConnPanel")
        layout = QHBoxLayout(panel)
        layout.addWidget(QLabel("TARGET HOST:"))
        self.url_input = QLineEdit(); self.url_input.setText("http://127.0.0.1:8000")
        layout.addWidget(self.url_input)
        self.btn = QPushButton("ESTABLISH CONNECTION")
        self.btn.clicked.connect(self.handle_connect)
        layout.addWidget(self.btn)
        layout.addStretch()
        self.status_dot = QLabel("● DISCONNECTED")
        layout.addWidget(self.status_dot)
        self.main_layout.addWidget(panel)

    def handle_connect(self):
        url = self.url_input.text().strip()
        if url:
            self.fetcher.set_url(url)
            self.fetcher.active = True
            self.status_dot.setText("● CONNECTING...")
            self.status_dot.setStyleSheet("color: #fbbf24;")

    def create_card(self, title, icon=""):
        card = QFrame(); card.setObjectName("StatCard")
        layout = QVBoxLayout(card)
        lbl = QLabel(f"{icon} {title}"); lbl.setObjectName("Header")
        layout.addWidget(lbl)
        return card, layout

    def init_dashboard(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        layout.setContentsMargins(35, 35, 35, 35); layout.setSpacing(30)
        row1 = QHBoxLayout(); row1.setSpacing(25)
        for title, icon, attr in [("CPU Load", "⚡", "cpu"), ("Memory", "🧠", "ram"), ("Disk", "💾", "disk")]:
            card, clat = self.create_card(title, icon)
            val = QLabel("0%"); val.setObjectName("ValueLarge")
            bar = QProgressBar()
            setattr(self, f"{attr}_bar", bar); setattr(self, f"{attr}_val", val)
            clat.addWidget(val); clat.addWidget(bar); row1.addWidget(card)
        layout.addLayout(row1)
        net_card, net_lay = self.create_card("Network Live Throughput", "🌐")
        net_info = QHBoxLayout()
        for label, obj_name in [("DOWNLOAD", "sp_down"), ("UPLOAD", "sp_up")]:
            v = QVBoxLayout(); l = QLabel(label); l.setObjectName("Header")
            val = QLabel("0 KB/s"); val.setObjectName("SpeedValue")
            setattr(self, obj_name, val); v.addWidget(l); v.addWidget(val)
            net_info.addLayout(v); net_info.addSpacing(50)
        net_info.addStretch()
        v_total = QVBoxLayout(); tl = QLabel("TOTAL DATA (RX/TX)"); tl.setObjectName("Header")
        self.total_net = QLabel("0 MB / 0 MB"); self.total_net.setObjectName("ValueLarge")
        v_total.addWidget(tl, alignment=Qt.AlignmentFlag.AlignRight)
        v_total.addWidget(self.total_net, alignment=Qt.AlignmentFlag.AlignRight)
        net_info.addLayout(v_total); net_lay.addLayout(net_info); layout.addWidget(net_card)
        sys_card, sys_lay = self.create_card("Server Environment", "🛠")
        self.sys_info = QLabel("Connecting to host...")
        self.sys_info.setStyleSheet("font-size: 15px; color: #94a3b8; font-weight: 500;")
        sys_lay.addWidget(self.sys_info); layout.addWidget(sys_card)
        self.tabs.addTab(tab, "📊 DASHBOARD")

    def _setup_table(self, table):
        table.verticalHeader().setVisible(False); table.verticalHeader().setDefaultSectionSize(52)
        table.setShowGrid(False); table.setAlternatingRowColors(True)
        table.setStyleSheet("QTableWidget { alternate-background-color: #161e2d; }")

    def init_traffic_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        layout.setContentsMargins(25, 25, 25, 25)
        tools = QHBoxLayout()
        self.traffic_search = QLineEdit(); self.traffic_search.setObjectName("SearchInput")
        self.traffic_search.setPlaceholderText("🔍 Search by IP, Protocol or Size...")
        self.traffic_search.textChanged.connect(self.filter_traffic)
        self.pause_btn = QPushButton("⏸ PAUSE STREAM"); self.pause_btn.setCheckable(True)
        self.pause_btn.setObjectName("ControlBtn"); self.pause_btn.clicked.connect(self.toggle_pause)
        tools.addWidget(self.traffic_search); tools.addStretch(); tools.addWidget(self.pause_btn)
        layout.addLayout(tools)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["SOURCE", "DESTINATION", "PROTO", "SIZE", "TIMESTAMP"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._setup_table(self.table); layout.addWidget(self.table)
        self.tabs.addTab(tab, "📡 NETWORK TRAFFIC")

    def init_conn_tab(self):
        tab = QWidget(); layout = QVBoxLayout(tab)
        self.conn_table = QTableWidget(0, 4)
        self.conn_table.setHorizontalHeaderLabels(["LOCAL", "REMOTE", "STATUS", "PID"])
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self._setup_table(self.conn_table); layout.addWidget(self.conn_table)
        self.tabs.addTab(tab, "🔗 CONNECTIONS")

    def toggle_pause(self):
        self.traffic_paused = self.pause_btn.isChecked()
        self.pause_btn.setText("▶ RESUME STREAM" if self.traffic_paused else "⏸ PAUSE STREAM")

    def filter_traffic(self, text):
        search_text = text.lower()
        for row in range(self.table.rowCount()):
            match = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item and search_text in item.text().lower():
                    match = True; break
            self.table.setRowHidden(row, not match)

    def update_status(self, s):
        if s == "OK": self.status_dot.setText("● ONLINE"); self.status_dot.setStyleSheet("color: #10b981;")
        else: self.status_dot.setText("● OFFLINE"); self.status_dot.setStyleSheet("color: #ef4444;")

    def update_stats(self, s):
        self.cpu_bar.setValue(int(s['cpu'])); self.cpu_val.setText(f"{s['cpu']}%")
        self.ram_bar.setValue(int(s['ram'])); self.ram_val.setText(f"{s['ram']}%")
        self.disk_bar.setValue(int(s['disk']['percent'])); self.disk_val.setText(f"{s['disk']['percent']}%")
        fmt = lambda b: f"{b / 1024 / 1024:.2f} MB/s" if b > 1024 * 1024 else f"{b / 1024:.1f} KB/s"
        self.sp_down.setText(f"⬇ {fmt(s['speed']['down'])}"); self.sp_up.setText(f"⬆ {fmt(s['speed']['up'])}")
        self.total_net.setText(f"{s['net_total']['rx']} MB / {s['net_total']['tx']} MB")
        i = s['sys_info']
        self.sys_info.setText(f"🖥 <b>Host:</b> {i['node']}  |  <b>OS:</b> {i['os']}  |  <b>Uptime:</b> {i['uptime']}")

    def update_packets(self, packets):
        if self.traffic_paused: return
        for p in packets:
            row = self.table.rowCount(); self.table.insertRow(row)
            data = [p['src'], p['dst'], p['proto'], str(p['size']), p['time']]
            for i, v in enumerate(data): self.table.setItem(row, i, QTableWidgetItem(v))
        if self.table.rowCount() > 100: self.table.removeRow(0)
        self.table.scrollToBottom()
        if self.traffic_search.text(): self.filter_traffic(self.traffic_search.text())

    def update_conns(self, conns):
        self.conn_table.setRowCount(0)
        for c in conns:
            r = self.conn_table.rowCount(); self.conn_table.insertRow(r)
            items = [c['local'], c['remote'], c['status'], str(c['pid'])]
            for i, v in enumerate(items): self.conn_table.setItem(r, i, QTableWidgetItem(v))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    win = CyberGuardClient()
    win.show()
    sys.exit(app.exec())
