import sys
import os
import psutil
import time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QLabel, QTabWidget, QProgressBar, QLineEdit, QMessageBox, QFrame
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer
from scapy.all import sniff, IP, TCP, UDP, ICMP

# --- Тот же стильный QSS ---
STYLE_SHEET = """
QMainWindow { background-color: #0f172a; }
QTabWidget::pane { border: 1px solid #1e293b; background: #0f172a; border-radius: 10px; }
QTabBar::tab { background: #1e293b; color: #94a3b8; padding: 10px 20px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; }
QTabBar::tab:selected { background: #3b82f6; color: white; font-weight: bold; }
#StatCard { background-color: #1e293b; border-radius: 12px; border: 1px solid #334155; }
QLabel { color: #f8fafc; font-family: 'Segoe UI', sans-serif; }
#Header { font-size: 18px; font-weight: bold; color: #3b82f6; }
QTableWidget { background-color: #0f172a; alternate-background-color: #1e293b; gridline-color: #334155; color: #e2e8f0; border: none; selection-background-color: #3b82f6; }
QHeaderView::section { background-color: #1e293b; color: #94a3b8; padding: 8px; border: none; font-weight: bold; }
QLineEdit { background-color: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px; color: white; }
QPushButton { background-color: #3b82f6; color: white; border-radius: 6px; padding: 8px 15px; font-weight: bold; }
QPushButton:hover { background-color: #2563eb; }
QPushButton#StopBtn { background-color: #ef4444; }
QProgressBar { background-color: #334155; border-radius: 5px; text-align: center; color: white; }
QProgressBar::chunk { background-color: #3b82f6; border-radius: 5px; }
"""


def check_root():
    return os.getuid() == 0


class SnifferThread(QThread):
    packet_signal = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.running = False

    def run(self):
        self.running = True

        def packet_callback(pkt):
            if not self.running: return True
            if IP in pkt:
                proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "ICMP" if ICMP in pkt else "Other"
                self.packet_signal.emit([pkt[IP].src, pkt[IP].dst, proto, f"{len(pkt)} B", time.strftime('%H:%M:%S')])

        sniff(prn=packet_callback, store=0, stop_filter=lambda x: not self.running)

    def stop(self):
        self.running = False


class CyberGuard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CYBERGUARD PRO | Network Monitor")
        self.resize(1150, 850)
        self.setStyleSheet(STYLE_SHEET)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.init_dashboard()
        self.init_sniffer()
        self.init_connections()

        # Единый таймер обновления (CPU, RAM, Сеть, Соединения)
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_all_metrics)
        self.timer.start(1000)

        # АВТОСТАРТ СНИФФЕРА ПРИ ВХОДЕ
        self.start_auto_sniffing()

    def start_auto_sniffing(self):
        self.sniffer.start()
        self.btn_action.setText("ОСТАНОВИТЬ МОНИТОРИНГ")
        self.btn_action.setObjectName("StopBtn")
        self.btn_action.setStyle(self.btn_action.style())

    def create_card(self, title):
        card = QFrame()
        card.setObjectName("StatCard")
        layout = QVBoxLayout(card)
        label = QLabel(title)
        label.setObjectName("Header")
        layout.addWidget(label)
        return card, layout

    def init_dashboard(self):
        tab = QWidget()
        main_layout = QVBoxLayout(tab)
        main_layout.setContentsMargins(20, 20, 20, 20)

        stats_row = QHBoxLayout()
        cpu_card, cpu_layout = self.create_card("ЦЕНТРАЛЬНЫЙ ПРОЦЕССОР")
        self.cpu_bar = QProgressBar()
        self.cpu_label = QLabel("Загрузка: 0%")
        cpu_layout.addWidget(self.cpu_label);
        cpu_layout.addWidget(self.cpu_bar)

        ram_card, ram_layout = self.create_card("ОПЕРАТИВНАЯ ПАМЯТЬ")
        self.ram_bar = QProgressBar()
        self.ram_label = QLabel("Использование: 0%")
        ram_layout.addWidget(self.ram_label);
        ram_layout.addWidget(self.ram_bar)

        stats_row.addWidget(cpu_card);
        stats_row.addWidget(ram_card)
        main_layout.addLayout(stats_row)

        net_card, net_layout = self.create_card("СЕТЕВОЙ ТРАФИК (ВСЕГО)")
        self.net_stats = QLabel("📥 Получено: 0 MB\n📤 Отправлено: 0 MB")
        self.net_stats.setStyleSheet("font-size: 22px; color: #10b981; font-weight: bold;")
        net_layout.addWidget(self.net_stats)
        main_layout.addWidget(net_card)

        main_layout.addStretch()
        self.tabs.addTab(tab, "📊 ДАШБОРД")

    def init_sniffer(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        tools = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Поиск по IP...")
        self.search.textChanged.connect(self.filter_data)
        self.btn_action = QPushButton("ЗАПУСТИТЬ")
        self.btn_action.clicked.connect(self.toggle_sniffer)

        tools.addWidget(self.search);
        tools.addWidget(self.btn_action)
        layout.addLayout(tools)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ИСТОЧНИК", "НАЗНАЧЕНИЕ", "ПРОТОКОЛ", "РАЗМЕР", "ВРЕМЯ"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.setAlternatingRowColors(True)
        layout.addWidget(self.table)

        self.tabs.addTab(tab, "📡 ТРАФИК")
        self.sniffer = SnifferThread()
        self.sniffer.packet_signal.connect(self.add_row)

    def init_connections(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.conn_table = QTableWidget(0, 4)
        self.conn_table.setHorizontalHeaderLabels(["ЛОКАЛЬНЫЙ", "УДАЛЕННЫЙ", "СТАТУС", "PID"])
        self.conn_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        info_label = QLabel("Обновляется автоматически каждую секунду")
        info_label.setStyleSheet("color: #64748b; font-style: italic;")

        layout.addWidget(info_label)
        layout.addWidget(self.conn_table)
        self.tabs.addTab(tab, "🔗 СОЕДИНЕНИЯ")

    def update_all_metrics(self):
        # 1. CPU & RAM
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        self.cpu_bar.setValue(int(cpu))
        self.cpu_label.setText(f"Загрузка CPU: {cpu}%")
        self.ram_bar.setValue(int(ram))
        self.ram_label.setText(f"Использование RAM: {ram}%")

        # 2. Сетевые счетчики
        net = psutil.net_io_counters()
        self.net_stats.setText(
            f"📥 Получено: {net.bytes_recv / 1024 / 1024:.2f} MB | 📤 Отправлено: {net.bytes_sent / 1024 / 1024:.2f} MB")

        # 3. АВТООБНОВЛЕНИЕ СОЕДИНЕНИЙ (Каждую секунду)
        self.refresh_connections_data()

    def refresh_connections_data(self):
        # Сохраняем текущее положение прокрутки, чтобы таблица не прыгала
        scroll_pos = self.conn_table.verticalScrollBar().value()

        self.conn_table.setRowCount(0)
        try:
            for c in psutil.net_connections(kind='inet'):
                r = self.conn_table.rowCount()
                self.conn_table.insertRow(r)
                l_addr = f"{c.laddr.ip}:{c.laddr.port}"
                r_addr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "LISTEN"
                self.conn_table.setItem(r, 0, QTableWidgetItem(l_addr))
                self.conn_table.setItem(r, 1, QTableWidgetItem(r_addr))
                self.conn_table.setItem(r, 2, QTableWidgetItem(c.status))
                self.conn_table.setItem(r, 3, QTableWidgetItem(str(c.pid)))
        except:
            pass

        self.conn_table.verticalScrollBar().setValue(scroll_pos)

    def add_row(self, data):
        row = self.table.rowCount()
        self.table.insertRow(row)
        for i, val in enumerate(data):
            self.table.setItem(row, i, QTableWidgetItem(val))

        # УВЕЛИЧЕННЫЙ ЛИМИТ ДО 1000 ЗАПИСЕЙ
        if row > 1000:
            self.table.removeRow(0)

        # Автоматический скролл вниз только если мы и так внизу
        self.table.scrollToBottom()

    def toggle_sniffer(self):
        if not self.sniffer.isRunning():
            self.sniffer.start()
            self.btn_action.setText("ОСТАНОВИТЬ МОНИТОРИНГ")
            self.btn_action.setObjectName("StopBtn")
        else:
            self.sniffer.stop()
            self.btn_action.setText("ЗАПУСТИТЬ МОНИТОРИНГ")
            self.btn_action.setObjectName("")
        self.btn_action.setStyle(self.btn_action.style())

    def filter_data(self):
        q = self.search.text().lower()
        for i in range(self.table.rowCount()):
            self.table.setRowHidden(i, q not in self.table.item(i, 0).text().lower() and q not in self.table.item(i,
                                                                                                                  1).text().lower())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    if not check_root():
        QMessageBox.critical(None, "Sudo Required", "Запустите программу через: sudo ./venv/bin/python main.py")
        sys.exit()
    win = CyberGuard()
    win.show()
    sys.exit(app.exec())
