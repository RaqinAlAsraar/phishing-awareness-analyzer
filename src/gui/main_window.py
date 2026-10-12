"""
PyQt6 Native Desktop GUI for Phishing Awareness Analyzer.

Author: Ali Abbas Haidar (Raqin Al-Asraar)
Features:
- Email message inspection with instant synthetic corpus loader
- Standalone URL threat analysis
- Benchmark suite execution across test corpus
- Clean dark theme styling and responsive layout
"""

from pathlib import Path
import sys
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

# Bootstrap sys.path for direct execution
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.core import analyze_file, analyze_input, analyze_standalone_url
from src.gui.styles import DARK_THEME_QSS

CORPUS_DIR = PROJECT_ROOT / "data" / "corpus"


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Phishing Awareness Analyzer - Threat Detection & Heuristics")
        self.resize(1180, 820)
        self.setStyleSheet(DARK_THEME_QSS)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(16, 16, 16, 16)
        self.main_layout.setSpacing(12)

        # Header Bar
        self.create_header()

        # Tabs
        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        self.setup_email_tab()
        self.setup_url_tab()
        self.setup_benchmark_tab()

    def create_header(self):
        header_layout = QHBoxLayout()
        title_label = QLabel("🛡️ Phishing Awareness Analyzer")
        title_font = QFont()
        title_font.setPointSize(16)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setStyleSheet("color: #38bdf8;")

        author_label = QLabel("Author: Ali Abbas Haidar (Raqin Al-Asraar) | @raqinalasraar")
        author_label.setStyleSheet("color: #94a3b8; font-size: 12px;")

        header_layout.addWidget(title_label)
        header_layout.addStretch()
        header_layout.addWidget(author_label)
        self.main_layout.addLayout(header_layout)

    # ================= EMAIL TAB =================
    def setup_email_tab(self):
        tab = QWidget()
        tab_layout = QHBoxLayout(tab)
        tab_layout.setSpacing(16)

        # Left Column: Input
        left_box = QGroupBox("Email Input & Synthetic Corpus")
        left_layout = QVBoxLayout(left_box)

        # Quick Loader
        loader_layout = QHBoxLayout()
        loader_label = QLabel("Sample:")
        self.corpus_combo = QComboBox()
        self.corpus_combo.addItem("-- Select Synthetic Test Sample --", "")
        self.populate_corpus_combo()
        self.corpus_combo.currentIndexChanged.connect(self.on_corpus_selected)

        browse_btn = QPushButton("📂 Browse .eml")
        browse_btn.clicked.connect(self.browse_email_file)

        loader_layout.addWidget(loader_label)
        loader_layout.addWidget(self.corpus_combo, 1)
        loader_layout.addWidget(browse_btn)
        left_layout.addLayout(loader_layout)

        # Text Area
        self.email_editor = QPlainTextEdit()
        self.email_editor.setPlaceholderText("Paste raw RFC-822 email message or plain email text here...")
        left_layout.addWidget(self.email_editor)

        # Action Buttons
        btn_layout = QHBoxLayout()
        clear_btn = QPushButton("Clear")
        clear_btn.setProperty("class", "secondary")
        clear_btn.clicked.connect(self.clear_email_tab)

        analyze_btn = QPushButton("🔍 Analyze Threat")
        analyze_btn.clicked.connect(self.run_email_analysis)

        btn_layout.addWidget(clear_btn)
        btn_layout.addWidget(analyze_btn)
        left_layout.addLayout(btn_layout)

        # Right Column: Analysis Results
        right_box = QGroupBox("Heuristic Threat Report")
        right_layout = QVBoxLayout(right_box)

        # Score & Verdict
        self.score_label = QLabel("Risk Score: -- / 100")
        score_font = QFont()
        score_font.setPointSize(16)
        score_font.setBold(True)
        self.score_label.setFont(score_font)

        self.verdict_label = QLabel("Awaiting input for analysis.")
        self.verdict_label.setStyleSheet("color: #94a3b8; font-weight: 600;")

        right_layout.addWidget(self.score_label)
        right_layout.addWidget(self.verdict_label)

        # Sender & Auth Summary
        self.sender_label = QLabel("Sender Info: N/A")
        self.sender_label.setStyleSheet("color: #cbd5e1; font-size: 12px; margin-top: 4px;")
        right_layout.addWidget(self.sender_label)

        # Findings Table
        findings_lbl = QLabel("Detected Indicators:")
        findings_lbl.setStyleSheet("font-weight: 600; margin-top: 8px;")
        right_layout.addWidget(findings_lbl)

        self.findings_table = QTableWidget(0, 4)
        self.findings_table.setHorizontalHeaderLabels(["Category", "Severity", "Points", "Description"])
        self.findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        right_layout.addWidget(self.findings_table, 2)

        # URLs Table
        urls_lbl = QLabel("Embedded Links:")
        urls_lbl.setStyleSheet("font-weight: 600; margin-top: 8px;")
        right_layout.addWidget(urls_lbl)

        self.urls_table = QTableWidget(0, 3)
        self.urls_table.setHorizontalHeaderLabels(["URL Destination", "Risk", "Domain"])
        self.urls_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        right_layout.addWidget(self.urls_table, 1)

        # Disclaimer
        disclaimer_lbl = QLabel("⚠️ Disclaimer: Automated heuristics assess behavioral threat patterns; verify sensitive emails via official channels.")
        disclaimer_lbl.setStyleSheet("color: #f59e0b; font-size: 11px;")
        disclaimer_lbl.setWordWrap(True)
        right_layout.addWidget(disclaimer_lbl)

        # Splitter for left and right
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(left_box)
        splitter.addWidget(right_box)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)

        tab_layout.addWidget(splitter)
        self.tabs.addTab(tab, "✉️ Email Analyzer")

    def populate_corpus_combo(self):
        if CORPUS_DIR.is_dir():
            for eml in sorted(CORPUS_DIR.glob("*.eml")):
                self.corpus_combo.addItem(eml.name, str(eml))

    def on_corpus_selected(self, index: int):
        path_str = self.corpus_combo.currentData()
        if path_str and Path(path_str).is_file():
            text = Path(path_str).read_text(encoding="utf-8", errors="replace")
            self.email_editor.setPlainText(text)
            self.run_email_analysis()

    def browse_email_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Open Email File", "", "Email Files (*.eml *.txt);;All Files (*)")
        if file_path:
            text = Path(file_path).read_text(encoding="utf-8", errors="replace")
            self.email_editor.setPlainText(text)
            self.run_email_analysis()

    def clear_email_tab(self):
        self.email_editor.clear()
        self.corpus_combo.setCurrentIndex(0)
        self.score_label.setText("Risk Score: -- / 100")
        self.score_label.setStyleSheet("color: #f8fafc;")
        self.verdict_label.setText("Awaiting input for analysis.")
        self.sender_label.setText("Sender Info: N/A")
        self.findings_table.setRowCount(0)
        self.urls_table.setRowCount(0)

    def run_email_analysis(self):
        text = self.email_editor.toPlainText().strip()
        if not text:
            QMessageBox.warning(self, "Input Required", "Please provide raw email content or choose a sample.")
            return

        report = analyze_input(text)
        data = report.to_dict()

        # Update Score and Tier
        score = data["risk_score"]
        tier = data["tier"]
        self.score_label.setText(f"Risk Score: {score} / 100 ({tier['name'].upper()})")
        self.score_label.setStyleSheet(f"color: {tier['color']};")
        self.verdict_label.setText(data["summary_verdict"])

        # Update Sender
        sender = data["sender_info"]
        sender_text = (
            f"From: {sender['from_display']} <{sender['from_email']}> | "
            f"SPF: {sender['spf'].upper()} | DKIM: {sender['dkim'].upper()}"
        )
        self.sender_label.setText(sender_text)

        # Update Findings Table
        findings = data["findings"]
        self.findings_table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            self.findings_table.setItem(row, 0, QTableWidgetItem(f["category"]))
            self.findings_table.setItem(row, 1, QTableWidgetItem(f["severity"].upper()))
            self.findings_table.setItem(row, 2, QTableWidgetItem(f"+{f['points']}"))
            self.findings_table.setItem(row, 3, QTableWidgetItem(f["description"]))

        # Update URLs Table
        urls = data["urls"]
        self.urls_table.setRowCount(len(urls))
        for row, u in enumerate(urls):
            self.urls_table.setItem(row, 0, QTableWidgetItem(u["url"]))
            self.urls_table.setItem(row, 1, QTableWidgetItem(f"{u['risk_score']} pts"))
            self.urls_table.setItem(row, 2, QTableWidgetItem(u["domain"]))

    # ================= URL TAB =================
    def setup_url_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setSpacing(16)

        box = QGroupBox("Standalone URL Inspector (100% Offline Static Heuristics)")
        box_layout = QVBoxLayout(box)

        # Quick buttons
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(QLabel("Quick Tests:"))
        samples = [
            ("IP Address", "http://192.168.1.100/login"),
            ("Typosquatting", "https://paypa1-security.com/restore"),
            ("Subdomain Deception", "https://paypal.com.verify-account.net/login"),
            ("High-Risk TLD", "https://portal-update.xyz/auth"),
            ("Clean GitHub", "https://github.com/login"),
        ]
        for name, url_val in samples:
            btn = QPushButton(name)
            btn.setProperty("class", "secondary")
            btn.clicked.connect(lambda _, u=url_val: self.load_url_sample(u))
            btn_layout.addWidget(btn)
        btn_layout.addStretch()
        box_layout.addLayout(btn_layout)

        # URL Input
        input_layout = QHBoxLayout()
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter target URL to inspect (e.g. http://192.168.1.50/verify)...")
        scan_btn = QPushButton("Scan URL")
        scan_btn.clicked.connect(self.run_url_analysis)
        input_layout.addWidget(self.url_input, 1)
        input_layout.addWidget(scan_btn)
        box_layout.addLayout(input_layout)

        # URL Results
        self.url_score_label = QLabel("URL Risk Score: -- / 100")
        url_font = QFont()
        url_font.setPointSize(15)
        url_font.setBold(True)
        self.url_score_label.setFont(url_font)
        box_layout.addWidget(self.url_score_label)

        self.url_verdict_label = QLabel("Enter a URL and click Scan.")
        self.url_verdict_label.setStyleSheet("color: #94a3b8;")
        box_layout.addWidget(self.url_verdict_label)

        self.url_findings_table = QTableWidget(0, 4)
        self.url_findings_table.setHorizontalHeaderLabels(["Category", "Severity", "Points", "Description"])
        self.url_findings_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        box_layout.addWidget(self.url_findings_table)

        tab_layout.addWidget(box)
        self.tabs.addTab(tab, "🔗 URL Inspector")

    def load_url_sample(self, url_str: str):
        self.url_input.setText(url_str)
        self.run_url_analysis()

    def run_url_analysis(self):
        url_text = self.url_input.text().strip()
        if not url_text:
            QMessageBox.warning(self, "Input Required", "Please enter a URL to inspect.")
            return

        report = analyze_standalone_url(url_text)
        data = report.to_dict()

        score = data["risk_score"]
        tier = data["tier"]
        self.url_score_label.setText(f"URL Risk Score: {score} / 100 ({tier['name'].upper()})")
        self.url_score_label.setStyleSheet(f"color: {tier['color']};")
        self.url_verdict_label.setText(data["summary_verdict"])

        findings = data["findings"]
        self.url_findings_table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            self.url_findings_table.setItem(row, 0, QTableWidgetItem(f["category"]))
            self.url_findings_table.setItem(row, 1, QTableWidgetItem(f["severity"].upper()))
            self.url_findings_table.setItem(row, 2, QTableWidgetItem(f"+{f['points']}"))
            self.url_findings_table.setItem(row, 3, QTableWidgetItem(f["description"]))

    # ================= BENCHMARK TAB =================
    def setup_benchmark_tab(self):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setSpacing(16)

        box = QGroupBox("Synthetic Corpus Benchmark Suite")
        box_layout = QVBoxLayout(box)

        top_layout = QHBoxLayout()
        desc = QLabel("Batch-evaluates all synthetic test emails against heuristic rules.")
        desc.setStyleSheet("color: #94a3b8;")
        run_btn = QPushButton("▶ Run Benchmark on All Samples")
        run_btn.clicked.connect(self.run_benchmark)
        top_layout.addWidget(desc)
        top_layout.addStretch()
        top_layout.addWidget(run_btn)
        box_layout.addLayout(top_layout)

        self.bench_table = QTableWidget(0, 5)
        self.bench_table.setHorizontalHeaderLabels(["Filename", "Expected Truth", "Predicted Risk", "Tier", "Findings Count"])
        self.bench_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        box_layout.addWidget(self.bench_table)

        tab_layout.addWidget(box)
        self.tabs.addTab(tab, "🧪 Corpus Benchmark")

    def run_benchmark(self):
        if not CORPUS_DIR.is_dir():
            QMessageBox.warning(self, "Directory Error", f"Corpus directory not found: {CORPUS_DIR}")
            return

        emls = sorted(CORPUS_DIR.glob("*.eml"))
        self.bench_table.setRowCount(len(emls))

        for row, eml in enumerate(emls):
            report = analyze_file(eml)
            data = report.to_dict()
            expected = "Legitimate" if eml.name.startswith("legit_") else "Phishing"

            self.bench_table.setItem(row, 0, QTableWidgetItem(eml.name))
            self.bench_table.setItem(row, 1, QTableWidgetItem(expected))
            self.bench_table.setItem(row, 2, QTableWidgetItem(f"{data['risk_score']} / 100"))
            self.bench_table.setItem(row, 3, QTableWidgetItem(data["tier"]["name"]))
            self.bench_table.setItem(row, 4, QTableWidgetItem(str(len(data["findings"]))))


def run_gui():
    """Launches the PyQt6 Desktop Application."""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
