import csv
import shutil
import subprocess
import threading
import time
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple

from PySide6.QtCore import Qt, QObject, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSplitter,
    QVBoxLayout,
    QWidget,
    QInputDialog,
    QRadioButton,
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
)


## ----------------------------
## Data model
## ----------------------------
@dataclass(frozen=True)
class Server:
    id: str
    customer: str
    env: str
    server_list: str
    name: str
    host: str
    port: int
    internal_server1: str
    internal_server2: str


## ----------------------------
## UI event bus (signals are thread-safe)
## ----------------------------
class UiBus(QObject):
    ## payload: (server_id, is_err, line)
    line = Signal(object)

    ## payload: (server_id, state, exit_code)
    status = Signal(object)

    ## payload: (finished, total, running, failed, done, stopped)
    progress = Signal(object)

    ## payload: bool (running or not)
    running = Signal(bool)

    ## payload: str
    debug = Signal(str)

    ## payload: dict summary for completion
    finished = Signal(object)


class AuditLogsDialog(QDialog):
    """
    Read-only audit log viewer (modal dialog) to preserve output console space.
    """

    def __init__(self, parent, audit_path: Path, audit_lock: threading.Lock):
        super().__init__(parent)
        self.setWindowTitle("Audit Logs (read-only)")
        self.resize(980, 520)

        self.audit_path = audit_path
        self.audit_lock = audit_lock

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        top = QHBoxLayout()
        info = QLabel(f"File: {self.audit_path.name}")
        info.setStyleSheet("color:#9fb2d0; font-weight:800;")
        top.addWidget(info)
        top.addStretch(1)

        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(self.refresh)
        top.addWidget(self.refresh_btn)
        layout.addLayout(top)

        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setFont(QFont("Consolas", 9))
        self.viewer.setStyleSheet("background:#050a14; color:#cbd5e1; border:1px solid #1b2842;")
        layout.addWidget(self.viewer, stretch=1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)

        self.refresh()

    def refresh(self):
        N = 800
        try:
            with self.audit_lock:
                if not self.audit_path.exists():
                    self.viewer.setPlainText("(audit_log.csv not found yet)\n")
                    return
                lines = self.audit_path.read_text(encoding="utf-8").splitlines()

            tail = lines[-N:] if len(lines) > N else lines
            self.viewer.setPlainText("\n".join(tail) + ("\n" if tail else ""))

        except Exception as e:
            self.viewer.setPlainText(f"Failed to load audit log: {e}\n")


class BroadcastSSHWindow(QMainWindow):
    """
    Broadcast SSH client using system-installed plink.exe (PATH).

    Important:
    - No password handling at all (passwordless plink).
    - Runs plink in parallel and keeps per-server output separated.
    - Audit logs stored locally in audit_log.csv (append-only).
    """

    ## ----------------------------
    ## Security gates
    ## ----------------------------
    DANGEROUS_CONFIRM_PHRASE = "RUN DANGEROUS"

    ## Commands/operators we treat as dangerous and require explicit phrase confirmation.
    DANGEROUS_PATTERNS: List[Tuple[str, str]] = [
        (r"\brm\s+-rf\b", "Destructive delete (rm -rf)"),
        (r"\bmkfs(\.\w+)?\b", "Filesystem format (mkfs)"),
        (r"\bdd\b", "Raw disk write/copy (dd)"),
        (r"\bshutdown\b", "Shutdown command"),
        (r"\breboot\b", "Reboot command"),
        (r"\bpoweroff\b", "Poweroff command"),
        (r":\(\)\s*\{\s*:\s*\|\s*:\s*;\s*\}\s*;\s*:", "Fork bomb pattern"),
        ## Shell control operators / redirection.
        ## These are flagged to reduce blast radius and accidental destructive chaining.
        (r";", "Shell chaining (;)"),
        (r"\&\&", "Shell chaining (&&)"),
        (r"\|\|", "Shell chaining (||)"),
        (r"\|", "Pipes (|)"),
        (r">>", "Redirection (>>)"),
        (r">", "Redirection (>)"),
        (r"<", "Redirection (<)"),
    ]

    ## Soft warnings (non-blocking confirmation).
    WARN_PATTERNS: List[Tuple[str, str]] = [
        (r"\bsudo\b", "Uses sudo (privilege escalation)"),
    ]

    ## ----------------------------
    ## Audit
    ## ----------------------------
    AUDIT_FILENAME = "audit_log.csv"
    AUDIT_HEADERS = ["timestamp", "user_id", "command_used", "command_status"]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Broadcast SSH Console • Plink engine")
        self.resize(1550, 900)

        ## ---- Thread-safe signal bus ----
        self.bus = UiBus()
        self.bus.line.connect(self.on_line)
        self.bus.status.connect(self.on_status)
        self.bus.progress.connect(self.on_progress)
        self.bus.running.connect(self.set_running_state)
        self.bus.debug.connect(self.on_debug)
        self.bus.finished.connect(self.on_finished)

        ## ---- Paths & files ----
        self.base_dir: Path = Path(__file__).resolve().parent
        self.audit_path: Path = self.base_dir / self.AUDIT_FILENAME
        self.audit_lock = threading.Lock()
        self._ensure_audit_file()

        self.inventory_path: Path = self.base_dir / "inventory.csv"

        ## ---- Inventory/state ----
        self.all_servers: List[Server] = []
        self.filtered_servers: List[Server] = []
        self.selected_ids: Set[str] = set()
        self.server_by_id: Dict[str, Server] = {}

        ## ---- Process control ----
        self.cancel_event = threading.Event()
        self.proc_lock = threading.Lock()
        self.procs: Dict[str, subprocess.Popen] = {}

        ## ---- Run metadata ----
        self.last_run_username: str = ""
        self.last_run_command: str = ""
        self.last_run_started_at: str = ""
        self.total_targets: int = 0

        ## ---- Output buffers (in-memory) ----
        self.server_buffers: Dict[str, List[str]] = {}
        self.server_state: Dict[str, str] = {}
        self.server_exit: Dict[str, Optional[int]] = {}

        ## ---- Command history ----
        self.command_history: List[str] = []

        ## ----------------------------
        ## UI layout
        ## ----------------------------
        root = QWidget()
        self.setCentralWidget(root)
        main = QVBoxLayout(root)
        main.setContentsMargins(14, 14, 14, 14)
        main.setSpacing(10)

        ## Header row
        top = QHBoxLayout()
        title = QLabel("Broadcast SSH Console")
        title.setStyleSheet("font-size:18px; font-weight:900;")
        top.addWidget(title)
        top.addStretch(1)

        self.status_lbl = QLabel("LOCAL • Ready")
        self.status_lbl.setStyleSheet(
            "padding:6px 10px; border-radius:999px;"
            "background:#0f2a1a; color:#7ee787; border:1px solid #1f6f3b; font-weight:900;"
        )
        top.addWidget(self.status_lbl)

        self.load_btn = QPushButton("Load Inventory")
        self.load_btn.clicked.connect(self.load_inventory_dialog)
        top.addWidget(self.load_btn)

        main.addLayout(top)

        hsplit = QSplitter(Qt.Horizontal)

        ## ----------------------------
        ## LEFT PANEL
        ## ----------------------------
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        filter_box = QGroupBox("Filter")
        filter_box.setStyleSheet("QGroupBox{font-weight:900;}")
        fgl = QGridLayout(filter_box)

        self.customer_dd = QComboBox()
        self.env_dd = QComboBox()

        self.search_txt = QLineEdit()
        self.search_txt.setPlaceholderText("Search by name / host / IP…")
        self.search_txt.textChanged.connect(self.apply_filter)

        fgl.addWidget(QLabel("Customer"), 0, 0)
        fgl.addWidget(self.customer_dd, 0, 1)
        fgl.addWidget(QLabel("Environment"), 1, 0)
        fgl.addWidget(self.env_dd, 1, 1)
        fgl.addWidget(QLabel("Search"), 2, 0)
        fgl.addWidget(self.search_txt, 2, 1)

        self.apply_btn = QPushButton("Apply Filter")
        self.apply_btn.clicked.connect(self.apply_filter)
        fgl.addWidget(self.apply_btn, 3, 1)

        left_layout.addWidget(filter_box)

        servers_box = QGroupBox("Servers (toggle selection)")
        servers_box.setStyleSheet("QGroupBox{font-weight:900;}")
        sbl = QVBoxLayout(servers_box)

        self.servers_hint = QLabel("Select customer for the server list")
        self.servers_hint.setStyleSheet("color:#9fb2d0; font-weight:800; padding:4px 2px;")
        sbl.addWidget(self.servers_hint)

        self.servers_list = QListWidget()
        self.servers_list.itemChanged.connect(self.on_server_toggle)
        sbl.addWidget(self.servers_list)

        row_btns = QHBoxLayout()
        self.sel_all_btn = QPushButton("Select All")
        self.sel_all_btn.clicked.connect(self.select_all_visible)
        self.clear_all_btn = QPushButton("Clear All")
        self.clear_all_btn.clicked.connect(self.clear_all_visible)

        row_btns.addWidget(self.sel_all_btn)
        row_btns.addWidget(self.clear_all_btn)
        sbl.addLayout(row_btns)

        left_layout.addWidget(servers_box, stretch=1)

        sel_box = QGroupBox("Selected Targets (summary)")
        sel_box.setStyleSheet("QGroupBox{font-weight:900;}")
        sel_layout = QVBoxLayout(sel_box)

        self.selected_summary = QLabel("0 selected")
        self.selected_summary.setStyleSheet("color:#9fb2d0; font-weight:800;")
        sel_layout.addWidget(self.selected_summary)

        self.selected_list = QListWidget()
        self.selected_list.setMinimumHeight(140)
        sel_layout.addWidget(self.selected_list)

        self.clear_sel_btn = QPushButton("Clear Selection")
        self.clear_sel_btn.clicked.connect(self.clear_selection)
        sel_layout.addWidget(self.clear_sel_btn)

        left_layout.addWidget(sel_box)

        hsplit.addWidget(left)

        ## ----------------------------
        ## RIGHT PANEL
        ## ----------------------------
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(10)

        runner_box = QGroupBox("Command Runner (System Plink • Passwordless)")
        runner_box.setStyleSheet("QGroupBox{font-weight:900;}")
        rgl = QGridLayout(runner_box)

        self.username_txt = QLineEdit()
        self.username_txt.setPlaceholderText("username (passwordless)")

        ## Target selection: Host / Internal1 / Internal2
        target_row = QHBoxLayout()
        self.rb_host = QRadioButton("Host")
        self.rb_int1 = QRadioButton("Internal 1")
        self.rb_int2 = QRadioButton("Internal 2")
        self.rb_host.setChecked(True)

        self.target_group = QButtonGroup(self)
        self.target_group.addButton(self.rb_host, 0)
        self.target_group.addButton(self.rb_int1, 1)
        self.target_group.addButton(self.rb_int2, 2)

        target_row.addWidget(self.rb_host)
        target_row.addWidget(self.rb_int1)
        target_row.addWidget(self.rb_int2)
        target_row.addStretch(1)

        ## History controls
        self.history_dd = QComboBox()
        self.history_dd.addItem("History (last 10)…", "")
        self.use_hist_btn = QPushButton("Use")
        self.use_hist_btn.clicked.connect(self.use_selected_history)
        self.clear_hist_btn = QPushButton("Clear History")
        self.clear_hist_btn.clicked.connect(self.clear_history)

        hist_row = QHBoxLayout()
        hist_row.addWidget(self.history_dd, stretch=1)
        hist_row.addWidget(self.use_hist_btn)
        hist_row.addWidget(self.clear_hist_btn)

        self.cmd_txt = QPlainTextEdit()
        self.cmd_txt.setPlaceholderText("Command to execute on selected servers…")
        self.cmd_txt.setMinimumHeight(70)

        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self.run_command)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet("background:#b42318; color:white; font-weight:900;")
        self.stop_btn.clicked.connect(self.stop_run)

        rgl.addWidget(QLabel("Username"), 0, 0)
        rgl.addWidget(self.username_txt, 0, 1)
        rgl.addWidget(QLabel("Target"), 1, 0, Qt.AlignTop)
        rgl.addLayout(target_row, 1, 1)
        rgl.addWidget(QLabel("History"), 2, 0, Qt.AlignTop)
        rgl.addLayout(hist_row, 2, 1)
        rgl.addWidget(QLabel("Command"), 3, 0, Qt.AlignTop)
        rgl.addWidget(self.cmd_txt, 3, 1)

        btns = QHBoxLayout()
        btns.addWidget(self.run_btn)
        btns.addWidget(self.stop_btn)
        rgl.addLayout(btns, 4, 1)

        right_layout.addWidget(runner_box)

        ## Output console
        out_box = QGroupBox("Output Console")
        out_box.setStyleSheet("QGroupBox{font-weight:900;}")
        out_layout = QVBoxLayout(out_box)

        self.out_header = QLabel("No run yet. Execute a command to see results.")
        self.out_header.setStyleSheet(
            "padding:10px; border-radius:10px;"
            "background:#0b1220; border:1px solid #1b2842; color:#cbd5e1; font-weight:800;"
        )
        self.out_header.setTextInteractionFlags(Qt.TextSelectableByMouse)
        out_layout.addWidget(self.out_header)

        osplit = QSplitter(Qt.Horizontal)

        self.output_selector = QListWidget()
        self.output_selector.setMinimumWidth(340)
        self.output_selector.itemSelectionChanged.connect(self.refresh_viewer)
        osplit.addWidget(self.output_selector)

        self.viewer = QPlainTextEdit()
        self.viewer.setReadOnly(True)
        self.viewer.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.viewer.setFont(QFont("Consolas", 10))
        self.viewer.setStyleSheet("background:#050a14; color:#e6edf6; border:1px solid #1b2842;")
        osplit.addWidget(self.viewer)

        osplit.setSizes([360, 900])
        out_layout.addWidget(osplit, stretch=1)

        out_btns = QHBoxLayout()
        self.save_out_btn = QPushButton("Save")
        self.save_out_btn.clicked.connect(self.save_terminal_output)
        self.clear_out_btn = QPushButton("Clear")
        self.clear_out_btn.clicked.connect(self.clear_output)
        self.audit_btn = QPushButton("Audit Logs")
        self.audit_btn.clicked.connect(self.open_audit_logs)
        out_btns.addWidget(self.save_out_btn)
        out_btns.addWidget(self.clear_out_btn)
        out_btns.addWidget(self.audit_btn)
        out_btns.addStretch(1)
        out_layout.addLayout(out_btns)

        right_layout.addWidget(out_box, stretch=1)

        hsplit.addWidget(right)
        hsplit.setSizes([480, 1070])
        main.addWidget(hsplit)

        ## Hook dropdowns
        self.customer_dd.currentIndexChanged.connect(self.apply_filter)
        self.env_dd.currentIndexChanged.connect(self.apply_filter)

        ## Init
        self.reset_output_selector()
        self._refresh_history_dropdown()

        ## Load inventory
        self.load_inventory(self.inventory_path)

        ## Hard dependency check: plink must be installed and in PATH.
        if not shutil.which("plink"):
            QMessageBox.critical(
                self,
                "Plink Not Found",
                "plink.exe was not found in system PATH.\n\n"
                "Please ensure PuTTY/Plink is installed and PATH is configured.\n\n"
                "Example check: `where plink` (Windows) or `which plink` (Linux).",
            )

    ## ----------------------------
    ## Audit
    ## ----------------------------
    def _ensure_audit_file(self):
        if self.audit_path.exists():
            return
        with self.audit_lock:
            if self.audit_path.exists():
                return
            with self.audit_path.open("w", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow(self.AUDIT_HEADERS)

    def _audit_append(self, timestamp: str, user_id: str, command_used: str, command_status: str):
        self._ensure_audit_file()
        with self.audit_lock:
            with self.audit_path.open("a", encoding="utf-8", newline="") as f:
                w = csv.writer(f)
                w.writerow([timestamp, user_id, command_used, command_status])

    def open_audit_logs(self):
        dlg = AuditLogsDialog(self, self.audit_path, self.audit_lock)
        dlg.exec()

    ## ----------------------------
    ## Security
    ## ----------------------------
    def _detect_command_risks(self, command: str) -> Tuple[List[str], List[str]]:
        dangers: List[str] = []
        warnings: List[str] = []
        c = command.strip()

        for pattern, reason in self.DANGEROUS_PATTERNS:
            if re.search(pattern, c, flags=re.IGNORECASE):
                dangers.append(reason)

        for pattern, reason in self.WARN_PATTERNS:
            if re.search(pattern, c, flags=re.IGNORECASE):
                warnings.append(reason)

        return list(dict.fromkeys(dangers)), list(dict.fromkeys(warnings))

    def _confirm_if_dangerous(self, command: str) -> bool:
        dangers, warnings = self._detect_command_risks(command)
        if not dangers and not warnings:
            return True

        msg_lines = []
        if dangers:
            msg_lines.append("⚠ Potentially dangerous command detected:")
            for d in dangers:
                msg_lines.append(f"  • {d}")
        if warnings:
            msg_lines.append("")
            msg_lines.append("Note:")
            for w in warnings:
                msg_lines.append(f"  • {w}")

        msg_lines.append("")
        if dangers:
            msg_lines.append(f"Type '{self.DANGEROUS_CONFIRM_PHRASE}' to proceed.")
            prompt = "\n".join(msg_lines)
            text, ok = QInputDialog.getText(self, "Dangerous Command Confirmation", prompt)
            return bool(ok and text.strip() == self.DANGEROUS_CONFIRM_PHRASE)

        prompt = "\n".join(msg_lines) + "\nProceed?"
        res = QMessageBox.question(self, "Command Warning", prompt, QMessageBox.Yes | QMessageBox.No)
        return res == QMessageBox.Yes

    ## ----------------------------
    ## History
    ## ----------------------------
    def _refresh_history_dropdown(self):
        self.history_dd.blockSignals(True)
        self.history_dd.clear()
        self.history_dd.addItem("History (last 10)…", "")
        for cmd in self.command_history:
            title = cmd.strip().replace("\n", " ⏎ ")
            if len(title) > 80:
                title = title[:77] + "..."
            self.history_dd.addItem(title, cmd)
        self.history_dd.setCurrentIndex(0)
        self.history_dd.blockSignals(False)

    def _add_to_history(self, command: str):
        cmd = command.strip()
        if not cmd:
            return
        self.command_history = [c for c in self.command_history if c != cmd]
        self.command_history.insert(0, cmd)
        self.command_history = self.command_history[:10]
        self._refresh_history_dropdown()

    def use_selected_history(self):
        cmd = self.history_dd.currentData()
        if cmd:
            self.cmd_txt.setPlainText(cmd)

    def clear_history(self):
        self.command_history = []
        self._refresh_history_dropdown()

    ## ----------------------------
    ## Inventory
    ## ----------------------------
    def load_inventory_dialog(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select inventory.csv", str(Path.cwd()), "CSV Files (*.csv)")
        if not path:
            return
        self.load_inventory(Path(path))

    def load_inventory(self, path: Path):
        self.inventory_path = path
        try:
            servers: List[Server] = []
            with path.open("r", encoding="utf-8", newline="") as f:
                reader = csv.DictReader(f)
                required = {
                    "id",
                    "customer",
                    "env",
                    "server_list",
                    "name",
                    "host",
                    "port",
                    "internal_server1",
                    "internal_server2",
                }
                if not required.issubset(set(reader.fieldnames or [])):
                    raise ValueError(
                        "CSV headers must be:\n"
                        "id,customer,env,server_list,name,host,port,internal_server1,internal_server2"
                    )

                for r in reader:
                    sid = (r.get("id") or "").strip()
                    if not sid:
                        continue
                    servers.append(
                        Server(
                            id=sid,
                            customer=(r.get("customer") or "").strip(),
                            env=(r.get("env") or "").strip().upper(),
                            server_list=(r.get("server_list") or "").strip(),
                            name=(r.get("name") or "").strip(),
                            host=(r.get("host") or "").strip(),
                            port=int((r.get("port") or "22").strip()),
                            internal_server1=(r.get("internal_server1") or "").strip(),
                            internal_server2=(r.get("internal_server2") or "").strip(),
                        )
                    )

            self.all_servers = servers
            self.server_by_id = {s.id: s for s in self.all_servers}
            self.rebuild_filters()

            self.selected_ids.clear()
            self.filtered_servers = []
            self.render_servers_list()

        except Exception as e:
            QMessageBox.critical(self, "Inventory load failed", str(e))

    def rebuild_filters(self):
        customers = sorted(set(s.customer for s in self.all_servers if s.customer))
        envs = sorted(set(s.env for s in self.all_servers if s.env), key=lambda x: (x != "PROD", x))

        self.customer_dd.blockSignals(True)
        self.customer_dd.clear()
        self.customer_dd.addItem("Select customer…", "")
        for c in customers:
            self.customer_dd.addItem(c, c)
        self.customer_dd.blockSignals(False)

        self.env_dd.blockSignals(True)
        self.env_dd.clear()
        self.env_dd.addItem("All envs", "")
        for e in envs:
            self.env_dd.addItem(e, e)
        self.env_dd.blockSignals(False)

    ## ----------------------------
    ## Filtering/selection
    ## ----------------------------
    def apply_filter(self):
        cust = self.customer_dd.currentData()
        env = self.env_dd.currentData()
        q = self.search_txt.text().strip().lower()

        if not cust:
            self.filtered_servers = []
            self.render_servers_list()
            return

        def matches(s: Server) -> bool:
            if s.customer != cust:
                return False
            if env and s.env != env:
                return False
            if q:
                hay = f"{s.name} {s.host} {s.customer} {s.env}".lower()
                if q not in hay:
                    return False
            return True

        self.filtered_servers = [s for s in self.all_servers if matches(s)]
        self.render_servers_list()

    def render_servers_list(self):
        self.servers_list.blockSignals(True)
        self.servers_list.clear()

        cust = self.customer_dd.currentData()
        self.servers_hint.setVisible(not bool(cust))

        for s in self.filtered_servers:
            label = f"{s.name}  •  {s.host}:{s.port}"
            it = QListWidgetItem(label)
            it.setData(Qt.UserRole, s.id)
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(Qt.Checked if s.id in self.selected_ids else Qt.Unchecked)
            self.servers_list.addItem(it)

        self.servers_list.blockSignals(False)
        self.render_selected_list()

    def on_server_toggle(self, item: QListWidgetItem):
        sid = item.data(Qt.UserRole)
        if not sid:
            return
        if item.checkState() == Qt.Checked:
            self.selected_ids.add(sid)
        else:
            self.selected_ids.discard(sid)
        self.render_selected_list()

    def render_selected_list(self):
        selected = [s for s in self.all_servers if s.id in self.selected_ids]
        selected.sort(key=lambda s: (s.customer, s.env != "PROD", s.name))

        self.selected_list.clear()
        for s in selected[:200]:
            self.selected_list.addItem(QListWidgetItem(f"{s.customer} | {s.env} | {s.name} | {s.host}:{s.port}"))

        if len(selected) > 200:
            self.selected_list.addItem(QListWidgetItem(f"... + {len(selected) - 200} more selected"))

        self.selected_summary.setText(f"{len(self.selected_ids)} selected")

    def clear_selection(self):
        self.selected_ids.clear()
        self.render_servers_list()

    def select_all_visible(self):
        for s in self.filtered_servers:
            self.selected_ids.add(s.id)
        self.render_servers_list()

    def clear_all_visible(self):
        for s in self.filtered_servers:
            self.selected_ids.discard(s.id)
        self.render_servers_list()

    ## ----------------------------
    ## Output helpers
    ## ----------------------------
    def reset_output_selector(self):
        self.output_selector.clear()
        all_item = QListWidgetItem("All (grouped)")
        all_item.setData(Qt.UserRole, "ALL")
        self.output_selector.addItem(all_item)
        self.output_selector.setCurrentRow(0)

    def _target_mode_name(self) -> str:
        mode = self.target_group.checkedId()
        return {0: "HOST", 1: "INTERNAL_1", 2: "INTERNAL_2"}.get(mode, "HOST")

    def build_all_grouped_view(self) -> str:
        blocks: List[str] = []
        blocks.append("=" * 92)
        blocks.append(f"RUN START • {self.last_run_started_at}")
        blocks.append(f"EXECUTED BY: {self.last_run_username}")
        blocks.append(f"TARGET MODE: {self._target_mode_name()}")
        blocks.append(f"COMMAND: {self.last_run_command}")
        blocks.append("=" * 92)
        blocks.append("")

        servers = [s for s in self.all_servers if s.id in self.server_buffers]
        servers.sort(key=lambda s: (s.customer, s.env != "PROD", s.name))

        for s in servers:
            state = self.server_state.get(s.id, "PENDING")
            rc = self.server_exit.get(s.id, None)
            status = f"{state}" + (f" (exit={rc})" if rc is not None else "")
            header = f"{s.customer} | {s.env} | {s.name} | {s.host}:{s.port}  ==>  {status}"

            blocks.append("┌" + "─" * 90 + "┐")
            blocks.append("│ " + header.ljust(90)[:90] + " │")
            blocks.append("├" + "─" * 90 + "┤")

            buf = self.server_buffers.get(s.id, [])
            if not buf:
                blocks.append("│ " + "(no output)".ljust(90) + " │")
            else:
                for line in buf[-400:]:
                    clean = line.rstrip("\n")
                    if len(clean) > 90:
                        clean = clean[:87] + "..."
                    blocks.append("│ " + clean.ljust(90) + " │")

            blocks.append("└" + "─" * 90 + "┘")
            blocks.append("")

        return "\n".join(blocks) + "\n"

    def refresh_viewer(self):
        items = self.output_selector.selectedItems()
        if not items:
            return
        key = items[0].data(Qt.UserRole)

        if key == "ALL":
            self.viewer.setPlainText(self.build_all_grouped_view())
            return

        buf = self.server_buffers.get(key, [])
        self.viewer.setPlainText("".join(buf))

    def clear_output(self):
        self.server_buffers.clear()
        self.server_state.clear()
        self.server_exit.clear()
        self.viewer.setPlainText("")
        self.out_header.setText("No run yet. Execute a command to see results.")
        self.reset_output_selector()

    ## ----------------------------
    ## Plink command builders (system PATH)
    ## ----------------------------
    def _selected_internal(self, server: Server) -> str:
        mode = self.target_group.checkedId()
        if mode == 1:
            return server.internal_server1
        if mode == 2:
            return server.internal_server2
        return ""

    def _build_remote_command(self, server: Server, user_command: str) -> str:
        mode = self.target_group.checkedId()
        if mode == 0:
            return user_command
        internal = self._selected_internal(server)
        return f"sudo su - {internal} < /dev/null && {user_command}"

    def _plink_cmd(self, username: str, server: Server, remote_command: str) -> List[str]:
        return [
            "plink",
            "-batch",
            "-P",
            str(server.port),
            f"{username}@{server.host}",
            remote_command,
        ]

    def _emit_progress(self):
        total = self.total_targets
        states = list(self.server_state.values())
        done = sum(1 for s in states if s == "DONE")
        failed = sum(1 for s in states if s == "FAILED")
        stopped = sum(1 for s in states if s == "STOPPED")
        running = sum(1 for s in states if s == "RUNNING")
        finished = done + failed + stopped
        self.bus.progress.emit((finished, total, running, failed, done, stopped))

    ## ----------------------------
    ## Run command (thread-safe UI updates)
    ## ----------------------------
    def run_command(self):
        try:
            self.bus.debug.emit("Run clicked")

            username = self.username_txt.text().strip()
            command = self.cmd_txt.toPlainText().strip()

            if not username:
                QMessageBox.warning(self, "Missing username", "Please enter a username.")
                return
            if not command:
                QMessageBox.warning(self, "Missing command", "Please enter a command.")
                return
            if not self.selected_ids:
                QMessageBox.warning(self, "No targets", "Select at least one server.")
                return

            if not self._confirm_if_dangerous(command):
                self.bus.debug.emit("Blocked by dangerous command gate")
                return

            selected = [s for s in self.all_servers if s.id in self.selected_ids]

            if any(s.env == "PROD" for s in selected):
                text, ok = QInputDialog.getText(
                    self,
                    "PROD Confirmation Required",
                    "⚠ PROD targets detected.\nType RUN to confirm execution:",
                )
                if (not ok) or (text.strip() != "RUN"):
                    self.bus.debug.emit("Blocked by PROD gate")
                    return

            self._add_to_history(command)

            self.last_run_username = username
            self.last_run_command = command
            self.last_run_started_at = time.strftime("%Y-%m-%d %H:%M:%S")
            self.total_targets = len(selected)

            self._audit_append(
                timestamp=self.last_run_started_at,
                user_id=username,
                command_used=command,
                command_status=f"RUN_STARTED targets={len(selected)} mode={self._target_mode_name()}",
            )

            self.server_buffers = {}
            self.server_state = {}
            self.server_exit = {}
            self.reset_output_selector()

            for s in selected:
                self.server_buffers[s.id] = []
                self.server_state[s.id] = "PENDING"
                self.server_exit[s.id] = None

                it = QListWidgetItem(f"{s.name}  •  {s.host}  ==>  PENDING")
                it.setData(Qt.UserRole, s.id)
                self.output_selector.addItem(it)

            self.output_selector.setCurrentRow(0)
            self.out_header.setText(
                f"RUNNING • {self.last_run_started_at}\n"
                f"Executed by: {username}\n"
                f"Targets: {len(selected)}\n"
                f"Target mode: {self._target_mode_name()}\n"
                f"Command: {command}\n"
                f"Progress: 0/{len(selected)} finished • Running: 0 • Failed: 0"
            )
            self.viewer.setPlainText(self.build_all_grouped_view())

            self.cancel_event.clear()
            with self.proc_lock:
                self.procs.clear()

            self.bus.running.emit(True)
            self._emit_progress()

            def stream_proc(server: Server):
                self.server_state[server.id] = "RUNNING"
                self.bus.status.emit((server.id, "RUNNING", None))
                self._emit_progress()

                mode_name = self._target_mode_name()
                internal = self._selected_internal(server)
                if mode_name == "HOST":
                    exec_path = f"EXEC: {username}@{server.host}:{server.port} (HOST)"
                else:
                    exec_path = f"EXEC: {username}@{server.host}:{server.port} -> sudo su - {internal} ({mode_name})"

                self.server_buffers[server.id].append(
                    f"\n=== {server.customer} | {server.env} | {server.name} | {server.host}:{server.port} ===\n"
                )
                self.server_buffers[server.id].append(exec_path + "\n")
                self.server_buffers[server.id].append("-" * 72 + "\n")

                remote_cmd = self._build_remote_command(server, command)
                cmd = self._plink_cmd(username, server, remote_cmd)

                try:
                    p = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        bufsize=1,
                        universal_newlines=True,
                    )

                    with self.proc_lock:
                        self.procs[server.id] = p

                    def reader(pipe, is_err: bool):
                        if not pipe:
                            return
                        for line in iter(pipe.readline, ""):
                            if self.cancel_event.is_set():
                                return
                            if not line:
                                continue
                            tag = "[stderr] " if is_err else ""
                            self.server_buffers[server.id].append(tag + line)
                            self.bus.line.emit((server.id, is_err, line))
                        try:
                            pipe.close()
                        except Exception:
                            pass

                    t_out = threading.Thread(target=reader, args=(p.stdout, False), daemon=True)
                    t_err = threading.Thread(target=reader, args=(p.stderr, True), daemon=True)
                    t_out.start()
                    t_err.start()

                    while True:
                        if self.cancel_event.is_set():
                            try:
                                p.terminate()
                            except Exception:
                                pass
                            self.server_state[server.id] = "STOPPED"
                            self.server_exit[server.id] = None
                            self.server_buffers[server.id].append("\n[stopped] Cancel requested.\n")
                            self.bus.status.emit((server.id, "STOPPED", None))
                            self._emit_progress()
                            return

                        rc = p.poll()
                        if rc is not None:
                            break
                        time.sleep(0.05)

                    t_out.join(timeout=1)
                    t_err.join(timeout=1)

                    self.server_exit[server.id] = rc
                    if rc == 0:
                        self.server_state[server.id] = "DONE"
                        self.server_buffers[server.id].append("\n[done] Success.\n")
                    else:
                        self.server_state[server.id] = "FAILED"
                        self.server_buffers[server.id].append(f"\n[failed] Exit={rc}\n")

                    self.bus.status.emit((server.id, self.server_state[server.id], rc))
                    self._emit_progress()

                except Exception as e:
                    self.server_state[server.id] = "FAILED"
                    self.server_exit[server.id] = 255
                    self.server_buffers[server.id].append(f"\n[failed] {e}\n")
                    self.bus.status.emit((server.id, "FAILED", 255))
                    self._emit_progress()
                finally:
                    with self.proc_lock:
                        self.procs.pop(server.id, None)

            def runner():
                threads: List[threading.Thread] = []
                for s in selected:
                    t = threading.Thread(target=stream_proc, args=(s,), daemon=True)
                    threads.append(t)
                    t.start()

                for t in threads:
                    t.join()

                finished, total, running, failed, done, stopped = self._progress_snapshot()

                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                self._audit_append(
                    timestamp=ts,
                    user_id=username,
                    command_used=command,
                    command_status=f"RUN_COMPLETED done={done} failed={failed} stopped={stopped}",
                )

                self.bus.finished.emit(
                    {
                        "started_at": self.last_run_started_at,
                        "username": username,
                        "targets": len(selected),
                        "mode": self._target_mode_name(),
                        "command": command,
                        "finished": finished,
                        "total": total,
                        "done": done,
                        "failed": failed,
                        "stopped": stopped,
                    }
                )

            threading.Thread(target=runner, daemon=True).start()

        except Exception as e:
            QMessageBox.critical(self, "Run failed", str(e))

    def _progress_snapshot(self) -> Tuple[int, int, int, int, int, int]:
        total = self.total_targets
        states = list(self.server_state.values())
        done = sum(1 for s in states if s == "DONE")
        failed = sum(1 for s in states if s == "FAILED")
        stopped = sum(1 for s in states if s == "STOPPED")
        running = sum(1 for s in states if s == "RUNNING")
        finished = done + failed + stopped
        return finished, total, running, failed, done, stopped

    def stop_run(self):
        self.cancel_event.set()
        with self.proc_lock:
            procs = list(self.procs.values())
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass

        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self._audit_append(
            timestamp=ts,
            user_id=self.last_run_username or "unknown",
            command_used=self.last_run_command or "",
            command_status="STOP_REQUESTED",
        )

    ## ----------------------------
    ## UI-thread slots
    ## ----------------------------
    def on_line(self, payload):
        sel = self.output_selector.selectedItems()
        if not sel:
            return
        key = sel[0].data(Qt.UserRole)
        if key == "ALL" or key == payload[0]:
            self.refresh_viewer()

    def on_status(self, payload):
        server_id, state, rc = payload
        for i in range(self.output_selector.count()):
            it = self.output_selector.item(i)
            if it.data(Qt.UserRole) == server_id:
                base = it.text().split("  ==>")[0]
                suffix = f"{state}" + (f" (exit={rc})" if rc is not None else "")
                it.setText(f"{base}  ==>  {suffix}")
                break

        if state in ("DONE", "FAILED", "STOPPED"):
            s = self.server_by_id.get(server_id)
            server_tag = "unknown_server"
            if s:
                server_tag = f"{s.customer}|{s.env}|{s.name}|{s.host}:{s.port}"
            ts = time.strftime("%Y-%m-%d %H:%M:%S")
            self._audit_append(
                timestamp=ts,
                user_id=self.last_run_username or "unknown",
                command_used=self.last_run_command or "",
                command_status=f"{state} server={server_tag} exit={rc}",
            )

        sel = self.output_selector.selectedItems()
        if sel and sel[0].data(Qt.UserRole) == "ALL":
            self.refresh_viewer()

    def on_progress(self, payload):
        finished, total, running, failed, done, stopped = payload
        self.out_header.setText(
            f"RUNNING • {self.last_run_started_at}\n"
            f"Executed by: {self.last_run_username}\n"
            f"Targets: {total}\n"
            f"Target mode: {self._target_mode_name()}\n"
            f"Command: {self.last_run_command}\n"
            f"Progress: {finished}/{total} finished • Running: {running} • Done: {done} • Failed: {failed} • Stopped: {stopped}"
        )

    def on_debug(self, msg: str):
        cur = self.viewer.toPlainText()
        self.viewer.setPlainText(cur + f"\n[DEBUG] {time.strftime('%H:%M:%S')} {msg}\n")

    def on_finished(self, summary: dict):
        self.out_header.setText(
            f"COMPLETED • {summary['started_at']}\n"
            f"Executed by: {summary['username']}\n"
            f"Targets: {summary['targets']}\n"
            f"Target mode: {summary['mode']}\n"
            f"Command: {summary['command']}\n"
            f"Progress: {summary['finished']}/{summary['total']} finished • "
            f"Done: {summary['done']} • Failed: {summary['failed']} • Stopped: {summary['stopped']}"
        )
        self.set_running_state(False)
        self.refresh_viewer()

    def set_running_state(self, is_running: bool):
        self.run_btn.setEnabled(not is_running)
        self.stop_btn.setEnabled(is_running)
        if is_running:
            self.status_lbl.setText("LOCAL • Running")
            self.status_lbl.setStyleSheet(
                "padding:6px 10px; border-radius:999px;"
                "background:#2a240f; color:#fbbf24; border:1px solid #a16207; font-weight:900;"
            )
        else:
            self.status_lbl.setText("LOCAL • Ready")
            self.status_lbl.setStyleSheet(
                "padding:6px 10px; border-radius:999px;"
                "background:#0f2a1a; color:#7ee787; border:1px solid #1f6f3b; font-weight:900;"
            )

    ## ----------------------------
    ## Save output to Downloads
    ## ----------------------------
    def save_terminal_output(self):
        try:
            downloads = Path.home() / "Downloads"
            downloads.mkdir(parents=True, exist_ok=True)

            ts = time.strftime("%Y%m%d_%H%M%S")
            user_part = self.last_run_username.strip() or "unknown_user"
            path = downloads / f"broadcast_plink_{user_part}_{ts}.txt"

            lines: List[str] = []
            lines.append("=" * 92 + "\n")
            lines.append(f"RUN START • {self.last_run_started_at}\n")
            lines.append(f"EXECUTED BY: {self.last_run_username}\n")
            lines.append(f"TARGET MODE: {self._target_mode_name()}\n")
            lines.append(f"COMMAND: {self.last_run_command}\n")
            lines.append("=" * 92 + "\n\n")

            servers = [s for s in self.all_servers if s.id in self.server_buffers]
            servers.sort(key=lambda s: (s.customer, s.env != "PROD", s.name))

            for s in servers:
                state = self.server_state.get(s.id, "PENDING")
                rc = self.server_exit.get(s.id, None)
                header = f"{s.customer} | {s.env} | {s.name} | {s.host}:{s.port}  ==>  {state}"
                if rc is not None:
                    header += f" (exit={rc})"

                lines.append(header + "\n")
                lines.append("-" * 92 + "\n")
                lines.extend(self.server_buffers.get(s.id, []))
                if lines and (not lines[-1].endswith("\n")):
                    lines.append("\n")
                lines.append("\n")

            path.write_text("".join(lines), encoding="utf-8")
            QMessageBox.information(self, "Saved", f"Saved to:\n{path}")

        except Exception as e:
            QMessageBox.critical(self, "Save failed", str(e))


def main():
    app = QApplication([])
    win = BroadcastSSHWindow()
    win.show()
    app.exec()


if __name__ == "__main__":
    main()
