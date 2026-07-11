#!/usr/bin/env python3
"""Nessus Authentication Scan to VA Scan Converter.

Copies each selected authentication scan, converts only the copy to a VA
scan template, verifies that a stored credential reference is still attached,
and leaves the original scan unchanged.

Dependency: requests
Run:
    python -m pip install requests
    python nessus_auth_to_va_converter.py
"""

from __future__ import annotations

import copy
import csv
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlparse

import tkinter as tk
from tkinter import filedialog, messagebox, ttk

try:
    import requests
    from requests import Response, Session
except ImportError as exc:
    raise SystemExit(
        "The requests package is required. Install it with: "
        "python -m pip install requests"
    ) from exc


APP_TITLE = "Nessus Authentication Scan to VA Converter"
APP_VERSION = "1.0"
PREFERRED_TEMPLATES = ("basic network scan", "advanced scan")
PRESERVE_KEYS = {
    "description", "scanner_id", "text_targets", "target_groups", "emails",
    "email", "acls", "network_id", "timeout_action", "scan_time_window",
    "host_tagging", "asset_tagging", "resolve_names", "safe_checks",
    "thorough_tests", "max_hosts", "max_checks", "network_receive_timeout",
    "read_timeout", "connect_timeout", "max_retries", "report_verbosity",
    "report_superseded_patches", "silent_dependencies",
}


@dataclass
class Folder:
    folder_id: int
    name: str
    folder_type: str = ""

    @property
    def display(self) -> str:
        return f"{self.name}  [ID: {self.folder_id}]"


@dataclass
class Template:
    uuid: str
    title: str

    @property
    def display(self) -> str:
        note = ""
        if self.title.lower() == "basic network scan":
            note = "  (Recommended)"
        elif self.title.lower() == "advanced scan":
            note = "  (Review plugins after conversion)"
        return self.title + note


@dataclass
class Scan:
    scan_id: int
    name: str
    folder_id: Optional[int]
    status: str = ""


@dataclass
class ConversionResult:
    source_scan_id: int
    source_name: str
    copied_scan_id: Optional[int]
    copied_name: str
    status: str
    message: str
    original_credentials: int = 0
    copied_credentials: int = 0
    final_credentials: int = 0
    launched: bool = False


def clean(value: Any) -> str:
    return "" if value is None else str(value).strip()


def validate_url(value: str) -> Tuple[bool, str]:
    url = clean(value).rstrip("/")
    if not url:
        return False, "Enter the Nessus URL."
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        return False, "The Nessus URL must start with http:// or https://."
    if not parsed.hostname:
        return False, "The Nessus URL must contain a hostname or IP address."
    return True, url


def friendly_error(error: Any, action: str) -> str:
    raw = clean(error)
    low = raw.lower()
    if "http 401" in low or "unauthorized" in low:
        return f"{action}: API keys were rejected. Copy or regenerate the API keys."
    if "http 403" in low or "forbidden" in low:
        return (
            f"{action}: permission denied. The API-key user needs Can View and "
            "Can Edit permission on the scan."
        )
    if "http 404" in low or "not found" in low:
        return f"{action}: scan, folder, or template was not found. Reload and retry."
    if "http 400" in low:
        return f"{action}: Nessus rejected the update payload. Details: {raw}"
    if "timeout" in low:
        return f"{action}: the Nessus request timed out. Retry later."
    if "certificate verify failed" in low or "ssl" in low:
        return (
            f"{action}: TLS certificate validation failed. For a self-signed "
            "certificate, clear 'Verify TLS certificate'."
        )
    if "connection refused" in low or "max retries exceeded" in low:
        return f"{action}: cannot connect to Nessus. Check URL, port 8834, VPN, and service."
    return f"{action}: {raw or 'Unknown error'}"


def safe_json(response: Response) -> Dict[str, Any]:
    try:
        value = response.json()
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {"data": value}


def is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def extract_editor_settings(node: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    ui_keys = {
        "title", "label", "help", "type", "inputs", "groups", "sections",
        "modes", "options", "visible", "required",
    }

    def walk(item: Any) -> None:
        if isinstance(item, list):
            for entry in item:
                walk(entry)
            return
        if not isinstance(item, dict):
            return
        if item.get("id") is not None and "default" in item:
            result[str(item["id"])] = item.get("default")
        for key, value in item.items():
            if key not in ui_keys | {"id", "default"} and is_scalar(value):
                result.setdefault(key, value)
        for value in item.values():
            if isinstance(value, (dict, list)):
                walk(value)

    walk(node)
    return result


def credential_fingerprint(editor: Dict[str, Any]) -> List[str]:
    credentials = editor.get("credentials")
    if not isinstance(credentials, (dict, list)):
        return []
    found: Set[str] = set()

    def add(instance: Any, path: Sequence[str]) -> None:
        if not isinstance(instance, dict):
            return
        identifier = (
            instance.get("id") or instance.get("uuid")
            or instance.get("credential_uuid")
            or instance.get("managed_credential_id")
        )
        if identifier is None:
            return
        username = instance.get("username") or instance.get("user") or ""
        method = instance.get("auth_method") or ""
        found.add("|".join(["/".join(path), clean(identifier), clean(username), clean(method)]))

    def walk(item: Any, path: List[str]) -> None:
        if isinstance(item, list):
            for entry in item:
                walk(entry, path)
            return
        if not isinstance(item, dict):
            return
        local = clean(item.get("name") or item.get("title") or item.get("type"))
        new_path = path + ([local] if local else [])
        for key in ("instances", "current"):
            value = item.get(key)
            if isinstance(value, list):
                for instance in value:
                    add(instance, new_path)
            elif isinstance(value, dict):
                walk(value, new_path + [key])
        for key, value in item.items():
            if key in {"instances", "current"}:
                continue
            if isinstance(value, (dict, list)):
                walk(value, new_path + ([] if key in {"data", "types"} else [key]))

    walk(credentials, [])
    return sorted(found)


def build_va_settings(
    template_editor: Dict[str, Any],
    source_editor: Dict[str, Any],
    new_name: str,
    destination_folder_id: int,
) -> Dict[str, Any]:
    template_settings = extract_editor_settings(template_editor.get("settings", {}))
    source_settings = extract_editor_settings(source_editor.get("settings", {}))
    settings = copy.deepcopy(template_settings)
    for key in PRESERVE_KEYS:
        if source_settings.get(key) not in (None, ""):
            settings[key] = source_settings[key]
    for key in ("scanner_id", "text_targets", "description"):
        if not settings.get(key) and source_editor.get(key) not in (None, ""):
            settings[key] = source_editor[key]
    if not settings.get("text_targets") and source_editor.get("custom_targets"):
        settings["text_targets"] = source_editor["custom_targets"]
    settings["name"] = new_name
    settings["folder_id"] = int(destination_folder_id)
    if "enabled" in settings:
        settings["enabled"] = False
    return settings


def extract_copy_scan_id(response: Dict[str, Any]) -> int:
    candidates = [response.get("id"), response.get("scan_id")]
    for key in ("scan", "data"):
        item = response.get(key)
        if isinstance(item, dict):
            candidates.extend([item.get("id"), item.get("scan_id")])
    for candidate in candidates:
        try:
            value = int(candidate)
            if value > 0:
                return value
        except (TypeError, ValueError):
            pass
    raise RuntimeError("Copied scan response did not contain a recognizable scan ID.")


class NessusClient:
    def __init__(self, url: str, access_key: str, secret_key: str, verify_tls: bool):
        self.base_url = url.rstrip("/")
        self.verify_tls = verify_tls
        self.session: Session = requests.Session()
        self.session.headers.update({
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"Nessus-Auth-to-VA/{APP_VERSION}",
            "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}",
        })
        if not verify_tls:
            try:
                requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
            except Exception:
                pass

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _request(self, method: str, path: str, **kwargs: Any) -> Response:
        response = self.session.request(
            method, self._url(path), verify=self.verify_tls, timeout=120, **kwargs
        )
        if not response.ok:
            data = safe_json(response)
            message = data.get("error") or data.get("message") or response.text[:600]
            raise RuntimeError(f"HTTP {response.status_code} - {clean(message)}")
        return response

    def get_json(self, path: str) -> Dict[str, Any]:
        return safe_json(self._request("GET", path))

    def post_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return safe_json(self._request("POST", path, json=payload))

    def put_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return safe_json(self._request("PUT", path, json=payload))

    def delete(self, path: str) -> None:
        self._request("DELETE", path)

    def list_folders(self) -> List[Folder]:
        data = self.get_json("/folders")
        result: List[Folder] = []
        for item in data.get("folders", []):
            try:
                folder_id = int(item.get("id"))
            except (TypeError, ValueError):
                continue
            result.append(Folder(folder_id, clean(item.get("name")), clean(item.get("type"))))
        return sorted(result, key=lambda x: x.name.lower())

    def list_templates(self) -> List[Template]:
        data = self.get_json("/editor/scan/templates")
        items = data.get("templates") or data.get("data") or []
        if isinstance(items, dict):
            items = list(items.values())
        result: List[Template] = []
        for item in items if isinstance(items, list) else []:
            if not isinstance(item, dict):
                continue
            uuid = clean(item.get("uuid"))
            title = clean(item.get("title") or item.get("name"))
            if uuid and title:
                result.append(Template(uuid, title))
        return sorted(result, key=lambda x: x.title.lower())

    def list_scans(self) -> List[Scan]:
        data = self.get_json("/scans")
        result: List[Scan] = []
        for item in data.get("scans", []):
            try:
                scan_id = int(item.get("id"))
            except (TypeError, ValueError):
                continue
            folder_id = item.get("folder_id")
            try:
                folder_id = int(folder_id) if folder_id is not None else None
            except (TypeError, ValueError):
                folder_id = None
            result.append(Scan(scan_id, clean(item.get("name")), folder_id, clean(item.get("status"))))
        return result

    def editor_scan(self, scan_id: int) -> Dict[str, Any]:
        return self.get_json(f"/editor/scan/{scan_id}")

    def editor_template(self, template_uuid: str) -> Dict[str, Any]:
        return self.get_json(f"/editor/scan/templates/{template_uuid}")

    def copy_scan(self, scan_id: int, folder_id: int, new_name: str) -> int:
        response = self.post_json(
            f"/scans/{scan_id}/copy", {"folder_id": folder_id, "name": new_name}
        )
        return extract_copy_scan_id(response)

    def update_scan(self, scan_id: int, template_uuid: str, settings: Dict[str, Any]) -> None:
        self.put_json(f"/scans/{scan_id}", {"uuid": template_uuid, "settings": settings})

    def launch_scan(self, scan_id: int) -> None:
        self.post_json(f"/scans/{scan_id}/launch", {})

    def delete_scan(self, scan_id: int) -> None:
        self.delete(f"/scans/{scan_id}")


class ConverterApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_TITLE} v{APP_VERSION}")
        self.geometry("1350x820")
        self.minsize(1050, 680)
        self.client: Optional[NessusClient] = None
        self.folders: List[Folder] = []
        self.templates: List[Template] = []
        self.scans: List[Scan] = []
        self.folder_map: Dict[str, Folder] = {}
        self.template_map: Dict[str, Template] = {}
        self.results: List[ConversionResult] = []
        self.cancel_event = threading.Event()
        self.running = False

        self.url_var = tk.StringVar(value="https://127.0.0.1:8834")
        self.access_var = tk.StringVar()
        self.secret_var = tk.StringVar()
        self.verify_var = tk.BooleanVar(value=False)
        self.source_var = tk.StringVar()
        self.dest_var = tk.StringVar()
        self.template_var = tk.StringVar()
        self.suffix_var = tk.StringVar(value="_VA")
        self.preview_var = tk.BooleanVar(value=True)
        self.single_test_var = tk.BooleanVar(value=True)
        self.require_cred_var = tk.BooleanVar(value=True)
        self.delete_failed_var = tk.BooleanVar(value=True)
        self.launch_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Enter Nessus API details and click Test & Load.")
        self.progress_var = tk.StringVar()
        self._build_ui()

    def _build_ui(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=26)

        conn = ttk.LabelFrame(self, text="1. Nessus API Connection", padding=10)
        conn.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Label(conn, text="Nessus URL:").grid(row=0, column=0, sticky="w")
        ttk.Entry(conn, textvariable=self.url_var).grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Label(conn, text="Access Key:").grid(row=0, column=2, sticky="w")
        ttk.Entry(conn, textvariable=self.access_var, show="*").grid(row=0, column=3, sticky="ew", padx=6)
        ttk.Label(conn, text="Secret Key:").grid(row=0, column=4, sticky="w")
        ttk.Entry(conn, textvariable=self.secret_var, show="*").grid(row=0, column=5, sticky="ew", padx=6)
        ttk.Checkbutton(conn, text="Verify TLS certificate", variable=self.verify_var).grid(row=1, column=1, sticky="w", pady=(8, 0))
        self.connect_btn = ttk.Button(conn, text="Test & Load", command=self.start_connect)
        self.connect_btn.grid(row=1, column=5, sticky="e", pady=(8, 0))
        for col in (1, 3, 5):
            conn.columnconfigure(col, weight=1)

        setup = ttk.LabelFrame(self, text="2. Conversion Setup", padding=10)
        setup.pack(fill="x", padx=10, pady=6)
        ttk.Label(setup, text="Source auth folder:").grid(row=0, column=0, sticky="w")
        self.source_combo = ttk.Combobox(setup, textvariable=self.source_var, state="readonly")
        self.source_combo.grid(row=0, column=1, sticky="ew", padx=6)
        ttk.Label(setup, text="Destination VA folder:").grid(row=0, column=2, sticky="w")
        self.dest_combo = ttk.Combobox(setup, textvariable=self.dest_var, state="readonly")
        self.dest_combo.grid(row=0, column=3, sticky="ew", padx=6)
        ttk.Label(setup, text="VA template:").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.template_combo = ttk.Combobox(setup, textvariable=self.template_var, state="readonly")
        self.template_combo.grid(row=1, column=1, sticky="ew", padx=6, pady=(8, 0))
        ttk.Label(setup, text="New scan suffix:").grid(row=1, column=2, sticky="w", pady=(8, 0))
        ttk.Entry(setup, textvariable=self.suffix_var).grid(row=1, column=3, sticky="ew", padx=6, pady=(8, 0))
        self.load_btn = ttk.Button(setup, text="Load Scans", command=self.start_load_scans, state="disabled")
        self.load_btn.grid(row=0, column=4, rowspan=2, padx=(10, 0))
        setup.columnconfigure(1, weight=1)
        setup.columnconfigure(3, weight=1)

        safety = ttk.LabelFrame(self, text="3. Safety Options", padding=8)
        safety.pack(fill="x", padx=10, pady=6)
        for text, var in [
            ("Preview only", self.preview_var),
            ("Single-test mode", self.single_test_var),
            ("Require visible credential reference", self.require_cred_var),
            ("Delete failed copy", self.delete_failed_var),
            ("Launch VA scan after verification", self.launch_var),
        ]:
            ttk.Checkbutton(safety, text=text, variable=var).pack(side="left", padx=(0, 16))

        scan_frame = ttk.LabelFrame(self, text="4. Select Authentication Scans", padding=8)
        scan_frame.pack(fill="both", expand=True, padx=10, pady=6)
        self.scan_tree = ttk.Treeview(scan_frame, columns=("id", "name", "status"), show="headings", selectmode="extended")
        for col, title, width in [("id", "Scan ID", 90), ("name", "Scan Name", 600), ("status", "Status", 160)]:
            self.scan_tree.heading(col, text=title)
            self.scan_tree.column(col, width=width, anchor="w")
        self.scan_tree.pack(fill="both", expand=True)
        buttons = ttk.Frame(scan_frame)
        buttons.pack(fill="x", pady=(8, 0))
        ttk.Button(buttons, text="Select All", command=lambda: self.scan_tree.selection_set(self.scan_tree.get_children())).pack(side="left")
        ttk.Button(buttons, text="Clear", command=lambda: self.scan_tree.selection_remove(self.scan_tree.selection())).pack(side="left", padx=6)
        self.selected_btn = ttk.Button(buttons, text="Preview / Convert Selected", command=self.start_selected, state="disabled")
        self.selected_btn.pack(side="left", padx=(18, 6))
        self.all_btn = ttk.Button(buttons, text="Preview / Convert All", command=self.start_all, state="disabled")
        self.all_btn.pack(side="left")
        self.cancel_btn = ttk.Button(buttons, text="Cancel", command=self.cancel, state="disabled")
        self.cancel_btn.pack(side="right")

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=10)
        ttk.Label(self, textvariable=self.progress_var).pack(anchor="w", padx=10, pady=(4, 6))

        result_frame = ttk.LabelFrame(self, text="5. Results", padding=8)
        result_frame.pack(fill="both", expand=True, padx=10, pady=(0, 6))
        cols = ("source", "copy", "status", "creds", "launch", "message")
        self.result_tree = ttk.Treeview(result_frame, columns=cols, show="headings")
        for col, title, width in [
            ("source", "Source", 250), ("copy", "VA Copy", 250),
            ("status", "Status", 100), ("creds", "Credential refs", 150),
            ("launch", "Launched", 80), ("message", "Message", 520),
        ]:
            self.result_tree.heading(col, text=title)
            self.result_tree.column(col, width=width, anchor="w")
        self.result_tree.pack(fill="both", expand=True)

        bottom = ttk.Frame(self, padding=(10, 0, 10, 10))
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Export Results CSV", command=self.export_results).pack(side="left")
        ttk.Label(bottom, textvariable=self.status_var).pack(side="right")

    def ui(self, fn, *args: Any) -> None:
        self.after(0, lambda: fn(*args))

    def start_connect(self) -> None:
        valid, url = validate_url(self.url_var.get())
        if not valid:
            messagebox.showwarning(APP_TITLE, url)
            return
        if not self.access_var.get().strip() or not self.secret_var.get().strip():
            messagebox.showwarning(APP_TITLE, "Enter both API keys.")
            return
        self.connect_btn.configure(state="disabled")
        self.status_var.set("Connecting...")
        threading.Thread(target=self._connect_worker, args=(url,), daemon=True).start()

    def _connect_worker(self, url: str) -> None:
        try:
            client = NessusClient(url, self.access_var.get().strip(), self.secret_var.get().strip(), self.verify_var.get())
            folders = client.list_folders()
            templates = client.list_templates()
            self.ui(self._connect_complete, client, folders, templates)
        except Exception as exc:
            self.ui(self._connect_failed, friendly_error(exc, "Connection"))

    def _connect_complete(self, client: NessusClient, folders: List[Folder], templates: List[Template]) -> None:
        self.client = client
        self.folders = folders
        self.templates = templates
        self.folder_map = {f.display: f for f in folders}
        va_templates = [t for t in templates if any(x in t.title.lower() for x in PREFERRED_TEMPLATES)] or templates
        self.template_map = {t.display: t for t in va_templates}
        folder_values = list(self.folder_map)
        template_values = list(self.template_map)
        self.source_combo.configure(values=folder_values)
        self.dest_combo.configure(values=folder_values)
        self.template_combo.configure(values=template_values)
        if folder_values:
            self.source_var.set(folder_values[0])
            self.dest_var.set(folder_values[1] if len(folder_values) > 1 else folder_values[0])
        preferred = next((d for d, t in self.template_map.items() if t.title.lower() == "basic network scan"), template_values[0] if template_values else "")
        self.template_var.set(preferred)
        self.connect_btn.configure(state="normal")
        self.load_btn.configure(state="normal")
        self.status_var.set(f"Connected: {len(folders)} folders, {len(templates)} templates.")

    def _connect_failed(self, message: str) -> None:
        self.connect_btn.configure(state="normal")
        self.status_var.set("Connection failed.")
        messagebox.showerror(APP_TITLE, message)

    def start_load_scans(self) -> None:
        source = self.folder_map.get(self.source_var.get())
        if not self.client or not source:
            messagebox.showwarning(APP_TITLE, "Connect and select a source folder.")
            return
        self.load_btn.configure(state="disabled")
        threading.Thread(target=self._load_worker, args=(source,), daemon=True).start()

    def _load_worker(self, source: Folder) -> None:
        try:
            assert self.client is not None
            scans = [s for s in self.client.list_scans() if s.folder_id == source.folder_id]
            scans.sort(key=lambda s: s.name.lower())
            self.ui(self._load_complete, scans)
        except Exception as exc:
            self.ui(self._load_failed, friendly_error(exc, "Load scans"))

    def _load_complete(self, scans: List[Scan]) -> None:
        self.scans = scans
        self.scan_tree.delete(*self.scan_tree.get_children())
        for i, scan in enumerate(scans):
            self.scan_tree.insert("", "end", iid=str(i), values=(scan.scan_id, scan.name, scan.status))
        state = "normal" if scans else "disabled"
        self.selected_btn.configure(state=state)
        self.all_btn.configure(state=state)
        self.load_btn.configure(state="normal")
        self.status_var.set(f"Loaded {len(scans)} scan(s).")

    def _load_failed(self, message: str) -> None:
        self.load_btn.configure(state="normal")
        messagebox.showerror(APP_TITLE, message)

    def selected_scans(self) -> List[Scan]:
        result: List[Scan] = []
        for iid in self.scan_tree.selection():
            try:
                result.append(self.scans[int(iid)])
            except (ValueError, IndexError):
                pass
        return result

    def start_selected(self) -> None:
        scans = self.selected_scans()
        if not scans:
            messagebox.showinfo(APP_TITLE, "Select at least one scan.")
            return
        self.start_conversion(scans)

    def start_all(self) -> None:
        if self.scans:
            self.start_conversion(list(self.scans))

    def start_conversion(self, scans: List[Scan]) -> None:
        destination = self.folder_map.get(self.dest_var.get())
        template = self.template_map.get(self.template_var.get())
        if not self.client or not destination or not template:
            messagebox.showwarning(APP_TITLE, "Select destination folder and VA template.")
            return
        suffix = self.suffix_var.get()
        if not suffix:
            messagebox.showwarning(APP_TITLE, "Enter a suffix such as _VA.")
            return
        if self.single_test_var.get() and len(scans) > 1:
            scans = scans[:1]
            messagebox.showinfo(APP_TITLE, "Single-test mode is enabled; only the first scan will be processed.")
        action = "Preview" if self.preview_var.get() else "Convert"
        if not messagebox.askyesno(
            APP_TITLE,
            f"{action} {len(scans)} scan(s)?\n\nDestination: {destination.name}\nTemplate: {template.title}\n\nThe original authentication scans will not be changed.",
        ):
            return
        self.running = True
        self.cancel_event.clear()
        self.results = []
        self.result_tree.delete(*self.result_tree.get_children())
        self.progress.configure(maximum=max(1, len(scans)), value=0)
        for widget in (self.selected_btn, self.all_btn, self.load_btn, self.connect_btn):
            widget.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        threading.Thread(target=self._convert_worker, args=(scans, destination, template, suffix), daemon=True).start()

    def _convert_worker(self, scans: List[Scan], destination: Folder, template: Template, suffix: str) -> None:
        assert self.client is not None
        try:
            template_editor = self.client.editor_template(template.uuid)
        except Exception as exc:
            self.ui(self._fatal, friendly_error(exc, "Read VA template"))
            return
        results: List[ConversionResult] = []
        for index, scan in enumerate(scans, 1):
            if self.cancel_event.is_set():
                break
            copied_id: Optional[int] = None
            new_name = scan.name + suffix
            try:
                self.ui(self._set_progress, index - 1, f"Reading {scan.name}")
                source_editor = self.client.editor_scan(scan.scan_id)
                source_fp = credential_fingerprint(source_editor)
                original_count = len(source_fp)
                source_settings = extract_editor_settings(source_editor.get("settings", {}))
                target = clean(source_settings.get("text_targets") or source_editor.get("custom_targets") or source_editor.get("text_targets"))
                if self.require_cred_var.get() and original_count == 0:
                    raise RuntimeError("No visible credential reference was found in the source scan.")
                if self.preview_var.get():
                    results.append(ConversionResult(scan.scan_id, scan.name, None, new_name, "PREVIEW", f"Would convert target {target or '-'} to {template.title} in {destination.name}.", original_count))
                    self.ui(self._set_progress, index, f"Previewed {scan.name}")
                    continue
                self.ui(self._set_progress, index - 1, f"Copying {scan.name}")
                copied_id = self.client.copy_scan(scan.scan_id, destination.folder_id, new_name)
                copied_editor = self.client.editor_scan(copied_id)
                copied_fp = credential_fingerprint(copied_editor)
                copied_count = len(copied_fp)
                if self.require_cred_var.get() and copied_count < max(1, original_count):
                    raise RuntimeError("The copied scan did not retain the stored credential reference.")
                settings = build_va_settings(template_editor, copied_editor, new_name, destination.folder_id)
                if not settings.get("text_targets"):
                    raise RuntimeError("Could not identify the target IP in the copied scan.")
                if not settings.get("scanner_id"):
                    raise RuntimeError("Could not identify scanner_id; conversion stopped to avoid changing scanners.")
                self.ui(self._set_progress, index - 1, f"Converting copy {copied_id}")
                self.client.update_scan(copied_id, template.uuid, settings)
                final_editor = self.client.editor_scan(copied_id)
                final_fp = credential_fingerprint(final_editor)
                final_count = len(final_fp)
                if self.require_cred_var.get() and final_count < max(1, copied_count, original_count):
                    raise RuntimeError("Credential verification failed after template conversion.")
                launched = False
                if self.launch_var.get():
                    self.client.launch_scan(copied_id)
                    launched = True
                results.append(ConversionResult(scan.scan_id, scan.name, copied_id, new_name, "SUCCESS", f"Converted copy to {template.title}; original unchanged.", original_count, copied_count, final_count, launched))
            except Exception as exc:
                rollback = ""
                if copied_id is not None and self.delete_failed_var.get():
                    try:
                        self.client.delete_scan(copied_id)
                        rollback = " Failed copy deleted."
                        copied_id = None
                    except Exception as rollback_exc:
                        rollback = f" Failed copy could not be deleted: {clean(rollback_exc)}"
                results.append(ConversionResult(scan.scan_id, scan.name, copied_id, new_name, "FAILED", friendly_error(exc, "Conversion") + rollback))
            self.ui(self._set_progress, index, f"Processed {scan.name}")
        self.ui(self._complete, results)

    def _set_progress(self, value: int, text: str) -> None:
        self.progress.configure(value=value)
        self.progress_var.set(text)

    def _fatal(self, message: str) -> None:
        self._reset()
        messagebox.showerror(APP_TITLE, message)

    def _complete(self, results: List[ConversionResult]) -> None:
        self.results = results
        self.result_tree.delete(*self.result_tree.get_children())
        for i, result in enumerate(results):
            copy_label = f"{result.copied_scan_id} / {result.copied_name}" if result.copied_scan_id else result.copied_name
            creds = f"{result.original_credentials} → {result.copied_credentials} → {result.final_credentials}"
            self.result_tree.insert("", "end", iid=str(i), values=(f"{result.source_scan_id} / {result.source_name}", copy_label, result.status, creds, "Yes" if result.launched else "No", result.message))
        self._reset()
        success = sum(r.status == "SUCCESS" for r in results)
        preview = sum(r.status == "PREVIEW" for r in results)
        failed = sum(r.status == "FAILED" for r in results)
        summary = f"Success: {success} | Preview: {preview} | Failed: {failed}"
        self.status_var.set(summary)
        self.progress_var.set("Completed. " + summary)
        (messagebox.showwarning if failed else messagebox.showinfo)(APP_TITLE, summary)

    def _reset(self) -> None:
        self.running = False
        self.connect_btn.configure(state="normal")
        self.load_btn.configure(state="normal" if self.client else "disabled")
        state = "normal" if self.scans else "disabled"
        self.selected_btn.configure(state=state)
        self.all_btn.configure(state=state)
        self.cancel_btn.configure(state="disabled")

    def cancel(self) -> None:
        self.cancel_event.set()
        self.progress_var.set("Cancellation requested; waiting for current API call.")

    def export_results(self) -> None:
        if not self.results:
            messagebox.showinfo(APP_TITLE, "No results to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")], initialfile="Nessus_Auth_to_VA_Results.csv")
        if not path:
            return
        fields = ["source_scan_id", "source_name", "copied_scan_id", "copied_name", "status", "message", "original_credentials", "copied_credentials", "final_credentials", "launched"]
        with Path(path).open("w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for result in self.results:
                writer.writerow({field: getattr(result, field) or "" for field in fields})
        messagebox.showinfo(APP_TITLE, f"Exported: {path}")


def main() -> None:
    ConverterApp().mainloop()


if __name__ == "__main__":
    main()
