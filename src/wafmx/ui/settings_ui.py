"""Tabbed settings window. Edits a copy; nothing changes until Save succeeds."""

from __future__ import annotations

import copy
import dataclasses
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from ..config import ExtractionRule, Settings
from ..extractor import explain
from ..service import Outcome
from ..urlutil import normalize_domain_pattern

PAD = {"padx": 8, "pady": 4}


class RuleDialog(tk.Toplevel):
    def __init__(self, parent: tk.Misc, rule: ExtractionRule | None):
        super().__init__(parent)
        self.title("Extraction rule")
        self.transient(parent)
        self.resizable(False, False)
        self.result: ExtractionRule | None = None
        r = rule or ExtractionRule(name="New rule")
        self.v_name = tk.StringVar(value=r.name)
        self.v_kind = tk.StringVar(value=r.kind)
        self.v_pat = tk.StringVar(value=r.pattern)
        self.v_suf = tk.StringVar(value=r.suffix)
        self.v_grp = tk.StringVar(value=str(r.group))
        self.v_on = tk.BooleanVar(value=r.enabled)
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        rows = [("Name", ttk.Entry(f, textvariable=self.v_name, width=48)),
                ("Kind", ttk.Combobox(f, textvariable=self.v_kind, values=ExtractionRule.VALID_KINDS, state="readonly", width=12)),
                ("Pattern / prefix / name", ttk.Entry(f, textvariable=self.v_pat, width=48)),
                ("Suffix (between only)", ttk.Entry(f, textvariable=self.v_suf, width=48)),
                ("Regex group", ttk.Entry(f, textvariable=self.v_grp, width=6))]
        for i, (label, w) in enumerate(rows):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", **PAD)
            w.grid(row=i, column=1, sticky="w", **PAD)
        ttk.Checkbutton(f, text="Enabled", variable=self.v_on).grid(row=5, column=1, sticky="w", **PAD)
        ttk.Label(
            f,
            text="regex: group N of the match is the MX id.  between: text between prefix and suffix.\n"
            "meta: pattern is the <meta name>.  header: pattern is the HTTP header name.",
            foreground="#475569",
        ).grid(row=6, column=0, columnspan=2, sticky="w", **PAD)
        b = ttk.Frame(f)
        b.grid(row=7, column=0, columnspan=2, sticky="e", pady=(8, 0))
        ttk.Button(b, text="OK", command=self._ok).pack(side="left", padx=4)
        ttk.Button(b, text="Cancel", command=self.destroy).pack(side="left")
        self.grab_set()
        self.wait_visibility()
        self.focus_set()

    def _ok(self) -> None:
        try:
            grp = int(self.v_grp.get() or "1")
            if grp < 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Rule", "Regex group must be a non-negative number", parent=self)
            return
        rule = ExtractionRule(self.v_name.get().strip() or "rule", self.v_kind.get(), self.v_pat.get(), self.v_suf.get(), grp, self.v_on.get())
        tmp = Settings(rules=[rule])
        bad = [p for p in tmp.validate() if p.startswith("Rule")]
        if bad:
            messagebox.showerror("Rule", "\n".join(bad), parent=self)
            return
        self.result = rule
        self.destroy()


class SettingsWindow(tk.Toplevel):
    def __init__(
        self,
        root: tk.Tk,
        settings: Settings,
        on_save: Callable[[Settings], None],
        probe: Callable[[Settings, str], Outcome],
        history_rows: Callable[[], list],
        clear_history: Callable[[], None],
        export_cfg: Callable[[Settings, Path], None],
        import_cfg: Callable[[Path], Settings],
    ):
        super().__init__(root)
        self.root_ = root
        self.base = settings
        self.on_save = on_save
        self.probe = probe
        self.history_rows = history_rows
        self.clear_history = clear_history
        self.export_cfg = export_cfg
        self.import_cfg = import_cfg
        self.title("WAF MX Detector – Settings")
        self.geometry("780x620")
        self.minsize(720, 560)
        self.rules: list[ExtractionRule] = []
        self.vars: dict[str, tk.Variable] = {}

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        self._tab_targets(nb)
        self._tab_extraction(nb)
        self._tab_triggers(nb)
        self._tab_network(nb)
        self._tab_general(nb)
        self._bottom()
        self.load(settings)
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    # ------------------------------------------------------------------ helpers
    def _var(self, name: str, kind: type = str, default=None) -> tk.Variable:
        v = {str: tk.StringVar, bool: tk.BooleanVar, int: tk.StringVar, float: tk.StringVar}[kind]()
        self.vars[name] = v
        return v

    def _row(self, parent, r: int, label: str, widget, hint: str = "") -> None:
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", **PAD)
        widget.grid(row=r, column=1, sticky="w", **PAD)
        if hint:
            ttk.Label(parent, text=hint, foreground="#64748b").grid(row=r, column=2, sticky="w", **PAD)

    # ------------------------------------------------------------------ tabs
    def _tab_targets(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Targets")
        ttk.Label(f, text="Allowed domains (only these can ever be contacted)").grid(row=0, column=0, columnspan=3, sticky="w", **PAD)
        self.lb = tk.Listbox(f, height=8, width=44, activestyle="none")
        self.lb.grid(row=1, column=0, rowspan=3, sticky="nsw", **PAD)
        self.v_newdom = tk.StringVar()
        e = ttk.Entry(f, textvariable=self.v_newdom, width=34)
        e.grid(row=1, column=1, sticky="we", **PAD)
        e.bind("<Return>", lambda _e: self._add_domain())
        ttk.Button(f, text="Add", command=self._add_domain).grid(row=1, column=2, sticky="w", **PAD)
        ttk.Button(f, text="Remove selected", command=self._del_domain).grid(row=2, column=1, sticky="w", **PAD)
        ttk.Label(f, text="Use example.com for an exact host, *.example.com for any subdomain.\nSeparate several entries with commas or spaces.", foreground="#64748b").grid(row=3, column=1, columnspan=2, sticky="nw", **PAD)
        g = ttk.LabelFrame(f, text="Probe request", padding=8)
        g.grid(row=4, column=0, columnspan=3, sticky="we", pady=10)
        self._row(g, 0, "Probe path", ttk.Entry(g, textvariable=self._var("probe_path"), width=36), "sent instead of the original path")
        self._row(g, 1, "Method", ttk.Combobox(g, textvariable=self._var("probe_method"), values=["GET", "HEAD", "POST"], state="readonly", width=8))
        self._row(g, 2, "Only extract for HTTP status", ttk.Entry(g, textvariable=self._var("match_status_codes"), width=20), "comma list, empty = any")
        self._row(g, 3, "Allowed ports", ttk.Entry(g, textvariable=self._var("allowed_ports"), width=20), "comma list")
        s = ttk.LabelFrame(f, text="Safety", padding=8)
        s.grid(row=5, column=0, columnspan=3, sticky="we")
        ttk.Checkbutton(s, text="Allow plain http:// targets (not recommended)", variable=self._var("allow_http", bool)).pack(anchor="w")
        ttk.Checkbutton(s, text="Allow hosts that resolve to private / loopback addresses", variable=self._var("allow_private_ips", bool)).pack(anchor="w")

    def _tab_extraction(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Extraction")
        ttk.Label(f, text="Rules are tried top to bottom; the first valid result wins.").pack(anchor="w")
        cols = ("name", "kind", "pattern", "suffix", "group", "on")
        self.tree = ttk.Treeview(f, columns=cols, show="headings", height=5, selectmode="browse")
        for c, w in zip(cols, (150, 70, 300, 90, 50, 40)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, stretch=c == "pattern")
        self.tree.pack(fill="x", pady=4)
        self.tree.bind("<Double-1>", lambda _e: self._edit_rule())
        bar = ttk.Frame(f)
        bar.pack(anchor="w")
        for text, cmd in (("Add", self._add_rule), ("Edit", self._edit_rule), ("Remove", self._del_rule), ("Up", lambda: self._move_rule(-1)), ("Down", lambda: self._move_rule(1))):
            ttk.Button(bar, text=text, command=cmd, width=8).pack(side="left", padx=2)
        r = ttk.Frame(f)
        r.pack(fill="x", pady=6)
        ttk.Label(r, text="MX value must fully match").pack(side="left")
        ttk.Entry(r, textvariable=self._var("mx_value_pattern"), width=40).pack(side="left", padx=6)
        t = ttk.LabelFrame(f, text="Test rules with sample text (paste a synthetic HTML page – never real internal responses)", padding=6)
        t.pack(fill="both", expand=True)
        self.sample = tk.Text(t, height=6, wrap="none", font=("Consolas", 9))
        self.sample.pack(fill="both", expand=True)
        row = ttk.Frame(t)
        row.pack(fill="x", pady=4)
        ttk.Button(row, text="Run rules", command=self._run_rules).pack(side="left")
        ttk.Label(row, text="Optional headers (Name: value per line) →").pack(side="left", padx=8)
        self.sample_hdr = tk.Text(t, height=2, wrap="none", font=("Consolas", 9))
        self.sample_hdr.pack(fill="x")
        self.rule_out = tk.Text(t, height=4, state="disabled", font=("Consolas", 9), background="#f8fafc")
        self.rule_out.pack(fill="x", pady=(4, 0))

    def _tab_triggers(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Triggers")
        ttk.Checkbutton(f, text="Enable global hotkey", variable=self._var("hotkey_enabled", bool)).grid(row=0, column=0, columnspan=2, sticky="w", **PAD)
        self._row(f, 1, "Hotkey", ttk.Entry(f, textvariable=self._var("hotkey"), width=22), "e.g. ctrl+alt+m, ctrl+shift+f9")
        ttk.Checkbutton(f, text="Enable hover detection", variable=self._var("hover_enabled", bool)).grid(row=2, column=0, columnspan=2, sticky="w", **PAD)
        self._row(f, 3, "Hover dwell (ms)", ttk.Entry(f, textvariable=self._var("hover_dwell_ms"), width=10))
        self._row(f, 4, "Require key while hovering", ttk.Combobox(f, textvariable=self._var("hover_modifier"), values=["", "ctrl", "shift", "alt"], state="readonly", width=8), "recommended: ctrl (avoids accidental probes)")
        g = ttk.LabelFrame(f, text="Clipboard fallback (hotkey only)", padding=8)
        g.grid(row=5, column=0, columnspan=3, sticky="we", pady=10)
        ttk.Checkbutton(g, text="Copy the current selection (Ctrl+C) when the hotkey is pressed", variable=self._var("use_clipboard_fallback", bool)).pack(anchor="w")
        ttk.Checkbutton(g, text="Restore the previous clipboard text afterwards", variable=self._var("restore_clipboard", bool)).pack(anchor="w")
        ttk.Label(g, text="Never send Ctrl+C to these programs (comma list):").pack(anchor="w", pady=(6, 0))
        ttk.Entry(g, textvariable=self._var("clipboard_blocklist"), width=70).pack(anchor="w")
        ttk.Label(f, text="Hover reads links through Windows UI Automation. Browsers expose link targets only\nwhile accessibility is active; if hover misses a link, select it and use the hotkey.", foreground="#64748b").grid(row=6, column=0, columnspan=3, sticky="w", **PAD)

    def _tab_network(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="Network")
        items = [
            ("Connect timeout (s)", "connect_timeout"), ("Read timeout (s)", "read_timeout"), ("Total timeout (s)", "total_timeout"),
            ("Max response (bytes)", "max_response_bytes"), ("Max redirects", "max_redirects"),
        ]
        for i, (label, key) in enumerate(items):
            self._row(f, i, label, ttk.Entry(f, textvariable=self._var(key), width=12))
        ttk.Checkbutton(f, text="Follow redirects (each hop re-checked against the allowlist)", variable=self._var("follow_redirects", bool)).grid(row=5, column=0, columnspan=3, sticky="w", **PAD)
        ttk.Checkbutton(f, text="Verify TLS certificates", variable=self._var("verify_tls", bool)).grid(row=6, column=0, columnspan=3, sticky="w", **PAD)
        ttk.Checkbutton(f, text="Use the Windows certificate store (needed for corporate CAs)", variable=self._var("use_system_trust_store", bool)).grid(row=7, column=0, columnspan=3, sticky="w", **PAD)
        ca = ttk.Frame(f)
        ca.grid(row=8, column=1, sticky="w", **PAD)
        ttk.Entry(ca, textvariable=self._var("ca_bundle_path"), width=40).pack(side="left")
        ttk.Button(ca, text="Browse…", command=self._pick_ca).pack(side="left", padx=4)
        ttk.Label(f, text="Extra CA bundle (PEM)").grid(row=8, column=0, sticky="w", **PAD)
        self._row(f, 9, "User-Agent", ttk.Entry(f, textvariable=self._var("user_agent"), width=40))
        ttk.Label(f, text="Extra request headers").grid(row=10, column=0, sticky="nw", **PAD)
        self.hdr_text = tk.Text(f, height=4, width=48, font=("Consolas", 9))
        self.hdr_text.grid(row=10, column=1, sticky="w", **PAD)
        ttk.Label(f, text="Name: value, one per line.\nHost, Cookie and Authorization are ignored.", foreground="#64748b").grid(row=10, column=2, sticky="nw", **PAD)

    def _tab_general(self, nb: ttk.Notebook) -> None:
        f = ttk.Frame(nb, padding=8)
        nb.add(f, text="General")
        self._row(f, 0, "Tooltip duration (s)", ttk.Entry(f, textvariable=self._var("tooltip_seconds"), width=8))
        self._row(f, 1, "Tooltip font size", ttk.Entry(f, textvariable=self._var("tooltip_font_size"), width=8))
        ttk.Checkbutton(f, text="Cache results", variable=self._var("cache_enabled", bool)).grid(row=2, column=0, sticky="w", **PAD)
        self._row(f, 3, "Cache lifetime (s)", ttk.Entry(f, textvariable=self._var("cache_ttl_seconds"), width=8))
        ttk.Checkbutton(f, text="Keep local history (host, MX and time only – never full URLs)", variable=self._var("history_enabled", bool)).grid(row=4, column=0, columnspan=3, sticky="w", **PAD)
        self._row(f, 5, "History entries", ttk.Entry(f, textvariable=self._var("history_max_entries"), width=8))
        hb = ttk.Frame(f)
        hb.grid(row=6, column=1, sticky="w", **PAD)
        ttk.Button(hb, text="View history", command=self._show_history).pack(side="left")
        ttk.Button(hb, text="Clear history", command=self._clear_history).pack(side="left", padx=6)
        ttk.Checkbutton(f, text="Start with Windows", variable=self._var("start_with_windows", bool)).grid(row=7, column=0, columnspan=2, sticky="w", **PAD)
        self._row(f, 8, "Log level", ttk.Combobox(f, textvariable=self._var("log_level"), values=["DEBUG", "INFO", "WARNING", "ERROR"], state="readonly", width=10))
        io = ttk.Frame(f)
        io.grid(row=9, column=0, columnspan=3, sticky="w", pady=14)
        ttk.Button(io, text="Export settings…", command=self._export).pack(side="left", padx=4)
        ttk.Button(io, text="Import settings…", command=self._import).pack(side="left", padx=4)
        ttk.Button(io, text="Reset to defaults", command=lambda: self.load(Settings())).pack(side="left", padx=4)

    def _bottom(self) -> None:
        box = ttk.LabelFrame(self, text="Test probe with the settings above (nothing is saved)", padding=6)
        box.pack(fill="x", padx=8, pady=6)
        self.v_probe_url = tk.StringVar()
        ttk.Entry(box, textvariable=self.v_probe_url, width=60).pack(side="left", padx=(0, 6))
        self.btn_probe = ttk.Button(box, text="Test", command=self._run_probe)
        self.btn_probe.pack(side="left")
        self.probe_label = ttk.Label(box, text="", wraplength=260)
        self.probe_label.pack(side="left", padx=8)
        b = ttk.Frame(self)
        b.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(b, text="Save", command=self._save).pack(side="right", padx=4)
        ttk.Button(b, text="Close", command=self.destroy).pack(side="right")

    # ------------------------------------------------------------------ load / collect
    def load(self, s: Settings) -> None:
        self.rules = copy.deepcopy(s.rules)
        self.lb.delete(0, "end")
        for d in s.allowed_domains:
            self.lb.insert("end", d)
        lists = {"match_status_codes": ", ".join(map(str, s.match_status_codes)), "allowed_ports": ", ".join(map(str, s.allowed_ports)), "clipboard_blocklist": ", ".join(s.clipboard_blocklist)}
        for key, var in self.vars.items():
            val = lists.get(key, getattr(s, key, ""))
            var.set(val)
        self.hdr_text.delete("1.0", "end")
        self.hdr_text.insert("1.0", "\n".join(f"{k}: {v}" for k, v in s.extra_headers.items()))
        self._refresh_rules()

    def collect(self) -> Settings:
        s = dataclasses.replace(self.base)
        ints = {"hover_dwell_ms", "max_response_bytes", "max_redirects", "cache_ttl_seconds", "history_max_entries", "tooltip_font_size"}
        floats = {"connect_timeout", "read_timeout", "total_timeout", "tooltip_seconds"}
        for key, var in self.vars.items():
            raw = var.get()
            try:
                if key in ints:
                    val = int(str(raw).strip())
                elif key in floats:
                    val = float(str(raw).strip())
                elif key in ("match_status_codes", "allowed_ports"):
                    val = [int(x) for x in str(raw).replace(";", ",").split(",") if x.strip()]
                elif key == "clipboard_blocklist":
                    val = [x.strip().lower() for x in str(raw).split(",") if x.strip()]
                elif isinstance(raw, str):
                    val = raw.strip() if key not in ("user_agent",) else raw
                else:
                    val = raw
            except ValueError:
                raise ValueError(f"'{key}' has an invalid value: {raw!r}") from None
            setattr(s, key, val)
        s.allowed_domains = list(self.lb.get(0, "end"))
        s.rules = copy.deepcopy(self.rules)
        hdrs: dict[str, str] = {}
        for line in self.hdr_text.get("1.0", "end").splitlines():
            if not line.strip():
                continue
            if ":" not in line:
                raise ValueError(f"Header line needs 'Name: value': {line!r}")
            k, v = (p.strip() for p in line.split(":", 1))
            if not k or any(c in k + v for c in "\r\n\0"):
                raise ValueError(f"Invalid header: {line!r}")
            hdrs[k] = v
        s.extra_headers = hdrs
        if not s.probe_path.startswith("/"):
            s.probe_path = "/" + s.probe_path
        return s

    # ------------------------------------------------------------------ domain list
    def _add_domain(self) -> None:
        raw = self.v_newdom.get().replace(",", " ").split()
        bad = []
        existing = set(self.lb.get(0, "end"))
        for item in raw:
            norm = normalize_domain_pattern(item)
            if norm is None:
                bad.append(item)
            elif norm not in existing:
                self.lb.insert("end", norm)
                existing.add(norm)
        if bad:
            messagebox.showerror("Domain", "Not a valid domain pattern:\n" + "\n".join(bad), parent=self)
        else:
            self.v_newdom.set("")

    def _del_domain(self) -> None:
        for i in reversed(self.lb.curselection()):
            self.lb.delete(i)

    # ------------------------------------------------------------------ rules
    def _refresh_rules(self) -> None:
        self.tree.delete(*self.tree.get_children())
        for i, r in enumerate(self.rules):
            self.tree.insert("", "end", iid=str(i), values=(r.name, r.kind, r.pattern, r.suffix, r.group, "yes" if r.enabled else "no"))

    def _selected_rule(self) -> int | None:
        sel = self.tree.selection()
        return int(sel[0]) if sel else None

    def _add_rule(self) -> None:
        d = RuleDialog(self, None)
        self.wait_window(d)
        if d.result:
            self.rules.append(d.result)
            self._refresh_rules()

    def _edit_rule(self) -> None:
        i = self._selected_rule()
        if i is None:
            return
        d = RuleDialog(self, self.rules[i])
        self.wait_window(d)
        if d.result:
            self.rules[i] = d.result
            self._refresh_rules()

    def _del_rule(self) -> None:
        i = self._selected_rule()
        if i is not None:
            del self.rules[i]
            self._refresh_rules()

    def _move_rule(self, delta: int) -> None:
        i = self._selected_rule()
        if i is None or not (0 <= i + delta < len(self.rules)):
            return
        self.rules[i], self.rules[i + delta] = self.rules[i + delta], self.rules[i]
        self._refresh_rules()
        self.tree.selection_set(str(i + delta))

    def _run_rules(self) -> None:
        headers = {}
        for line in self.sample_hdr.get("1.0", "end").splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        try:
            lines = explain(self.sample.get("1.0", "end"), headers, self.rules, self.vars["mx_value_pattern"].get())
        except Exception as e:
            lines = [f"Error: {e}"]
        self.rule_out.config(state="normal")
        self.rule_out.delete("1.0", "end")
        self.rule_out.insert("1.0", "\n".join(lines) or "No rules")
        self.rule_out.config(state="disabled")

    # ------------------------------------------------------------------ misc actions
    def _pick_ca(self) -> None:
        p = filedialog.askopenfilename(parent=self, filetypes=[("PEM", "*.pem *.crt *.cer"), ("All", "*.*")])
        if p:
            self.vars["ca_bundle_path"].set(p)

    def _run_probe(self) -> None:
        try:
            s = self.collect()
        except ValueError as e:
            self.probe_label.config(text=str(e), foreground="#b91c1c")
            return
        problems = s.validate()
        if problems:
            self.probe_label.config(text=problems[0], foreground="#b91c1c")
            return
        url = self.v_probe_url.get().strip()
        self.btn_probe.config(state="disabled")
        self.probe_label.config(text="Testing…", foreground="#1d4ed8")

        def work() -> None:
            out = self.probe(s, url)
            self.after(0, lambda: self._probe_done(out))

        threading.Thread(target=work, daemon=True).start()

    def _probe_done(self, out: Outcome) -> None:
        if not self.winfo_exists():
            return
        self.btn_probe.config(state="normal")
        ok = out.ok
        text = (f"MX: {out.mx}  (HTTP {out.http_status}, rule '{out.rule}')" if ok else f"{out.status.value}: {out.message}")
        self.probe_label.config(text=text, foreground="#15803d" if ok else "#b45309")

    def _show_history(self) -> None:
        w = tk.Toplevel(self)
        w.title("History")
        w.geometry("560x320")
        tv = ttk.Treeview(w, columns=("time", "host", "status", "mx", "http"), show="headings")
        for c, wd in (("time", 140), ("host", 190), ("status", 80), ("mx", 100), ("http", 50)):
            tv.heading(c, text=c.capitalize())
            tv.column(c, width=wd)
        tv.pack(fill="both", expand=True)
        for r in self.history_rows():
            tv.insert("", "end", values=(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r.ts)), r.host, r.status, r.mx, r.http_status or ""))

    def _clear_history(self) -> None:
        if messagebox.askyesno("History", "Delete all history entries?", parent=self):
            self.clear_history()

    def _export(self) -> None:
        try:
            s = self.collect()
        except ValueError as e:
            messagebox.showerror("Export", str(e), parent=self)
            return
        p = filedialog.asksaveasfilename(parent=self, defaultextension=".json", initialfile="wafmx-settings.json", filetypes=[("JSON", "*.json")])
        if p:
            self.export_cfg(s, Path(p))

    def _import(self) -> None:
        p = filedialog.askopenfilename(parent=self, filetypes=[("JSON", "*.json")])
        if not p:
            return
        try:
            self.load(self.import_cfg(Path(p)))
        except Exception as e:
            messagebox.showerror("Import", f"Could not import: {e}", parent=self)

    def _save(self) -> None:
        try:
            s = self.collect()
        except ValueError as e:
            messagebox.showerror("Settings", str(e), parent=self)
            return
        problems = s.validate()
        if problems:
            messagebox.showerror("Settings", "\n".join(problems), parent=self)
            return
        if not s.verify_tls and self.base.verify_tls:
            if not messagebox.askyesno("TLS verification off", "Disabling certificate verification lets anyone on the network impersonate the target.\nSave anyway?", icon="warning", parent=self):
                return
        if s.allow_http and not self.base.allow_http:
            if not messagebox.askyesno("Plain HTTP", "Plain http:// probes are readable and modifiable on the network.\nSave anyway?", icon="warning", parent=self):
                return
        self.base = s
        self.on_save(s)
        self.probe_label.config(text="Saved.", foreground="#15803d")
