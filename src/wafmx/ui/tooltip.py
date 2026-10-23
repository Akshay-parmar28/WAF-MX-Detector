"""Small floating result tooltip.

Never takes keyboard focus (WS_EX_NOACTIVATE), stays on top, closes by timer,
Escape-free by design. Click it to copy the MX identifier.
"""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont

from ..service import Outcome, Status

_COLORS = {
    "checking": ("#1d4ed8", "#eff6ff"),
    Status.MX_FOUND: ("#15803d", "#f0fdf4"),
    Status.NO_MX: ("#b45309", "#fffbeb"),
    Status.FAILED: ("#b91c1c", "#fef2f2"),
    Status.NOT_ALLOWED: ("#475569", "#f1f5f9"),
    Status.NO_URL: ("#475569", "#f1f5f9"),
}
_TITLES = {
    Status.NO_MX: "No MX identifier",
    Status.FAILED: "Request failed",
    Status.NOT_ALLOWED: "URL not allowed",
    Status.NO_URL: "No URL found",
}


class Tooltip:
    def __init__(self, root: tk.Tk, font_size: int = 10):
        self.root = root
        self.font_size = font_size
        self._win: tk.Toplevel | None = None
        self._after: str | None = None
        self._copy_text = ""
        self._rect: tuple[int, int, int, int] | None = None  # cached so other threads can hit-test safely

    # -- public ----------------------------------------------------------------
    def show_checking(self, x: int, y: int, host_hint: str = "") -> None:
        self._render("checking", "Checking…", host_hint, x, y, seconds=30)

    def show_outcome(self, out: Outcome, x: int, y: int, seconds: float) -> None:
        if out.status is Status.MX_FOUND:
            title = out.mx
            sub = f"{out.host} · HTTP {out.http_status}" + (" · cached" if out.cached else "")
            self._copy_text = out.mx
        else:
            title = _TITLES[out.status]
            sub = out.message if out.status is not Status.NO_MX else out.message
            self._copy_text = ""
        self._render(out.status, title, sub, x, y, seconds)

    def hide(self) -> None:
        if self._after:
            try:
                self.root.after_cancel(self._after)
            except tk.TclError:
                pass
            self._after = None
        if self._win is not None:
            try:
                self._win.destroy()
            except tk.TclError:
                pass
            self._win = None
        self._rect = None

    def contains_point(self, x: int, y: int) -> bool:
        """Thread-safe: uses a cached rectangle, never touches Tk."""
        r = self._rect
        return bool(r) and r[0] <= x <= r[2] and r[1] <= y <= r[3]

    # -- internals -------------------------------------------------------------
    def _render(self, key, title: str, sub: str, x: int, y: int, seconds: float) -> None:
        self.hide()
        accent, bg = _COLORS[key]
        w = tk.Toplevel(self.root)
        w.withdraw()
        w.overrideredirect(True)
        w.attributes("-topmost", True)
        try:
            w.attributes("-alpha", 0.97)
        except tk.TclError:
            pass
        base = tkfont.nametofont("TkDefaultFont").actual()["family"]
        outer = tk.Frame(w, bg=accent, padx=1, pady=1)
        outer.pack()
        inner = tk.Frame(outer, bg=bg, padx=12, pady=8)
        inner.pack()
        tk.Frame(inner, bg=accent, width=4).pack(side="left", fill="y", padx=(0, 10))
        col = tk.Frame(inner, bg=bg)
        col.pack(side="left")
        tk.Label(col, text=title, bg=bg, fg=accent, font=(base, self.font_size + 4, "bold"), anchor="w", justify="left").pack(anchor="w")
        if sub:
            tk.Label(col, text=sub, bg=bg, fg="#334155", font=(base, max(self.font_size - 1, 7)), anchor="w", justify="left", wraplength=360).pack(anchor="w")
        if self._copy_text and key is Status.MX_FOUND:
            tk.Label(col, text="click to copy", bg=bg, fg="#64748b", font=(base, max(self.font_size - 2, 7))).pack(anchor="w")
        for widget in (w, outer, inner, col, *col.winfo_children()):
            widget.bind("<Button-1>", self._on_click)
        w.update_idletasks()
        px, py = self._clamp(x + 16, y + 20, w.winfo_reqwidth(), w.winfo_reqheight())
        w.geometry(f"+{px}+{py}")
        self._rect = (px, py, px + w.winfo_reqwidth(), py + w.winfo_reqheight())
        w.deiconify()
        self._no_activate(w)
        self._win = w
        self._after = self.root.after(int(seconds * 1000), self.hide)

    def _on_click(self, _e=None) -> None:
        if self._copy_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(self._copy_text)
            self.root.update()
        self.hide()

    def _clamp(self, x: int, y: int, w: int, h: int) -> tuple[int, int]:
        left, top, right, bottom = 0, 0, self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        if sys.platform == "win32":
            import ctypes

            gm = ctypes.windll.user32.GetSystemMetrics
            left, top = gm(76), gm(77)  # SM_X/YVIRTUALSCREEN
            right, bottom = left + gm(78), top + gm(79)
        if x + w > right:
            x = max(left, x - w - 32)
        if y + h > bottom:
            y = max(top, y - h - 40)
        return max(left, x), max(top, y)

    @staticmethod
    def _no_activate(win: tk.Toplevel) -> None:
        if sys.platform != "win32":
            return
        import ctypes

        u = ctypes.windll.user32
        hwnd = u.GetParent(win.winfo_id()) or win.winfo_id()
        GWL_EXSTYLE, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW = -20, 0x08000000, 0x00000080
        style = u.GetWindowLongW(hwnd, GWL_EXSTYLE)
        u.SetWindowLongW(hwnd, GWL_EXSTYLE, style | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW)
