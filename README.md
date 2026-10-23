# WAF MX Detector

A small Windows tray application that tells you **which Imperva SecureSphere MX gateway handled a URL**. Hover over a link (or select it and press a hotkey) in Chrome, Teams, Excel or most other apps; the tool sends one tightly restricted probe request to the URL's host, reads the WAF's HTML response, extracts the MX identifier with rules you configure, and shows it in a small floating tooltip.

Nothing organisation-specific is built in. The domain allowlist starts **empty**, so you add your own domains in the Settings window. Extraction rules for the standard SecureSphere block-page wording (`The incident ID is … / <number> - <MX id>` and `MX ID is <id>`) are built in, so no regex is needed to get started.

## How it works

1. **Capture** the text you pointed at:
   - *Hotkey* (default `Ctrl+Alt+M`): copies the current selection (and restores your clipboard), then falls back to the element under the mouse pointer (Windows UI Automation), then to text already on the clipboard.
   - *Hover* (off by default): after the pointer rests on a link for the dwell time (optionally only while holding Ctrl) the element under it is read through UI Automation.
2. **Validate** every candidate URL against your allowlist (scheme, credentials, IP literals, ports, exact/wildcard host match).
3. **Probe** `https://<host><probe path>`. Your original path and query string are never sent, so tokens in links do not leak.
4. **Extract** the MX id from the response body or headers using your ordered rules, then check it against an MX-value pattern.
5. **Show** one of: the MX id (green), "No MX identifier" with the HTTP status (amber, a generic error page), "Request failed" with the reason (red), or "URL not allowed" / "No URL found" (grey).

## Quick start (from source)

```powershell
py -3.12 -m venv .venv ; .\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
pytest
python -m wafmx            # opens Settings on first run
```

Command prompt (built exe): run the tray app with `WAFMXDetector.exe` (add `--minimized` to skip the Settings window), or check one URL and read the result in the console:

```bat
WAFMXDetector-cli.exe --detect "https://host.example.com/anything"
echo %ERRORLEVEL%
```
Output is `mx_found: <id>` (exit 0), or `no_mx` / `failed` / `not_allowed` / `no_url` with a reason (exit 2). It uses the same saved settings as the tray app. (`WAFMXDetector.exe --detect` works too, but as a windowed program cmd does not wait for it; use `start /wait` or the CLI exe.)

From source: `python -m wafmx --detect "https://host.example.com/anything"` runs one detection with the saved settings and exits (`0` = MX found, `2` otherwise). `--config path.json` uses another config file.

## Build the standalone .exe

```powershell
powershell -ExecutionPolicy Bypass -File packaging\build.ps1            # folder build (recommended)
powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -OneFile   # single exe
```

Output is `dist\WAFMXDetector\` containing `WAFMXDetector.exe` (the tray app) and `WAFMXDetector-cli.exe` (console tool); zip that folder and hand it out. No Python is needed on the target machine. The GitHub Actions workflow `build-windows-exe` does the same on a Windows runner and publishes a zip plus SHA-256.

Notes: the folder build starts faster and triggers fewer antivirus false positives than `-OneFile`. Unsigned PyInstaller binaries can still be flagged; sign the exe with your organisation's code-signing certificate for managed fleets.

## Configure

Everything is in **Tray icon → Settings**. Saved to `%APPDATA%\WAFMXDetector\config.json` (written atomically; a corrupt file is set aside as `config.json.bad`). `config.example.json` shows the format with placeholder domains. Settings can be exported/imported as JSON for sharing a team baseline (it contains no secrets).

| Tab | What you set |
|---|---|
| Targets | Allowed domains (`example.com` exact, `*.example.com` subdomains), probe path and method, status filter, allowed ports, http / private-IP opt-ins |
| Extraction | Ordered rules (regex, text between markers, `<meta>`, response header), MX-value sanity pattern, a **rule tester** where you paste synthetic sample HTML |
| Triggers | Hotkey, hover on/off, dwell, required modifier key, clipboard fallback and its program blocklist |
| Network | Timeouts, size cap, redirects, TLS verification, Windows trust store, extra CA bundle, User-Agent, extra headers |
| General | Tooltip, cache, history, start with Windows, log level, import/export |

The Settings window also has a **Test probe** box that runs a detection with the unsaved settings.

### Extraction rules

The built-in rules read the MX id from the standard block-page sentence (the part after the dash in `The incident ID is N/A / <number> - <MX id>.`) or from an explicit `MX ID is <id>`. If your gateways word the page differently, open the Extraction tab, paste a *sanitised or synthetic* copy of the page into the tester, and add a rule until it reports `[HIT]`. **Restore built-in rules** brings the defaults back. Please do not paste real internal responses into issues or commits.

## What works where (read this)

- **Hotkey after selecting text** works in nearly everything that supports Ctrl+C: browsers, Teams, Excel cells, Office, editors.
- **Hover** depends on what each app exposes through UI Automation. Chrome/Edge expose link targets only while accessibility is active (it normally switches on when a UI Automation client such as this app queries it; if not, enable `chrome://accessibility`). Teams, Outlook and Excel generally expose the displayed text, which is the URL when the link text *is* the URL. Where hover shows nothing, select the text and use the hotkey, or right-click → *Copy link address* and use the hotkey or **tray → Detect URL on clipboard**.
- Console programs (cmd, PowerShell, Windows Terminal) are on a blocklist for the Ctrl+C step because Ctrl+C there interrupts running jobs. Hover and clipboard still work for them.
- Clipboard restore handles text. If the clipboard holds an image or files, the selection-copy step is skipped rather than overwriting them.
- Clipboard-history tools (Win+V, third-party managers) may record the momentary copy made by the hotkey.
- Elevated (administrator) windows are not readable from a non-elevated process; run the app elevated if you need those.

## Security model (summary; details in SECURITY.md)

- Requests go only to hosts matching the allowlist, re-checked on **every redirect**; redirects to other hosts, to plain http, or beyond the hop limit are refused.
- TLS verification is on by default using the Windows certificate store (so corporate CAs work); an extra PEM bundle can be added. Turning verification off is a deliberate, confirmed setting.
- DNS is resolved once, loopback/private/link-local/reserved results are refused (unless opted in), and the connection is pinned to the vetted address.
- Hard limits on connect/read/total time and body size; no cookies, credentials or proxy variables are used.
- History stores host, outcome, MX and time only, never paths or query strings, and is off by default.

## Layout

```
src/wafmx/   config, urlutil, fetcher, extractor, service, store (core, cross-platform)
src/wafmx/win/   hotkey, hover, uia, capture, winapi, autostart (Windows only)
src/wafmx/ui/    tooltip, tray, settings_ui, icon (Tk + pystray)
tests/           pytest suite (local TLS test servers, synthetic pages only)
packaging/       build.ps1 (PyInstaller), icon + example-config generators
```

## Known limits

- The Windows-specific layers (hotkey, UI Automation, clipboard capture, Tk UI, tray) cannot be exercised on Linux CI; the core is covered by tests on Linux and Windows, and the Windows layers need a manual pass on a real desktop.
- User-supplied regular expressions run in-process; a pathological pattern can stall one detection (input is capped at the size limit). Keep rules simple.
- Per-monitor DPI and multi-monitor tooltip placement are handled but have only been designed, not tested on every scaling combination.

## License

MIT. See `LICENSE`.
