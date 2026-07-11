# Nessus Authentication Scan to Advanced Scan Converter

A Windows-friendly Python GUI that copies an existing one-IP Nessus authentication-validation scan and converts only the copy into an **Advanced Scan**. The original authentication scan remains unchanged.

## Fixed version

Run this entry point:

```bash
python nessus_auth_to_advanced_converter.py
```

The earlier GUI could appear not to work because **Preview only** was enabled by default, meaning no scan was created, and **Basic Network Scan** was preferred before **Advanced Scan**.

The fixed entry point now:

- Enables actual creation mode by default.
- Selects **Advanced Scan** automatically when Nessus returns that template.
- Keeps **Single-test mode** enabled so the first run processes only one scan.
- Keeps a failed copy for troubleshooting instead of deleting it automatically.
- Warns clearly when Preview mode is enabled.

## Files

- `nessus_auth_to_advanced_converter.py` — recommended fixed entry point.
- `nessus_auth_to_va_converter.py` — base GUI and API implementation.
- `requirements.txt` — Python dependency.

## Requirements

- Python 3.9 or newer
- Nessus Professional or Nessus Manager API access
- API-key user permission to view, copy, edit, and optionally launch scans

Install:

```bash
python -m pip install -r requirements.txt
```

Run:

```bash
python nessus_auth_to_advanced_converter.py
```

## Recommended first test

1. Connect using the Nessus Access Key and Secret Key.
2. Select the authentication-scan source folder.
3. Select the destination VA folder.
4. Confirm that **Advanced Scan** is selected.
5. Keep **Single-test mode** enabled.
6. Select one authentication scan that previously passed.
7. Click **CREATE Advanced Scan from Selected**.
8. Confirm the copied scan appears in the destination folder.
9. Launch it and verify plugin `19506` reports `Credentialed checks : yes`.

## Important limitation

The application does not retrieve, display, or decrypt the saved password. It attempts to reuse the credential already stored in the copied Nessus scan.

If Nessus copies the scan but rejects changing its template, review the Results message and the copied scan retained in the destination folder. The API-key user needs **Can View** and **Can Edit** permission.

Do not commit API keys, passwords, `.nessus` exports, reports, or client data to this repository.
