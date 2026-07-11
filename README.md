# Nessus Authentication Scan to VA Converter

A Windows-friendly Python GUI that copies an existing Nessus authentication-validation scan and converts only the copy into a vulnerability-assessment scan.

## Key behavior

- Connects to Nessus with an **Access Key** and **Secret Key**.
- Loads scans from a selected Nessus folder.
- Copies the selected authentication scan before making changes.
- Converts the copied scan to **Basic Network Scan** or **Advanced Scan**.
- Keeps the original authentication scan unchanged.
- Verifies non-secret credential references before and after conversion.
- Supports preview-only and single-test modes.
- Can delete a copied scan automatically when conversion fails.
- Can optionally launch the converted VA scan after verification.

## Important limitation

The application does not retrieve, display, or decrypt the saved password. It attempts to reuse the credential already stored in the copied Nessus scan.

## Requirements

- Python 3.9 or newer
- Nessus Professional or Nessus Manager API access
- API-key user permissions to view, copy, edit, and optionally launch the scans

Install the dependency:

```bash
python -m pip install -r requirements.txt
```

## Run

```bash
python nessus_auth_to_va_converter.py
```

## Recommended first test

1. Keep **Preview only** enabled.
2. Keep **Single-test mode** enabled.
3. Select one authentication scan that previously passed.
4. Select **Basic Network Scan** as the VA template.
5. Review the preview result.
6. Disable **Preview only** and convert only that one scan.
7. Confirm the copied scan still contains the expected credential configuration.
8. Launch it and verify `Credentialed checks : yes` in Nessus plugin 19506.

## Safety notes

- Test with one scan before processing multiple assets.
- Keep the original authentication scans until the converted VA scans are validated.
- Use an approved service account or PAM-managed credential.
- Do not commit Nessus API keys, passwords, exports, or scan reports to this repository.
