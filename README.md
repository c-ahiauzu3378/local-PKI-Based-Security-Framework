# Campus PKI Registration Authority App

Lightweight Python proof-of-concept web app for certificate provisioning,
management, and deployment in a campus Wi-Fi PKI security framework.

## Features

- Local launcher with an activation button.
- Runs the web UI on `127.0.0.1:8080`.
- Opens the selected browser after startup.
- SQLite database on the administrator computer.
- Menus for:
  - Register User
  - Register Device
  - Create Certificate
  - Deploy Certificate
  - Renew Certificate
  - Revoke Certificate
  - Settings
- Local OpenSSL mode for proof-of-concept certificate generation.
- Settings fields for local or remote OpenSSL operation.
- CSV bulk user upload.
- Certificate creation for registered devices only.

## Requirements

- Python 3.10 or newer.
- No system-wide OpenSSL installation is required if a portable OpenSSL 3+
  build is placed inside `tools/openssl`.

The web app itself uses only the Python standard library.

## Run

From this folder:

```powershell
python launcher.py
```

On Windows, if `python` points somewhere unusual, use:

```powershell
py launcher.py
```

Click **Activate Server**, choose a browser, and the app will open at:

```text
http://127.0.0.1:8080
```

On first launch, the app will ask you to create the local superadmin account.
After that, all pages require login. The superadmin can create operator
accounts from **Admin Accounts**.

You can also run the web server directly:

```powershell
python app.py
```

## Data Location

Runtime data is stored in:

```text
data/
```

This includes:

- `campus_pki_ra.sqlite3`
- local CA files
- generated certificates
- certificate signing requests
- private keys
- deployment bundles

## Proof-of-Concept Notes

The app supports local OpenSSL operations immediately. It first looks for a
bundled OpenSSL executable inside:

```text
tools/openssl/windows/bin/openssl.exe
tools/openssl/macos/bin/openssl
```

If no bundled executable is found, it falls back to the OpenSSL path configured
in Settings. Remote OpenSSL mode uses SSH/SCP to run OpenSSL on the configured
server and then copy generated certificate files back into the local repository.
Use SSH key-based access for unattended operation.

## Bulk User CSV Format

Use this header row:

```csv
user_type,first_name,middle_name,surname,email,department,faculty,identifier
```

`user_type` must be `Staff` or `Student`. Instead of `identifier`, the CSV may
use `staff_number` or `matriculation_number`.

Example:

```csv
user_type,first_name,surname,email,identifier
Student,Ada,Ngozi,Okafor,ada.okafor@example.edu.ng,Computer Science,Science,MAT-2026-001
Staff,Chinedu,Emeka,Nwosu,chinedu.nwosu@example.edu.ng,ICT,Administration,STAFF-1042
```

## Bundling OpenSSL

Because OpenSSL binaries differ between Windows and macOS, copy the correct
portable OpenSSL 3+ build into the appropriate folder before distributing the
app. See:

```text
tools/openssl/README.md
```

To verify that the bundled executable is detected correctly, run:

```powershell
python check_openssl.py
```

If the diagnostic says no bundled OpenSSL was detected, the app is not seeing
the executable in the expected installation folder.
