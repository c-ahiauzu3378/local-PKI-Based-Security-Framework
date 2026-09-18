from __future__ import annotations

import sys
from pathlib import Path

import app


def main() -> int:
    app.ensure_dirs()
    effective = app.resolve_openssl_path("openssl")
    print("Campus PKI RA OpenSSL diagnostic")
    print("=" * 38)
    print(app.bundled_openssl_hint())
    print(f"Effective OpenSSL command: {effective}")
    print(f"OpenSSL config file: {app.OPENSSL_CONF_PATH}")
    print()

    print("Bundled candidates checked:")
    for candidate in app.bundled_openssl_candidates():
        status = "FOUND" if candidate.exists() else "missing"
        print(f"  [{status}] {candidate}")
    print()

    ok, output = app.run_command([effective, "version", "-a"])
    print("Command: openssl version -a")
    print("Result:", "OK" if ok else "FAILED")
    print(output or "(no output)")
    print()

    if not ok:
        print("Common fixes:")
        print("  1. Put Windows OpenSSL at tools/openssl/windows/bin/openssl.exe")
        print("  2. Keep required DLL files beside openssl.exe in the same bin folder")
        print("  3. If using another layout, set the full executable path in Settings")
        print("  4. Restart the launcher after moving OpenSSL files")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

