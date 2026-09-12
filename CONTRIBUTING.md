# Contributing Guidelines

Thank you for considering contributing to **Android Enterprise Security Lab**! We welcome research contributions, diagnostic enhancements, i18n translations, and documentation improvements.

## Code of Ethics & Scope

This project is strictly for **educational security research, diagnostic auditing, and enterprise system administration**.

* **No Exploits / Weaponization:** Pull requests containing weaponized lock bypasses, zero-day exploits, or malware targeting commercial MDM platforms will be rejected immediately.
* **Non-Destructive Tools:** All diagnostic utilities must operate in a read-only or non-destructive manner.
* **Privacy & Sanitization:** Ensure all sample outputs, logs, or test data sanitize sensitive PII, IMEI numbers, and real device MAC addresses.

## Development Workflow

1. Fork and clone the repository.
2. Run setup check:
   ```bash
   ./scripts/setup.sh
   ```
3. Test your code (the same checks CI runs):
   ```bash
   python3 -m py_compile core/mdm_inspector.py core/apk_analyzer.py \
       core/axml_parser.py core/logcat_monitor.py
   bash -n scripts/adb_check.sh scripts/setup.sh scripts/create_testbed_avd.sh
   python3 core/mdm_inspector.py --help     # CLI smoke check
   python3 -m pytest tests/ -v              # unit tests
   ```
4. Submit a Pull Request with a clear description of changes.

## License
By contributing to this repository, you agree that your contributions will be licensed under the **Apache License 2.0**.
