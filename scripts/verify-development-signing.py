"""Inspect signature metadata only, without querying any Keychain item values.

Never prints certificate names, team IDs, access groups, or private config.
This verifies signing structure, not successful biometric enrollment.
"""
import plistlib
import re
import subprocess
import sys
from pathlib import Path

def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)

if len(sys.argv) != 2:
    fail("Usage: python3 scripts/verify-development-signing.py /path/to/Vaultwarden.app")
app = Path(sys.argv[1])
verification = subprocess.run(["codesign", "--verify", "--strict", str(app)], capture_output=True)
if verification.returncode:
    fail("Development signature verification failed.")
metadata = subprocess.run(["codesign", "-dv", "--verbose=4", str(app)], capture_output=True, text=True)
text = metadata.stdout + metadata.stderr
team = re.search(r"^TeamIdentifier=([A-Z0-9]{10})$", text, re.MULTILINE)
if not team or "Signature=adhoc" in text:
    fail("This is not an Apple team-signed build. Use VaultwardenDevelopment, not the ad-hoc script/scheme.")
inspection = subprocess.run(["codesign", "-d", "--entitlements", "-", "--xml", str(app)], capture_output=True)
try:
    entitlements = plistlib.loads(inspection.stdout)
    info = plistlib.loads((app / "Contents/Info.plist").read_bytes())
except (ValueError, OSError, plistlib.InvalidFileException):
    fail("Could not inspect development entitlements.")
bundle = info.get("CFBundleIdentifier", "")
identity = entitlements.get("com.apple.application-identifier") or entitlements.get("application-identifier")
groups = entitlements.get("keychain-access-groups", [])
if not isinstance(identity, str) or not identity.endswith("." + bundle):
    fail("The signed app has no matching application identifier; verify Xcode provisioning.")
if not isinstance(groups, list) or not all(isinstance(group, str) for group in groups) or identity not in groups or any("$(" in group or "*" in group for group in groups):
    fail("The signed app has no concrete matching Keychain access group; verify Xcode capability/provisioning.")
if not entitlements.get("com.apple.security.app-sandbox") or not entitlements.get("com.apple.security.network.client"):
    fail("Required standalone sandbox/network entitlements are missing.")
print("Development signature verified: Apple team identity, matching app identifier and concrete Keychain group.")
print("Biometric ACL support still requires explicit testing in this signed app.")
