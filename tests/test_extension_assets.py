import json
import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT_DIR = os.path.join(ROOT, "chrome_extension")


def test_manifest_v3_and_minimal_permissions():
    with open(os.path.join(EXT_DIR, "manifest.json"), "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["manifest_version"] == 3
    perms = set(manifest.get("permissions", []))
    assert perms == {"activeTab", "scripting", "storage", "tabs", "notifications"}
    assert "cookies" not in perms
    assert "webRequestBlocking" not in perms


def test_extension_has_no_embedded_api_keys_or_credential_collection():
    for fname in ("content.js", "background.js", "popup.js"):
        with open(os.path.join(EXT_DIR, fname), "r", encoding="utf-8") as f:
            txt = f.read()
        assert "gsk_" not in txt, f"Found Groq key pattern in {fname}"
        assert "api.groq.com" not in txt, f"Extension must not call Groq directly in {fname}"
        assert "document.cookie" not in txt, f"Extension must not read cookies in {fname}"
        assert "openrouter" not in txt.lower(), f"Stale OpenRouter reference in {fname}"

