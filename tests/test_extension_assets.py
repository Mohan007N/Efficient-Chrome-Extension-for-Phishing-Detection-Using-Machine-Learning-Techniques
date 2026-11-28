import json
import os
import shutil
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT_DIR = os.path.join(ROOT, "chrome_extension")


def test_manifest_v3_and_minimal_permissions():
    with open(os.path.join(EXT_DIR, "manifest.json"), "r", encoding="utf-8") as f:
        manifest = json.load(f)
    assert manifest["manifest_version"] == 3
    assert manifest["version"].startswith("3.")
    perms = set(manifest.get("permissions", []))
    assert perms == {"activeTab", "scripting", "storage", "tabs", "notifications"}
    assert "cookies" not in perms
    assert "webRequestBlocking" not in perms
    cs_js = manifest["content_scripts"][0]["js"]
    assert "utils.js" in cs_js and "content.js" in cs_js


def test_extension_has_no_embedded_api_keys_or_credential_or_trust_bypass():
    for fname in ("utils.js", "content.js", "background.js", "popup.js"):
        with open(os.path.join(EXT_DIR, fname), "r", encoding="utf-8") as f:
            txt = f.read()
        assert "gsk_" not in txt, f"Found Groq key pattern in {fname}"
        assert "api.groq.com" not in txt, f"Extension must not call Groq directly in {fname}"
        assert "document.cookie" not in txt, f"Extension must not read cookies in {fname}"
        assert "openrouter" not in txt.lower(), f"Stale OpenRouter reference in {fname}"

    with open(os.path.join(EXT_DIR, "content.js"), "r", encoding="utf-8") as f:
        c_txt = f.read()
    assert "user_trusted" not in c_txt
    assert "escapeHtml" in c_txt
    assert "brand_domain_mismatch: brandDomainMismatch" in c_txt
    assert "shannonEntropy" in c_txt
    assert "history.pushState" in c_txt and "URL_CHANGED" in c_txt
    assert "MAX_MUTATIONS_PER_WINDOW" in c_txt
    assert "mutationScanCount >= 3" not in c_txt

    with open(os.path.join(EXT_DIR, "background.js"), "r", encoding="utf-8") as f:
        b_txt = f.read()
    assert "LOCAL_NETWORK_UNVERIFIED" in b_txt
    assert "onUpdated.addListener" in b_txt
    assert "buildCacheKey" in b_txt
    assert "cachedModelVersions" in b_txt
    assert "backendUrl: baseUrl" in b_txt
    assert "URL_CHANGED" in b_txt


def test_extension_utils_behavior_with_node():
    node_bin = shutil.which("node")
    if not node_bin:
        return
    js_script = """
    const assert = require("assert");
    const u = require("./chrome_extension/utils.js");

    // 1. XSS HTML escaping
    const escaped = u.escapeHtml('<img src=x onerror="alert(1)"> & \\'quote\\'');
    assert(!escaped.includes("<") && !escaped.includes(">") && escaped.includes("&lt;"));

    // 2. URL normalization & DOM fingerprint invalidation
    const u1 = u.normalizeUrlForCache("https://Example.COM/login?a=1&utm_source=x#frag");
    assert.strictEqual(u1, "https://example.com/login?a=1");

    const k1 = u.buildCacheKey({ url: u1, domFeatures: { num_password_fields: 0, external_forms_count: 0 }, modelVersion: "v3.0.0", backendUrl: "http://127.0.0.1:8000" });
    const k2 = u.buildCacheKey({ url: u1, domFeatures: { num_password_fields: 1, external_forms_count: 1 }, modelVersion: "v3.0.0", backendUrl: "http://127.0.0.1:8000" });
    const k3 = u.buildCacheKey({ url: u1, domFeatures: { num_password_fields: 0, external_forms_count: 0 }, modelVersion: "v3.0.1", backendUrl: "http://127.0.0.1:8000" });
    const k4 = u.buildCacheKey({ url: u1, domFeatures: { num_password_fields: 0, external_forms_count: 0 }, modelVersion: "v3.0.0", backendUrl: "https://prod.example.com" });
    assert.notStrictEqual(k1, k2);
    assert.notStrictEqual(k1, k3);
    assert.notStrictEqual(k1, k4);

    // 3. Cache entry expiration & model version checks
    assert.strictEqual(u.isCacheEntryValid({ timestamp: 1000, model_version: "v3.0.0" }, "v3.0.0", 2000, 5000), true);
    assert.strictEqual(u.isCacheEntryValid({ timestamp: 1000, model_version: "v3.0.0" }, "v3.0.1", 2000, 5000), false);
    assert.strictEqual(u.isCacheEntryValid({ timestamp: 1000, model_version: "v3.0.0" }, "v3.0.0", 10000, 5000), false);

    // 4. Local host detection, PSL compound domains, entropy, and brand mismatch
    assert.strictEqual(u.isLocalNetworkHost("127.0.0.1"), true);
    assert.strictEqual(u.isLocalNetworkHost("192.168.1.5"), true);
    assert.strictEqual(u.isLocalNetworkHost("example.com"), false);
    assert.strictEqual(u.extractRootDomain("shop.aurora.co.jp"), "aurora.co.jp");
    assert(u.shannonEntropy("abcdefgh12345678!@#$%^&*()-_=+[]{}|;:,./<>?~`") > 5.0);
    assert.strictEqual(u.detectBrandImpersonation("amaz0n-verify.invalid", "Amazon Sign In").brandDomainMismatch, 1);
    assert.strictEqual(u.detectBrandImpersonation("www.amazon.in", "Amazon.in Shopping").brandDomainMismatch, 0);
    console.log("NODE_UTILS_OK");
    """
    proc = subprocess.run([node_bin, "-e", js_script], cwd=ROOT, capture_output=True, text=True, timeout=15)
    assert proc.returncode == 0, f"Node utils check failed: {proc.stderr}\n{proc.stdout}"
    assert "NODE_UTILS_OK" in proc.stdout
