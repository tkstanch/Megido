"""
Core decompilation engine for browser extensions.

This module contains the main logic for decompiling and analyzing
browser extensions including Chrome CRX, Firefox XPI, Java applets,
Flash SWF files, Silverlight XAP packages, WASM, Electron ASAR,
and userscripts.
"""
import zipfile
import tempfile
import os
import re
import json
import struct
import subprocess
import shutil
import time
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import requests

from .config import (
    TOOL_PATHS, DOWNLOAD_TIMEOUT, DECOMPILE_TIMEOUT,
    MAX_DOWNLOAD_RETRIES, DOWNLOAD_CHUNK_SIZE, SHORT_NAME_RATIO_THRESHOLD,
)
from .utils.file_utils import (
    detect_type_from_magic, calculate_checksums,
    safe_extract_zip,
)
from .utils.crypto_utils import (
    calculate_entropy, find_high_entropy_strings,
    find_base64_strings,
    detect_xor_operations, detect_atob_usage,
)
from .utils.js_utils import (
    beautify_js, is_minified, detect_module_system,
    parse_userscript_metadata,
)
from .utils.manifest_parser import (
    parse_chrome_manifest, parse_install_rdf, score_permission,
)
from .utils.pattern_library import (
    PATTERNS_SECRETS, PATTERNS_VULNERABILITIES, PATTERNS_MALICIOUS,
    PATTERNS_OBFUSCATION, PATTERN_URL, PATTERN_WEBSOCKET,
    PATTERN_FETCH, PATTERN_XHR, PATTERN_AXIOS,
)

# Module-level precompiled patterns (avoids recompilation on each call)
_RE_JAVA_METHOD = re.compile(
    r"(?:public|private|protected|static|final|void|native|synchronized)"
    r"[^;{]*\([^)]*\)\s*(?:throws[^{;]+)?\s*\{"
)
_RE_IDENTIFIER = re.compile(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b")
_RE_HEX_NAME = re.compile(r"^[0-9a-f]{4,}$")
_RE_FETCH_FULL = re.compile(
    r'fetch\s*\(\s*["\']([^"\']+)["\']'
    r'(?:\s*,\s*\{([^}]*)\})?', re.DOTALL
)
_RE_REQUIRE = re.compile(r'require\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)')
_RE_IMPORT_FROM = re.compile(r'import\s+.*?\bfrom\s+[\'"]([^\'"]+)[\'"]')

_DATA_FLOW_PATTERNS = {
    "chrome_storage": re.compile(
        r"chrome\.storage\.(local|sync|session)\.(get|set|remove)"
    ),
    "local_storage": re.compile(r"localStorage\.(getItem|setItem|removeItem)"),
    "session_storage": re.compile(r"sessionStorage\.(getItem|setItem)"),
    "cookies_read": re.compile(r"document\.cookie"),
    "chrome_cookies": re.compile(r"chrome\.cookies\.(get|set|remove|getAll)"),
    "post_message": re.compile(r"(?:window|self)\.postMessage\s*\("),
    "indexed_db": re.compile(r"indexedDB\.(open|deleteDatabase)"),
}

_JS_HOOK_PATTERNS = {
    "event_listeners": re.compile(r"addEventListener\s*\(\s*['\"](\w+)['\"]"),
    "mutation_observer": re.compile(r"new\s+MutationObserver\s*\("),
    "proxy_trap": re.compile(r"new\s+Proxy\s*\("),
    "getter_setter": re.compile(r"Object\.definePropert(?:y|ies)\s*\("),
    "prototype_method": re.compile(r"\.prototype\.\w+\s*=\s*function"),
    "message_handler": re.compile(r"addEventListener\s*\(\s*['\"]message['\"]"),
}


class DecompilationEngine:
    """Main engine for handling browser extension decompilation workflows."""

    def __init__(self):
        self.supported_types = [
            "chrome_crx", "firefox_xpi", "edge_msix", "safari_appex",
            "webextension", "electron_asar", "wasm", "pwa",
            "java_applet", "flash", "silverlight", "javascript",
            "browser_addon", "userscript",
        ]
        self.decompiler_paths = self._init_decompiler_paths()

    def _init_decompiler_paths(self) -> Dict[str, Optional[str]]:
        paths: Dict[str, Optional[str]] = {}
        for tool, path in TOOL_PATHS.items():
            resolved = shutil.which(path) if path else None
            paths[tool] = resolved
        return paths

    def _tool_available(self, tool_key: str) -> bool:
        return bool(self.decompiler_paths.get(tool_key))

    def download_extension(self, url: str, output_path: str) -> Dict:
        """Download a browser extension with retry and checksum verification."""
        last_error = ""
        for attempt in range(MAX_DOWNLOAD_RETRIES):
            try:
                headers: Dict[str, str] = {}
                existing_size = 0
                if os.path.exists(output_path):
                    existing_size = os.path.getsize(output_path)
                    if existing_size:
                        headers["Range"] = f"bytes={existing_size}-"
                with requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT,
                                  headers=headers) as resp:
                    if resp.status_code == 416:
                        break
                    resp.raise_for_status()
                    mode = "ab" if existing_size and resp.status_code == 206 else "wb"
                    with open(output_path, mode) as fh:
                        for chunk in resp.iter_content(chunk_size=DOWNLOAD_CHUNK_SIZE):
                            if chunk:
                                fh.write(chunk)
                break
            except requests.RequestException as exc:
                last_error = str(exc)
                time.sleep(2 ** attempt)
        else:
            return {"success": False, "error": f"Download failed after retries: {last_error}"}

        if not os.path.exists(output_path):
            return {"success": False, "error": "Output file not created"}
        checksums = calculate_checksums(output_path)
        return {
            "success": True,
            "file_path": output_path,
            "file_size": os.path.getsize(output_path),
            "checksums": checksums,
        }

    def detect_extension_type(self, file_path: str) -> str:
        """Detect extension type from magic bytes and file extension."""
        detected = detect_type_from_magic(file_path)
        if detected and detected != "unknown":
            return detected
        ext = Path(file_path).suffix.lower()
        mapping = {
            ".jar": "java_applet", ".class": "java_applet",
            ".swf": "flash", ".xap": "silverlight",
            ".crx": "chrome_crx", ".xpi": "firefox_xpi",
            ".msix": "edge_msix", ".wasm": "wasm",
            ".asar": "electron_asar",
        }
        return mapping.get(ext, "unknown")

    def decompile(self, file_path: str, output_dir: str,
                  extension_type: Optional[str] = None,
                  options: Optional[Dict] = None) -> Dict:
        """Route decompilation to the appropriate handler."""
        if extension_type is None:
            extension_type = self.detect_extension_type(file_path)
        dispatch = {
            "java_applet": self.decompile_java_applet,
            "flash": self.decompile_flash_swf,
            "silverlight": self.decompile_silverlight_xap,
            "chrome_crx": self.decompile_chrome_extension,
            "firefox_xpi": self.decompile_firefox_extension,
            "webextension": self.decompile_chrome_extension,
            "edge_msix": self.decompile_chrome_extension,
            "wasm": self.decompile_webassembly,
            "electron_asar": self.decompile_electron_asar,
            "userscript": self.decompile_userscript,
            "javascript": self._decompile_javascript,
            "browser_addon": self.decompile_chrome_extension,
        }
        handler = dispatch.get(extension_type)
        if handler is None:
            return {"success": False, "error": f"Unsupported extension type: {extension_type}"}
        return handler(file_path, output_dir, options)

    def decompile_java_applet(self, jar_path: str, output_dir: str,
                              options: Optional[Dict] = None) -> Dict:
        """Decompile Java applet (.jar or .class) using CFR."""
        os.makedirs(output_dir, exist_ok=True)
        if not self._tool_available("cfr"):
            class_files = self._extract_jar_classes(jar_path, output_dir)
            return {
                "success": True, "output_dir": output_dir,
                "num_classes": len(class_files), "num_methods": 0,
                "log": "CFR decompiler not found; .class files extracted.",
                "warning": "Install CFR for full Java decompilation.",
            }
        try:
            result = subprocess.run(
                [self.decompiler_paths["cfr"], "--outputdir", output_dir, jar_path],
                capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT,
            )
            java_files = list(Path(output_dir).rglob("*.java"))
            return {
                "success": result.returncode == 0, "output_dir": output_dir,
                "num_classes": len(java_files),
                "num_methods": self._count_java_methods(java_files),
                "log": result.stdout + result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "CFR timed out"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _extract_jar_classes(self, jar_path: str, output_dir: str) -> List[str]:
        class_files: List[str] = []
        try:
            with zipfile.ZipFile(jar_path, "r") as zf:
                for name in zf.namelist():
                    if name.endswith(".class"):
                        zf.extract(name, output_dir)
                        class_files.append(name)
        except Exception:
            pass
        return class_files

    def _count_java_methods(self, java_files: List[Path]) -> int:
        count = 0
        for path in java_files:
            try:
                count += len(_RE_JAVA_METHOD.findall(path.read_text(errors="ignore")))
            except Exception:
                pass
        return count

    def decompile_flash_swf(self, swf_path: str, output_dir: str,
                            options: Optional[Dict] = None) -> Dict:
        """Decompile Flash SWF using JPEXS or parse header manually."""
        os.makedirs(output_dir, exist_ok=True)
        swf_info = self._parse_swf_header(swf_path)
        if not swf_info.get("valid"):
            return {"success": False, "error": "Not a valid SWF file"}
        if not self._tool_available("jpexs"):
            return {
                "success": True, "output_dir": output_dir, "swf_info": swf_info,
                "log": "JPEXS not found; SWF header parsed only.",
                "warning": "Install JPEXS for full ActionScript decompilation.",
            }
        try:
            result = subprocess.run(
                [self.decompiler_paths["jpexs"], "-export", "script", output_dir, swf_path],
                capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT,
            )
            return {
                "success": result.returncode == 0, "output_dir": output_dir,
                "swf_info": swf_info, "log": result.stdout + result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "JPEXS timed out"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _parse_swf_header(self, swf_path: str) -> Dict:
        try:
            with open(swf_path, "rb") as fh:
                sig = fh.read(3)
                if sig not in (b"FWS", b"CWS", b"ZWS"):
                    return {"valid": False}
                version = struct.unpack("B", fh.read(1))[0]
                file_length = struct.unpack("<I", fh.read(4))[0]
                compression = {b"FWS": "none", b"CWS": "zlib", b"ZWS": "lzma"}[sig]
                return {"valid": True, "version": version,
                        "file_length": file_length, "compression": compression}
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

    def decompile_silverlight_xap(self, xap_path: str, output_dir: str,
                                  options: Optional[Dict] = None) -> Dict:
        """Decompile Silverlight XAP (ZIP of .NET assemblies) using ILSpy."""
        os.makedirs(output_dir, exist_ok=True)
        extract_dir = os.path.join(output_dir, "_extracted")
        ok, err = safe_extract_zip(xap_path, extract_dir)
        if not ok:
            return {"success": False, "error": f"Failed to extract XAP: {err}"}
        dlls = list(Path(extract_dir).rglob("*.dll"))
        if not dlls:
            return {"success": False, "error": "No .dll assemblies in XAP"}
        if not self._tool_available("ilspy"):
            return {
                "success": True, "output_dir": extract_dir,
                "num_assemblies": len(dlls),
                "log": "ILSpy not found; .dll files extracted.",
                "warning": "Install ilspycmd for C# decompilation.",
            }
        cs_dir = os.path.join(output_dir, "csharp")
        os.makedirs(cs_dir, exist_ok=True)
        logs = []
        for dll in dlls:
            try:
                result = subprocess.run(
                    [self.decompiler_paths["ilspy"], str(dll),
                     "--outputdir", cs_dir, "--project"],
                    capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT,
                )
                logs.append(result.stdout + result.stderr)
            except Exception as exc:
                logs.append(str(exc))
        cs_files = list(Path(cs_dir).rglob("*.cs"))
        return {
            "success": True, "output_dir": cs_dir,
            "num_assemblies": len(dlls), "num_source_files": len(cs_files),
            "log": "\n".join(logs),
        }

    def decompile_chrome_extension(self, crx_path: str, output_dir: str,
                                   options: Optional[Dict] = None) -> Dict:
        """Handle CRX3 format or plain ZIP WebExtension."""
        os.makedirs(output_dir, exist_ok=True)
        zip_path = crx_path
        with open(crx_path, "rb") as fh:
            header = fh.read(4)
        if header == b"Cr24":
            zip_path = self._strip_crx3_header(crx_path, output_dir)
            if zip_path is None:
                return {"success": False, "error": "Failed to parse CRX3 header"}
        ok, err = safe_extract_zip(zip_path, output_dir)
        if not ok:
            return {"success": False, "error": f"Failed to extract: {err}"}
        result = self._process_webextension_dir(output_dir, options)
        result.update({"success": True, "output_dir": output_dir})
        return result

    def _strip_crx3_header(self, crx_path: str, output_dir: str) -> Optional[str]:
        try:
            with open(crx_path, "rb") as fh:
                fh.read(4)  # magic Cr24
                version = struct.unpack("<I", fh.read(4))[0]
                if version == 3:
                    header_size = struct.unpack("<I", fh.read(4))[0]
                    fh.seek(12 + header_size)
                else:
                    pk_len = struct.unpack("<I", fh.read(4))[0]
                    sig_len = struct.unpack("<I", fh.read(4))[0]
                    fh.seek(16 + pk_len + sig_len)
                zip_data = fh.read()
            zip_path = os.path.join(output_dir, "_inner.zip")
            with open(zip_path, "wb") as fh:
                fh.write(zip_data)
            return zip_path
        except Exception:
            return None

    def _process_webextension_dir(self, ext_dir: str,
                                  options: Optional[Dict]) -> Dict:
        manifest_info: Dict = {}
        manifest_path = os.path.join(ext_dir, "manifest.json")
        if os.path.exists(manifest_path):
            try:
                with open(manifest_path, encoding="utf-8", errors="replace") as fh:
                    manifest_info = parse_chrome_manifest(fh.read())
            except Exception:
                pass
        js_files = list(Path(ext_dir).rglob("*.js"))
        beautified = 0
        for js_file in js_files:
            try:
                src = js_file.read_text(encoding="utf-8", errors="replace")
                if is_minified(src):
                    js_file.write_text(beautify_js(src), encoding="utf-8")
                    beautified += 1
            except Exception:
                pass
        return {
            "manifest": manifest_info,
            "num_js_files": len(js_files),
            "num_beautified": beautified,
            "log": f"Extracted {len(js_files)} JS files, beautified {beautified}.",
        }

    def decompile_firefox_extension(self, xpi_path: str, output_dir: str,
                                    options: Optional[Dict] = None) -> Dict:
        """Handle XPI (ZIP) Firefox extension."""
        os.makedirs(output_dir, exist_ok=True)
        ok, err = safe_extract_zip(xpi_path, output_dir)
        if not ok:
            return {"success": False, "error": f"Failed to extract XPI: {err}"}
        manifest_info: Dict = {}
        manifest_path = os.path.join(output_dir, "manifest.json")
        rdf_path = os.path.join(output_dir, "install.rdf")
        if os.path.exists(manifest_path):
            with open(manifest_path, encoding="utf-8", errors="replace") as fh:
                manifest_info = parse_chrome_manifest(fh.read())
        elif os.path.exists(rdf_path):
            with open(rdf_path, encoding="utf-8", errors="replace") as fh:
                manifest_info = parse_install_rdf(fh.read())
        result = self._process_webextension_dir(output_dir, options)
        result.update({"manifest": manifest_info, "output_dir": output_dir, "success": True})
        return result

    def decompile_webassembly(self, wasm_path: str, output_dir: str,
                              options: Optional[Dict] = None) -> Dict:
        """Disassemble WASM to WAT format."""
        os.makedirs(output_dir, exist_ok=True)
        wat_path = os.path.join(output_dir, "module.wat")
        if self._tool_available("wasm_tools"):
            try:
                result = subprocess.run(
                    [self.decompiler_paths["wasm_tools"], "print", wasm_path, "-o", wat_path],
                    capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT,
                )
                if result.returncode == 0:
                    return {"success": True, "output_dir": output_dir,
                            "wat_file": wat_path, "log": result.stdout + result.stderr}
            except Exception:
                pass
        info = self._parse_wasm_header(wasm_path)
        with open(wat_path, "w") as fh:
            fh.write(f";; WebAssembly module\n;; {json.dumps(info)}\n")
        return {
            "success": True, "output_dir": output_dir, "wasm_info": info,
            "log": "wasm-tools not found; WASM header parsed.",
            "warning": "Install wasm-tools for full WAT disassembly.",
        }

    def _parse_wasm_header(self, wasm_path: str) -> Dict:
        info: Dict = {"valid": False}
        try:
            with open(wasm_path, "rb") as fh:
                magic = fh.read(4)
                if magic != b"\x00asm":
                    return info
                version = struct.unpack("<I", fh.read(4))[0]
                info = {"valid": True, "version": version, "sections": []}
                section_names = {
                    0: "custom", 1: "type", 2: "import", 3: "function",
                    4: "table", 5: "memory", 6: "global", 7: "export",
                    8: "start", 9: "element", 10: "code", 11: "data",
                }
                while True:
                    b = fh.read(1)
                    if not b:
                        break
                    section_id = b[0]
                    size = self._read_leb128(fh)
                    fh.seek(size, 1)
                    info["sections"].append(
                        section_names.get(section_id, f"unknown({section_id})")
                    )
        except Exception as exc:
            info["error"] = str(exc)
        return info

    @staticmethod
    def _read_leb128(fh) -> int:
        result = 0
        shift = 0
        while True:
            b = fh.read(1)
            if not b:
                break
            byte = b[0]
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                break
            shift += 7
        return result

    def decompile_electron_asar(self, asar_path: str, output_dir: str,
                                options: Optional[Dict] = None) -> Dict:
        """Parse Electron ASAR archive and extract all files."""
        os.makedirs(output_dir, exist_ok=True)
        try:
            with open(asar_path, "rb") as fh:
                hdr_bytes = fh.read(4)
                if len(hdr_bytes) < 4:
                    return {"success": False, "error": "Truncated ASAR"}
                header_size = struct.unpack("<I", hdr_bytes)[0]
                header_json = fh.read(header_size).decode("utf-8", errors="replace")
                fh.seek(4 + header_size)
                all_data = fh.read()
            try:
                header = json.loads(header_json)
            except json.JSONDecodeError:
                return {"success": False, "error": "Invalid ASAR header JSON"}
            extracted = self._extract_asar_files(header.get("files", {}), all_data, output_dir, "")
            result = self._process_webextension_dir(output_dir, options)
            result.update({"success": True, "output_dir": output_dir,
                           "num_extracted": extracted})
            return result
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def _extract_asar_files(self, tree: Dict, data: bytes,
                             base: str, prefix: str) -> int:
        count = 0
        for name, info in tree.items():
            path = os.path.join(base, prefix, name) if prefix else os.path.join(base, name)
            if "files" in info:
                os.makedirs(path, exist_ok=True)
                count += self._extract_asar_files(
                    info["files"], data, base,
                    os.path.join(prefix, name) if prefix else name
                )
            elif "offset" in info and "size" in info:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                offset = int(info["offset"])
                size = int(info["size"])
                file_content = data[offset:offset + size]
                with open(path, "wb") as fh:
                    fh.write(file_content)
                count += 1
        return count

    def decompile_userscript(self, script_path: str, output_dir: str,
                             options: Optional[Dict] = None) -> Dict:
        """Parse and beautify a Tampermonkey/Greasemonkey userscript."""
        os.makedirs(output_dir, exist_ok=True)
        try:
            with open(script_path, encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except Exception as exc:
            return {"success": False, "error": str(exc)}
        metadata = parse_userscript_metadata(source)
        beautified = beautify_js(source)
        out_path = os.path.join(output_dir, "userscript.js")
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(beautified)
        return {
            "success": True, "output_dir": output_dir, "metadata": metadata,
            "grants": metadata.get("grant", []),
            "match_patterns": metadata.get("match", []),
            "requires": metadata.get("require", []),
            "log": f"Parsed {len(metadata)} metadata keys.",
        }

    def _decompile_javascript(self, js_path: str, output_dir: str,
                              options: Optional[Dict] = None) -> Dict:
        os.makedirs(output_dir, exist_ok=True)
        try:
            with open(js_path, encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except Exception as exc:
            return {"success": False, "error": str(exc)}
        beautified = beautify_js(source)
        out_path = os.path.join(output_dir, Path(js_path).name)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(beautified)
        return {
            "success": True, "output_dir": output_dir,
            "module_system": detect_module_system(beautified),
            "log": "JavaScript beautified.",
        }


class ObfuscationDetector:
    """Detector for common code obfuscation techniques."""

    def detect_name_mangling(self, source_code: str) -> Tuple[bool, float, str]:
        """Detect name mangling by measuring ratio of short identifiers."""
        identifiers = _RE_IDENTIFIER.findall(source_code)
        if len(identifiers) < 20:
            return False, 0.0, "Too few identifiers"
        short = [i for i in identifiers if len(i) <= 2]
        ratio = len(short) / len(identifiers)
        hex_names = [i for i in identifiers if _RE_HEX_NAME.match(i)]
        hex_ratio = len(hex_names) / len(identifiers)
        avg_len = sum(len(i) for i in identifiers) / len(identifiers)
        confidence = 0.0
        evidence_parts = []
        if ratio > SHORT_NAME_RATIO_THRESHOLD:
            confidence += 0.5
            evidence_parts.append(f"{ratio:.0%} short identifiers")
        if avg_len < 4:
            confidence += 0.3
            evidence_parts.append(f"avg identifier length {avg_len:.1f}")
        if hex_ratio > 0.05:
            confidence += 0.2
            evidence_parts.append(f"{hex_ratio:.0%} hex-looking names")
        confidence = min(confidence, 1.0)
        return confidence >= 0.5, confidence, "; ".join(evidence_parts) or "No evidence"

    def detect_string_encryption(self, source_code: str) -> Tuple[bool, float, str]:
        """Detect encrypted/encoded string literals."""
        evidence_parts = []
        confidence = 0.0
        high_entropy = find_high_entropy_strings(source_code)
        if high_entropy:
            confidence += min(0.4, 0.1 * len(high_entropy))
            evidence_parts.append(f"{len(high_entropy)} high-entropy string(s)")
        b64_strings = find_base64_strings(source_code)
        if b64_strings:
            confidence += 0.3
            evidence_parts.append(f"{len(b64_strings)} Base64 string(s)")
        if detect_xor_operations(source_code):
            confidence += 0.2
            evidence_parts.append("XOR operations detected")
        if detect_atob_usage(source_code):
            confidence += 0.2
            evidence_parts.append("atob()/btoa() usage")
        confidence = min(confidence, 1.0)
        return confidence >= 0.4, confidence, "; ".join(evidence_parts) or "No evidence"

    def detect_control_flow_obfuscation(self, source_code: str) -> Tuple[bool, float, str]:
        """Detect control flow obfuscation patterns."""
        evidence_parts = []
        confidence = 0.0
        switch_count = len(re.findall(r"\bswitch\s*\(", source_code))
        if switch_count > 5:
            confidence += 0.3
            evidence_parts.append(f"{switch_count} switch statements")
        while_true = len(re.findall(r"while\s*\(\s*(?:true|1|!0)\s*\)", source_code))
        if while_true > 2:
            confidence += 0.2
            evidence_parts.append(f"{while_true} while(true) loops")
        max_depth = self._max_nesting_depth(source_code)
        if max_depth > 10:
            confidence += 0.3
            evidence_parts.append(f"nesting depth {max_depth}")
        if PATTERNS_OBFUSCATION["dean_edwards"].search(source_code):
            confidence += 0.5
            evidence_parts.append("Dean Edwards packer detected")
        if PATTERNS_OBFUSCATION["eval_encoded"].search(source_code):
            confidence += 0.4
            evidence_parts.append("eval() of encoded payload")
        confidence = min(confidence, 1.0)
        return confidence >= 0.4, confidence, "; ".join(evidence_parts) or "No evidence"

    @staticmethod
    def _max_nesting_depth(source_code: str) -> int:
        depth = 0
        max_depth = 0
        for ch in source_code:
            if ch == "{":
                depth += 1
                max_depth = max(max_depth, depth)
            elif ch == "}":
                depth = max(0, depth - 1)
        return max_depth

    def detect_reflection_obfuscation(self, source_code: str) -> Tuple[bool, float, str]:
        """Detect reflection-based obfuscation."""
        evidence_parts = []
        confidence = 0.0
        java_hits = len(PATTERNS_VULNERABILITIES["java_reflection"].findall(source_code))
        if java_hits:
            confidence += 0.4
            evidence_parts.append(f"{java_hits} Java reflection calls")
        dotnet_hits = len(PATTERNS_VULNERABILITIES["dotnet_reflection"].findall(source_code))
        if dotnet_hits:
            confidence += 0.4
            evidence_parts.append(f"{dotnet_hits} .NET reflection calls")
        js_hits = len(PATTERNS_VULNERABILITIES["js_reflect"].findall(source_code))
        if js_hits:
            confidence += 0.3
            evidence_parts.append(f"{js_hits} JS reflect/eval calls")
        confidence = min(confidence, 1.0)
        return confidence >= 0.3, confidence, "; ".join(evidence_parts) or "No evidence"

    def detect_packing(self, source_code: str) -> Tuple[bool, float, str]:
        """Detect common JS/Java packers."""
        evidence_parts = []
        confidence = 0.0
        if PATTERNS_OBFUSCATION["dean_edwards"].search(source_code):
            confidence += 0.9
            evidence_parts.append("Dean Edwards packer")
        if PATTERNS_OBFUSCATION["eval_encoded"].search(source_code):
            confidence += 0.6
            evidence_parts.append("eval() of encoded payload")
        classloader = len(PATTERNS_OBFUSCATION["classloader"].findall(source_code))
        if classloader:
            confidence += 0.3
            evidence_parts.append(f"{classloader} ClassLoader manipulations")
        confidence = min(confidence, 1.0)
        return confidence >= 0.5, confidence, "; ".join(evidence_parts) or "No evidence"

    def detect_anti_debugging(self, source_code: str) -> Tuple[bool, float, str]:
        """Detect anti-debugging techniques."""
        evidence_parts = []
        confidence = 0.0
        debugger_count = len(re.findall(r"\bdebugger\b", source_code))
        if debugger_count:
            confidence += 0.5
            evidence_parts.append(f"{debugger_count} debugger statement(s)")
        if PATTERNS_MALICIOUS["timing_check"].search(source_code):
            confidence += 0.3
            evidence_parts.append("performance.now() timing check")
        if re.search(r"console\.log\s*=\s*function", source_code):
            confidence += 0.4
            evidence_parts.append("console.log override")
        confidence = min(confidence, 1.0)
        return confidence >= 0.3, confidence, "; ".join(evidence_parts) or "No evidence"

    def calculate_entropy(self, data: str) -> float:
        """Shannon entropy of a string."""
        return calculate_entropy(data)

    def generate_obfuscation_report(self, source_code: str) -> Dict:
        """Aggregate all detection results into a structured report."""
        techniques = {
            "name_mangling": self.detect_name_mangling,
            "string_encryption": self.detect_string_encryption,
            "control_flow": self.detect_control_flow_obfuscation,
            "reflection": self.detect_reflection_obfuscation,
            "packing": self.detect_packing,
            "anti_debugging": self.detect_anti_debugging,
        }
        findings = []
        total_confidence = 0.0
        for name, fn in techniques.items():
            detected, confidence, evidence = fn(source_code)
            if detected:
                findings.append({"technique": name,
                                  "confidence": round(confidence, 3),
                                  "evidence": evidence})
                total_confidence += confidence
        overall_score = min(total_confidence / max(len(techniques), 1), 1.0)
        return {
            "overall_obfuscation_score": round(overall_score, 3),
            "techniques_detected": len(findings),
            "findings": findings,
        }

    def detect_all(self, source_code: str) -> List[Dict]:
        """Run all obfuscation detection methods and return findings."""
        return self.generate_obfuscation_report(source_code)["findings"]


class CodeAnalyzer:
    """Static analyser for decompiled source code."""

    def extract_api_endpoints(self, source_code: str) -> List[Dict[str, str]]:
        """Extract API endpoints and URLs from source code."""
        results = []
        seen: set = set()
        for match in PATTERN_URL.finditer(source_code):
            url = match.group(0).rstrip(".,;)'\"")
            if url not in seen:
                seen.add(url)
                results.append({"url": url, "type": "http_url"})
        for match in PATTERN_WEBSOCKET.finditer(source_code):
            url = match.group(0).rstrip(".,;)'\"")
            if url not in seen:
                seen.add(url)
                results.append({"url": url, "type": "websocket"})
        for match in PATTERN_FETCH.finditer(source_code):
            url = match.group(1) or match.group(2) or ""
            if url and url not in seen:
                seen.add(url)
                results.append({"url": url, "type": "fetch"})
        for match in PATTERN_AXIOS.finditer(source_code):
            url = match.group(2)
            if url and url not in seen:
                seen.add(url)
                results.append({"url": url, "type": "axios",
                                 "method": match.group(1).upper()})
        return results

    def extract_network_requests(self, source_code: str) -> List[Dict]:
        """Extract fetch/XHR/axios network request patterns."""
        results = []
        for match in _RE_FETCH_FULL.finditer(source_code):
            results.append({
                "library": "fetch", "url": match.group(1),
                "options_fragment": (match.group(2) or "").strip()[:200],
            })
        for match in PATTERN_XHR.finditer(source_code):
            if match.group(1) and match.group(2):
                results.append({"library": "XMLHttpRequest",
                                 "method": match.group(1), "url": match.group(2)})
        for match in PATTERN_AXIOS.finditer(source_code):
            results.append({"library": "axios",
                             "method": match.group(1).upper(), "url": match.group(2)})
        return results

    def analyze_data_flows(self, source_code: str) -> List[Dict]:
        """Identify data flow patterns."""
        results = []
        for flow_type, pattern in _DATA_FLOW_PATTERNS.items():
            matches = pattern.findall(source_code)
            if matches:
                results.append({
                    "type": flow_type,
                    "occurrences": len(matches),
                    "details": list(set(str(m) for m in matches[:5])),
                })
        return results

    def find_vulnerabilities(self, source_code: str) -> List[Dict]:
        """Detect potential security vulnerabilities."""
        results = []
        severity_map = {
            "eval_with_input": "high", "java_reflection": "high",
            "dotnet_reflection": "high", "prototype_pollution": "high",
            "inner_html": "medium", "document_write": "medium",
            "dangerously_set_html": "medium", "insecure_http": "medium",
        }
        for vuln_type, pattern in PATTERNS_VULNERABILITIES.items():
            hits = pattern.findall(source_code)
            if hits:
                results.append({
                    "type": vuln_type,
                    "severity": severity_map.get(vuln_type, "low"),
                    "occurrences": len(hits),
                    "sample": str(hits[0])[:200],
                })
        return results

    def find_javascript_hooks(self, source_code: str) -> List[Dict[str, str]]:
        """Identify hookable JavaScript functions."""
        results = []
        for hook_type, pattern in _JS_HOOK_PATTERNS.items():
            matches = pattern.findall(source_code)
            if matches:
                results.append({
                    "type": hook_type,
                    "occurrences": len(matches),
                    "sample": str(matches[0])[:100] if matches else hook_type,
                })
        return results

    def analyze_permissions(self, permissions: List[str]) -> List[Dict]:
        """Score extension permissions for risk."""
        results = []
        for perm in permissions:
            score, level = score_permission(perm)
            results.append({"permission": perm, "risk_score": score, "risk_level": level})
        return sorted(results, key=lambda x: x["risk_score"], reverse=True)

    def detect_malicious_patterns(self, source_code: str) -> List[Dict]:
        """Check for malicious behaviour patterns."""
        results = []
        low_severity = {"debugger_detect", "timing_check"}
        for pattern_type, pattern in PATTERNS_MALICIOUS.items():
            if pattern.search(source_code):
                results.append({
                    "type": pattern_type,
                    "severity": "medium" if pattern_type in low_severity else "high",
                })
        return results

    def extract_secrets(self, source_code: str) -> List[Dict]:
        """Find hardcoded credentials and API keys."""
        results = []
        for secret_type, pattern in PATTERNS_SECRETS.items():
            matches = pattern.findall(source_code)
            if matches:
                results.append({
                    "type": secret_type, "count": len(matches),
                    "severity": "critical", "sample": str(matches[0])[:100],
                })
        return results

    def generate_dependency_graph(self, source_code: str) -> Dict:
        """Map import/require relationships."""
        imports = []
        for m in _RE_REQUIRE.finditer(source_code):
            imports.append(m.group(1))
        for m in _RE_IMPORT_FROM.finditer(source_code):
            imports.append(m.group(1))
        return {"imports": list(set(imports)), "total_dependencies": len(set(imports))}


class TrafficAnalyzer:
    """Analyzer for intercepted browser extension traffic."""

    def parse_amf(self, data: bytes) -> Dict:
        """Parse AMF0/AMF3 binary data."""
        if len(data) < 2:
            return {"error": "Data too short for AMF"}
        try:
            version = struct.unpack(">H", data[:2])[0]
            if version not in (0, 3):
                return {"error": f"Unknown AMF version: {version}"}
            pos = 2
            header_count = struct.unpack(">H", data[pos:pos + 2])[0]
            pos += 2
            headers = []
            for _ in range(header_count):
                if pos + 2 > len(data):
                    break
                name_len = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
                name = data[pos:pos + name_len].decode("utf-8", errors="replace")
                pos += name_len + 5
                headers.append(name)
            body_count = struct.unpack(">H", data[pos:pos + 2])[0] if pos + 2 <= len(data) else 0
            return {
                "success": True, "version": version,
                "header_count": header_count, "headers": headers,
                "body_count": body_count, "raw_bytes": len(data),
            }
        except struct.error as exc:
            return {"error": f"AMF parse error: {exc}"}

    def parse_java_serialization(self, data: bytes) -> Dict:
        """Parse Java serialized object stream."""
        if len(data) < 4:
            return {"error": "Data too short"}
        if data[:2] != b"\xac\xed":
            return {"error": f"Not Java serialization (magic={data[:2].hex()})"}
        version = struct.unpack(">H", data[2:4])[0]
        result: Dict = {
            "success": True, "magic": "ACED 0005",
            "stream_version": version, "total_bytes": len(data),
            "class_descriptors": [],
        }
        pos = 4
        while pos < len(data) - 2:
            if data[pos] == 0x72:
                pos += 1
                if pos + 2 > len(data):
                    break
                name_len = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
                if pos + name_len > len(data):
                    break
                class_name = data[pos:pos + name_len].decode("utf-8", errors="replace")
                result["class_descriptors"].append(class_name)
                pos += name_len
            else:
                pos += 1
            if len(result["class_descriptors"]) >= 20:
                break
        return result

    def identify_protocol(self, data: bytes) -> str:
        """Identify protocol/format of captured data."""
        if not data:
            return "empty"
        if data[:4] in (b"HTTP", b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD"):
            return "http"
        if data[:2] == b"\xac\xed":
            return "java_serialization"
        if data[:4] == b"\x00asm":
            return "wasm"
        stripped = data.lstrip(b" \t\r\n")
        if stripped[:1] in (b"{", b"["):
            return "json"
        if stripped[:5] in (b"<?xml", b"<soap", b"<env"):
            return "xml"
        return "unknown"

    def parse_websocket_frames(self, data: bytes) -> List[Dict]:
        """Parse WebSocket frame format."""
        frames = []
        pos = 0
        opcodes = {0: "continuation", 1: "text", 2: "binary",
                   8: "close", 9: "ping", 10: "pong"}
        while pos + 2 <= len(data):
            b0 = data[pos]
            b1 = data[pos + 1]
            fin = bool(b0 & 0x80)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            payload_len = b1 & 0x7F
            pos += 2
            if payload_len == 126:
                if pos + 2 > len(data):
                    break
                payload_len = struct.unpack(">H", data[pos:pos + 2])[0]
                pos += 2
            elif payload_len == 127:
                if pos + 8 > len(data):
                    break
                payload_len = struct.unpack(">Q", data[pos:pos + 8])[0]
                pos += 8
            mask_key = b""
            if masked:
                if pos + 4 > len(data):
                    break
                mask_key = data[pos:pos + 4]
                pos += 4
            payload = data[pos:pos + payload_len]
            if masked and mask_key:
                payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
            pos += payload_len
            frame: Dict = {
                "fin": fin,
                "opcode": opcodes.get(opcode, f"reserved({opcode})"),
                "masked": masked, "payload_length": payload_len,
            }
            if opcode == 1:
                frame["text"] = payload.decode("utf-8", errors="replace")
            else:
                frame["hex"] = payload[:64].hex()
            frames.append(frame)
        return frames

    def extract_credentials(self, data: bytes) -> List[Dict]:
        """Find authentication tokens and credentials in traffic data."""
        results = []
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            return results
        for secret_type, pattern in PATTERNS_SECRETS.items():
            matches = pattern.findall(text)
            if matches:
                results.append({"type": secret_type, "count": len(matches),
                                 "sample": str(matches[0])[:100]})
        bearer = re.findall(
            r"(?i)(?:Authorization|Bearer)[:\s]+([A-Za-z0-9\-._~+/]+=*)", text
        )
        if bearer:
            results.append({"type": "bearer_token", "count": len(bearer),
                            "sample": bearer[0][:60]})
        return results


class RecompilationEngine:
    """Engine for recompiling modified source code."""

    def __init__(self):
        self._paths = TOOL_PATHS

    def _find_tool(self, key: str) -> Optional[str]:
        path = self._paths.get(key, "")
        return shutil.which(path) if path else None

    def recompile_java(self, source_dir: str, output_jar: str) -> Dict:
        """Compile .java files to .class and package into JAR."""
        javac = self._find_tool("javac")
        jar_tool = self._find_tool("jar")
        if not javac:
            return {"success": False, "error": "javac not found — install JDK"}
        if not jar_tool:
            return {"success": False, "error": "jar tool not found — install JDK"}
        java_files = list(Path(source_dir).rglob("*.java"))
        if not java_files:
            return {"success": False, "error": "No .java files found"}
        with tempfile.TemporaryDirectory() as classes_dir:
            try:
                compile_result = subprocess.run(
                    [javac, "-d", classes_dir] + [str(f) for f in java_files],
                    capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT,
                )
                if compile_result.returncode != 0:
                    return {"success": False, "error": "Compilation failed",
                            "log": compile_result.stdout + compile_result.stderr}
                jar_result = subprocess.run(
                    [jar_tool, "cf", output_jar, "-C", classes_dir, "."],
                    capture_output=True, text=True, timeout=60,
                )
                return {"success": jar_result.returncode == 0, "output_jar": output_jar,
                        "log": jar_result.stdout + jar_result.stderr}
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "Compilation timed out"}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def recompile_actionscript(self, source_dir: str, output_swf: str) -> Dict:
        """Compile ActionScript 3 source to SWF using Flex SDK mxmlc."""
        mxmlc = self._find_tool("mxmlc")
        if not mxmlc:
            return {"success": False, "error": "mxmlc not found — install Apache Flex SDK"}
        main_files = list(Path(source_dir).rglob("Main.as"))
        if not main_files:
            as_files = list(Path(source_dir).rglob("*.as"))
            if not as_files:
                return {"success": False, "error": "No .as files found"}
            main_file = str(as_files[0])
        else:
            main_file = str(main_files[0])
        try:
            result = subprocess.run(
                [mxmlc, "-output", output_swf, main_file],
                capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT,
            )
            return {"success": result.returncode == 0, "output_swf": output_swf,
                    "log": result.stdout + result.stderr}
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "mxmlc timed out"}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def recompile_csharp(self, source_dir: str, output_xap: str) -> Dict:
        """Compile C# source and package into XAP."""
        dotnet = self._find_tool("dotnet")
        if not dotnet:
            return {"success": False, "error": "dotnet CLI not found — install .NET SDK"}
        csproj_files = list(Path(source_dir).rglob("*.csproj"))
        if not csproj_files:
            return {"success": False, "error": "No .csproj file found"}
        with tempfile.TemporaryDirectory() as build_dir:
            try:
                result = subprocess.run(
                    [dotnet, "build", str(csproj_files[0]),
                     "-o", build_dir, "--configuration", "Release"],
                    capture_output=True, text=True, timeout=DECOMPILE_TIMEOUT,
                )
                if result.returncode != 0:
                    return {"success": False, "error": "Build failed",
                            "log": result.stdout + result.stderr}
                dlls = list(Path(build_dir).glob("*.dll"))
                with zipfile.ZipFile(output_xap, "w", zipfile.ZIP_DEFLATED) as zf:
                    for dll in dlls:
                        zf.write(dll, dll.name)
                return {"success": True, "output_xap": output_xap,
                        "log": result.stdout + result.stderr}
            except subprocess.TimeoutExpired:
                return {"success": False, "error": "dotnet build timed out"}
            except Exception as exc:
                return {"success": False, "error": str(exc)}

    def repackage_chrome_extension(self, source_dir: str, output_crx: str,
                                   signing_key: Optional[str] = None) -> Dict:
        """Rebuild a Chrome extension ZIP (unsigned)."""
        try:
            with zipfile.ZipFile(output_crx, "w", zipfile.ZIP_DEFLATED) as zf:
                for path in Path(source_dir).rglob("*"):
                    if path.is_file():
                        zf.write(path, path.relative_to(source_dir))
            return {"success": True, "output_crx": output_crx,
                    "note": "Packaged as unsigned ZIP."}
        except Exception as exc:
            return {"success": False, "error": str(exc)}

    def repackage_firefox_extension(self, source_dir: str, output_xpi: str) -> Dict:
        """Rebuild a Firefox extension XPI (ZIP)."""
        return self.repackage_chrome_extension(source_dir, output_xpi)

    def inject_payload(self, source_dir: str, target_file: str,
                       payload_code: str, injection_point: str = "end") -> Dict:
        """Insert custom JavaScript into a file at a specified injection point."""
        target_path = Path(source_dir) / target_file
        if not target_path.exists():
            return {"success": False, "error": f"Target file not found: {target_file}"}
        try:
            original = target_path.read_text(encoding="utf-8", errors="replace")
            if injection_point == "start":
                modified = payload_code + "\n" + original
            elif injection_point == "end":
                modified = original + "\n" + payload_code
            else:
                match = re.search(injection_point, original)
                if not match:
                    return {"success": False,
                            "error": f"Injection point pattern not found: {injection_point}"}
                pos = match.end()
                modified = original[:pos] + "\n" + payload_code + "\n" + original[pos:]
            target_path.write_text(modified, encoding="utf-8")
            return {"success": True, "modified_file": str(target_path)}
        except Exception as exc:
            return {"success": False, "error": str(exc)}
