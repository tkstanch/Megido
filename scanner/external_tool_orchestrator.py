"""
External Tool Orchestrator

Orchestrates external security tools via subprocess for bug bounty / authorized
penetration testing workflows.  Each tool integration:

  1. Checks whether the tool binary is installed and on PATH.
  2. Builds the correct command with proper arguments.
  3. Executes the command via subprocess (sync) or asyncio subprocess (async).
  4. Parses structured (JSON) or plain-text output.
  5. Returns a list of :class:`EngineResult` objects that are compatible with
     the existing ``scanner.engine_plugins`` architecture.

Supported tool families
-----------------------
* **Nuclei** – template-based vulnerability scanner
* **Content Discovery** – ffuf / gobuster / feroxbuster
* **Port Scanning** – nmap
* **Application Analysis** – nikto / whatweb
* **Parameter Analysis** – arjun / paramspider

Usage::

    from scanner.external_tool_orchestrator import ExternalToolOrchestrator

    orc = ExternalToolOrchestrator()
    results = orc.run_all(target_url="https://example.com", target_file="/tmp/urls.txt")
    for r in results:
        print(f"[{r.severity}] {r.title} – {r.url}")
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from scanner.engine_plugins.base_engine import EngineResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_available(binary: str) -> bool:
    """Return *True* if *binary* is found on PATH."""
    return shutil.which(binary) is not None


def _run(cmd: List[str], timeout: int = 300, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    """
    Execute *cmd* synchronously and return the completed process.

    Both stdout and stderr are captured.  A non-zero exit code is **not**
    treated as an error here – callers must inspect ``returncode`` themselves
    because many security tools return 1 when findings are present.
    """
    logger.debug("Executing: %s", " ".join(cmd))
    merged_env = {**os.environ, **(env or {})}
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged_env,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc
    return proc


async def _run_async(
    cmd: List[str],
    timeout: int = 300,
    env: Optional[Dict[str, str]] = None,
) -> tuple[int, str, str]:
    """
    Execute *cmd* asynchronously and return ``(returncode, stdout, stderr)``.
    """
    logger.debug("Async executing: %s", " ".join(cmd))
    merged_env = {**os.environ, **(env or {})}
    try:
        proc = await asyncio.wait_for(
            asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=merged_env,
            ),
            timeout=timeout,
        )
        stdout_bytes, stderr_bytes = await proc.communicate()
        return proc.returncode, stdout_bytes.decode(errors="replace"), stderr_bytes.decode(errors="replace")
    except asyncio.TimeoutError as exc:
        raise RuntimeError(
            f"Async command timed out after {timeout}s: {' '.join(cmd)}"
        ) from exc


# ---------------------------------------------------------------------------
# Nuclei Scanner
# ---------------------------------------------------------------------------

class NucleiScanner:
    """
    Integration with `nuclei <https://github.com/projectdiscovery/nuclei>`_
    template-based vulnerability scanner.

    Nuclei is executed with a comprehensive set of template categories and
    its JSONL output is parsed into :class:`EngineResult` objects.
    """

    ENGINE_ID = "nuclei"
    ENGINE_NAME = "Nuclei Template Scanner"

    # Template tags / categories to include in the scan
    DEFAULT_TAGS: List[str] = [
        "cve",
        "oast",
        "xss",
        "sqli",
        "rce",
        "lfi",
        "ssrf",
        "exposed",
        "misconfig",
        "default-login",
        "exposure",
        "fuzzing",
        "takeover",
    ]

    # Severity levels that Nuclei uses
    _SEVERITY_MAP: Dict[str, str] = {
        "info": "info",
        "low": "low",
        "medium": "medium",
        "high": "high",
        "critical": "critical",
        "unknown": "low",
    }

    def is_available(self) -> bool:
        """Return *True* if the ``nuclei`` binary is on PATH."""
        return _is_available("nuclei")

    def scan(
        self,
        target_url: Optional[str] = None,
        target_file: Optional[str] = None,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        rate_limit: int = 150,
        timeout: int = 600,
        extra_args: Optional[List[str]] = None,
    ) -> List[EngineResult]:
        """
        Run Nuclei against one or more targets.

        Args:
            target_url:  Single URL to scan (mutually optional with *target_file*).
            target_file: File containing one URL per line.
            tags:        List of Nuclei template tags (defaults to
                         :attr:`DEFAULT_TAGS`).
            severity:    Severity levels to report (e.g. ``['high', 'critical']``).
                         *None* means all severities.
            rate_limit:  Maximum requests per second.
            timeout:     Command-level timeout in seconds.
            extra_args:  Additional raw arguments passed to the nuclei binary.

        Returns:
            List of :class:`EngineResult` findings.

        Raises:
            RuntimeError: If Nuclei is not installed or the command fails.
        """
        if not self.is_available():
            raise RuntimeError(
                "nuclei is not installed or not on PATH. "
                "Install: https://github.com/projectdiscovery/nuclei#installation"
            )
        if not target_url and not target_file:
            raise ValueError("Provide either target_url or target_file")

        tags_to_use = tags or self.DEFAULT_TAGS

        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", mode="w", delete=False
        ) as out_file:
            output_path = out_file.name

        try:
            cmd = ["nuclei"]

            if target_file:
                cmd += ["-l", target_file]
            else:
                cmd += ["-u", target_url]

            cmd += [
                "-t", "nuclei-templates/",
                "-tags", ",".join(tags_to_use),
                "-rl", str(rate_limit),
                "-j",                     # JSONL output
                "-o", output_path,
                "-silent",
                "-no-color",
            ]

            if severity:
                cmd += ["-severity", ",".join(severity)]

            if extra_args:
                cmd.extend(extra_args)

            proc = _run(cmd, timeout=timeout)
            if proc.returncode not in (0, 1):
                logger.warning(
                    "nuclei exited with code %d. stderr: %s",
                    proc.returncode,
                    proc.stderr[:500],
                )

            return self._parse_output(output_path)
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass

    async def scan_async(
        self,
        target_url: Optional[str] = None,
        target_file: Optional[str] = None,
        tags: Optional[List[str]] = None,
        severity: Optional[List[str]] = None,
        rate_limit: int = 150,
        timeout: int = 600,
        extra_args: Optional[List[str]] = None,
    ) -> List[EngineResult]:
        """Async variant of :meth:`scan`."""
        if not self.is_available():
            raise RuntimeError("nuclei is not installed or not on PATH.")
        if not target_url and not target_file:
            raise ValueError("Provide either target_url or target_file")

        tags_to_use = tags or self.DEFAULT_TAGS

        with tempfile.NamedTemporaryFile(
            suffix=".jsonl", mode="w", delete=False
        ) as out_file:
            output_path = out_file.name

        try:
            cmd = ["nuclei"]
            if target_file:
                cmd += ["-l", target_file]
            else:
                cmd += ["-u", target_url]

            cmd += [
                "-t", "nuclei-templates/",
                "-tags", ",".join(tags_to_use),
                "-rl", str(rate_limit),
                "-j",
                "-o", output_path,
                "-silent",
                "-no-color",
            ]
            if severity:
                cmd += ["-severity", ",".join(severity)]
            if extra_args:
                cmd.extend(extra_args)

            rc, _out, stderr = await _run_async(cmd, timeout=timeout)
            if rc not in (0, 1):
                logger.warning("nuclei async exited with code %d. stderr: %s", rc, stderr[:500])

            return self._parse_output(output_path)
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass

    def _parse_output(self, output_path: str) -> List[EngineResult]:
        """Parse Nuclei JSONL output file into :class:`EngineResult` objects."""
        findings: List[EngineResult] = []
        try:
            with open(output_path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        logger.debug("Skipping non-JSON Nuclei line: %s", line[:120])
                        continue
                    findings.append(self._item_to_result(item))
        except FileNotFoundError:
            logger.debug("Nuclei output file not found – no findings.")
        return findings

    def _item_to_result(self, item: Dict[str, Any]) -> EngineResult:
        """Convert a single Nuclei JSONL record to an :class:`EngineResult`."""
        info = item.get("info", {})
        severity_raw = info.get("severity", "info").lower()
        severity = self._SEVERITY_MAP.get(severity_raw, "info")

        # Confidence: Nuclei verified findings are high confidence
        confidence_map = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.70,
            "low": 0.55,
            "info": 0.40,
        }
        confidence = confidence_map.get(severity, 0.60)

        matched_at = item.get("matched-at", item.get("host", ""))
        template_id = item.get("template-id", "")
        name = info.get("name", template_id)
        description = info.get("description", "")
        tags = info.get("tags", [])
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]

        cve_id: Optional[str] = None
        cwe_id: Optional[str] = None
        for tag in (tags if isinstance(tags, list) else []):
            if isinstance(tag, str):
                if tag.upper().startswith("CVE-"):
                    cve_id = tag.upper()
                elif tag.upper().startswith("CWE-"):
                    cwe_id = tag.upper()

        # Classification block (newer Nuclei versions)
        classification = info.get("classification", {})
        if not cve_id and classification.get("cve-id"):
            cve_ids = classification["cve-id"]
            cve_id = cve_ids[0] if isinstance(cve_ids, list) else cve_ids
        if not cwe_id and classification.get("cwe-id"):
            cwe_ids = classification["cwe-id"]
            cwe_id = cwe_ids[0] if isinstance(cwe_ids, list) else cwe_ids

        extracted_results = item.get("extracted-results", [])
        evidence_parts = [f"Template: {template_id}", f"Matched at: {matched_at}"]
        if extracted_results:
            evidence_parts.append(f"Extracted: {', '.join(str(r) for r in extracted_results[:5])}")
        evidence = "\n".join(evidence_parts)

        curl_command = item.get("curl-command", "")
        if curl_command:
            evidence += f"\nCurl: {curl_command}"

        remediation = info.get("remediation", "Review the finding and apply the recommended fix.")

        return EngineResult(
            engine_id=self.ENGINE_ID,
            engine_name=self.ENGINE_NAME,
            title=name,
            description=description or f"Nuclei template {template_id} matched.",
            severity=severity,
            confidence=confidence,
            url=matched_at or None,
            category=", ".join(tags) if isinstance(tags, list) else str(tags),
            cwe_id=cwe_id,
            cve_id=cve_id,
            evidence=evidence,
            remediation=remediation,
            references=references,
            raw_output=item,
        )


# ---------------------------------------------------------------------------
# Content Discovery Scanner
# ---------------------------------------------------------------------------

class ContentDiscoveryScanner:
    """
    Content / directory discovery using **ffuf**, **gobuster**, or
    **feroxbuster** (first available tool is used).

    Discovered paths are returned as informational :class:`EngineResult`
    findings so that the rest of the scan pipeline can further analyse them.
    """

    ENGINE_ID = "content_discovery"
    ENGINE_NAME = "Content Discovery Scanner"

    # Preference order – first available binary wins
    PREFERRED_TOOLS: List[str] = ["ffuf", "feroxbuster", "gobuster"]

    def is_available(self) -> bool:
        """Return *True* if at least one discovery binary is on PATH."""
        return any(_is_available(t) for t in self.PREFERRED_TOOLS)

    def _pick_tool(self) -> Optional[str]:
        for tool in self.PREFERRED_TOOLS:
            if _is_available(tool):
                return tool
        return None

    def scan(
        self,
        target_url: str,
        wordlist: str = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
        extensions: Optional[List[str]] = None,
        threads: int = 40,
        timeout: int = 300,
        status_codes: Optional[List[int]] = None,
        extra_args: Optional[List[str]] = None,
    ) -> List[EngineResult]:
        """
        Perform directory/file brute-force against *target_url*.

        Args:
            target_url:   Base URL to enumerate.
            wordlist:     Path to the wordlist file.
            extensions:   File extensions to try (e.g. ``['php', 'asp']``).
            threads:      Number of concurrent requests.
            timeout:      Command-level timeout in seconds.
            status_codes: HTTP status codes to report.  Defaults to
                          ``[200, 201, 204, 301, 302, 307, 401, 403]``.
            extra_args:   Additional raw arguments passed to the binary.

        Returns:
            List of :class:`EngineResult` findings for discovered paths.

        Raises:
            RuntimeError: If no supported tool is installed.
        """
        tool = self._pick_tool()
        if not tool:
            raise RuntimeError(
                "No content discovery tool found. Install one of: "
                + ", ".join(self.PREFERRED_TOOLS)
            )
        if not os.path.isfile(wordlist):
            raise FileNotFoundError(f"Wordlist not found: {wordlist}")

        status_codes = status_codes or [200, 201, 204, 301, 302, 307, 401, 403]
        ext_str = ",".join(extensions) if extensions else ""

        if tool == "ffuf":
            return self._scan_ffuf(target_url, wordlist, ext_str, threads, timeout, status_codes, extra_args)
        elif tool == "feroxbuster":
            return self._scan_feroxbuster(target_url, wordlist, ext_str, threads, timeout, status_codes, extra_args)
        else:  # gobuster
            return self._scan_gobuster(target_url, wordlist, ext_str, threads, timeout, status_codes, extra_args)

    # ---- ffuf ---------------------------------------------------------------

    def _scan_ffuf(
        self,
        target_url: str,
        wordlist: str,
        extensions: str,
        threads: int,
        timeout: int,
        status_codes: List[int],
        extra_args: Optional[List[str]],
    ) -> List[EngineResult]:
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            out = f.name
        try:
            # Ensure FUZZ keyword is present
            url = target_url.rstrip("/") + "/FUZZ"
            cmd = [
                "ffuf",
                "-u", url,
                "-w", wordlist,
                "-t", str(threads),
                "-mc", ",".join(str(c) for c in status_codes),
                "-of", "json",
                "-o", out,
                "-s",  # silent mode
            ]
            if extensions:
                cmd += ["-e", extensions]
            if extra_args:
                cmd.extend(extra_args)
            proc = _run(cmd, timeout=timeout)
            if proc.returncode not in (0, 1):
                logger.warning("ffuf exited %d: %s", proc.returncode, proc.stderr[:300])
            return self._parse_ffuf(out, target_url)
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    def _parse_ffuf(self, path: str, base_url: str) -> List[EngineResult]:
        findings: List[EngineResult] = []
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError):
            return findings
        for result in data.get("results", []):
            url = result.get("url", "")
            status = result.get("status", 0)
            length = result.get("length", 0)
            findings.append(
                EngineResult(
                    engine_id=self.ENGINE_ID,
                    engine_name=self.ENGINE_NAME,
                    title=f"Discovered path: {result.get('input', {}).get('FUZZ', url)}",
                    description=(
                        f"Content discovery found a reachable path.\n"
                        f"URL: {url}\nStatus: {status}\nLength: {length}"
                    ),
                    severity="info",
                    confidence=0.90,
                    url=url,
                    category="content_discovery",
                    evidence=f"HTTP {status} – {length} bytes",
                    remediation=(
                        "Review the discovered path; restrict access to sensitive resources."
                    ),
                    raw_output=result,
                )
            )
        return findings

    # ---- feroxbuster --------------------------------------------------------

    def _scan_feroxbuster(
        self,
        target_url: str,
        wordlist: str,
        extensions: str,
        threads: int,
        timeout: int,
        status_codes: List[int],
        extra_args: Optional[List[str]],
    ) -> List[EngineResult]:
        with tempfile.NamedTemporaryFile(suffix=".jsonl", mode="w", delete=False) as f:
            out = f.name
        try:
            cmd = [
                "feroxbuster",
                "--url", target_url,
                "--wordlist", wordlist,
                "--threads", str(threads),
                "--status-codes", " ".join(str(c) for c in status_codes),
                "--json",
                "--output", out,
                "--quiet",
                "--no-state",
            ]
            if extensions:
                cmd += ["--extensions", extensions]
            if extra_args:
                cmd.extend(extra_args)
            proc = _run(cmd, timeout=timeout)
            if proc.returncode not in (0, 1):
                logger.warning("feroxbuster exited %d: %s", proc.returncode, proc.stderr[:300])
            return self._parse_feroxbuster(out)
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    def _parse_feroxbuster(self, path: str) -> List[EngineResult]:
        findings: List[EngineResult] = []
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if item.get("type") != "response":
                        continue
                    url = item.get("url", "")
                    status = item.get("status", 0)
                    findings.append(
                        EngineResult(
                            engine_id=self.ENGINE_ID,
                            engine_name=self.ENGINE_NAME,
                            title=f"Discovered path: {url}",
                            description=f"feroxbuster found a reachable path. Status: {status}",
                            severity="info",
                            confidence=0.90,
                            url=url,
                            category="content_discovery",
                            evidence=f"HTTP {status}",
                            remediation="Review the discovered path; restrict access if sensitive.",
                            raw_output=item,
                        )
                    )
        except FileNotFoundError:
            pass
        return findings

    # ---- gobuster -----------------------------------------------------------

    def _scan_gobuster(
        self,
        target_url: str,
        wordlist: str,
        extensions: str,
        threads: int,
        timeout: int,
        status_codes: List[int],
        extra_args: Optional[List[str]],
    ) -> List[EngineResult]:
        cmd = [
            "gobuster", "dir",
            "-u", target_url,
            "-w", wordlist,
            "-t", str(threads),
            "-s", ",".join(str(c) for c in status_codes),
            "--no-progress",
            "--no-error",
        ]
        if extensions:
            cmd += ["-x", extensions]
        if extra_args:
            cmd.extend(extra_args)
        proc = _run(cmd, timeout=timeout)
        return self._parse_gobuster(proc.stdout, target_url)

    def _parse_gobuster(self, output: str, base_url: str) -> List[EngineResult]:
        """
        Parse gobuster plain-text output.

        Example line::

            /admin                (Status: 301) [Size: 321] [--> /admin/]
        """
        findings: List[EngineResult] = []
        import re
        pattern = re.compile(
            r"^(/\S+)\s+\(Status:\s*(\d+)\)(?:\s*\[Size:\s*(\d+)\])?",
            re.MULTILINE,
        )
        for match in pattern.finditer(output):
            path = match.group(1)
            status = int(match.group(2))
            size = match.group(3) or "?"
            url = base_url.rstrip("/") + path
            findings.append(
                EngineResult(
                    engine_id=self.ENGINE_ID,
                    engine_name=self.ENGINE_NAME,
                    title=f"Discovered path: {path}",
                    description=f"gobuster found a reachable path. Status: {status}",
                    severity="info",
                    confidence=0.85,
                    url=url,
                    category="content_discovery",
                    evidence=f"HTTP {status} – {size} bytes",
                    remediation="Review the discovered path; restrict access if sensitive.",
                    raw_output={"path": path, "status": status, "size": size},
                )
            )
        return findings


# ---------------------------------------------------------------------------
# Port Scan Orchestrator
# ---------------------------------------------------------------------------

class PortScanOrchestrator:
    """
    Port scanning via `nmap <https://nmap.org/>`_.

    Runs nmap with XML output and parses open ports / service versions into
    :class:`EngineResult` findings.
    """

    ENGINE_ID = "nmap_port_scan"
    ENGINE_NAME = "Nmap Port Scanner"

    def is_available(self) -> bool:
        """Return *True* if ``nmap`` is on PATH."""
        return _is_available("nmap")

    def scan(
        self,
        target: str,
        ports: str = "1-65535",
        scan_type: str = "-sV",
        timing: str = "-T4",
        scripts: Optional[List[str]] = None,
        timeout: int = 600,
        extra_args: Optional[List[str]] = None,
    ) -> List[EngineResult]:
        """
        Scan *target* for open ports and service information.

        Args:
            target:     Hostname or IP address to scan.
            ports:      Port range string (e.g. ``"80,443,8080"`` or ``"1-1024"``).
            scan_type:  nmap scan flag (e.g. ``"-sV"`` for version detection).
            timing:     nmap timing template (``"-T4"`` recommended).
            scripts:    List of NSE script names/categories to run.
            timeout:    Command-level timeout in seconds.
            extra_args: Additional raw nmap arguments.

        Returns:
            List of :class:`EngineResult` findings (one per open port).

        Raises:
            RuntimeError: If nmap is not installed or the command fails fatally.
        """
        if not self.is_available():
            raise RuntimeError(
                "nmap is not installed or not on PATH. "
                "Install: https://nmap.org/download.html"
            )

        with tempfile.NamedTemporaryFile(suffix=".xml", mode="w", delete=False) as f:
            xml_out = f.name

        try:
            cmd = ["nmap", scan_type, timing, "-p", ports, "-oX", xml_out, "--open"]
            if scripts:
                cmd += ["--script", ",".join(scripts)]
            if extra_args:
                cmd.extend(extra_args)
            cmd.append(target)

            proc = _run(cmd, timeout=timeout)
            if proc.returncode != 0:
                logger.warning("nmap exited %d: %s", proc.returncode, proc.stderr[:300])

            return self._parse_xml(xml_out, target)
        finally:
            try:
                os.unlink(xml_out)
            except OSError:
                pass

    def _parse_xml(self, xml_path: str, target: str) -> List[EngineResult]:
        """Parse nmap XML output into :class:`EngineResult` objects."""
        findings: List[EngineResult] = []
        try:
            import xml.etree.ElementTree as ET
            tree = ET.parse(xml_path)
            root = tree.getroot()
        except Exception as exc:
            logger.error("Failed to parse nmap XML %s: %s", xml_path, exc)
            return findings

        for host in root.findall("host"):
            address_el = host.find("address")
            ip = address_el.get("addr", target) if address_el is not None else target

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port_el in ports_el.findall("port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                portid = port_el.get("portid", "?")
                protocol = port_el.get("protocol", "tcp")

                service_el = port_el.find("service")
                service_name = "unknown"
                product = ""
                version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "unknown")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")

                service_str = " ".join(filter(None, [service_name, product, version]))

                # NSE script output
                script_output: List[str] = []
                for script_el in port_el.findall("script"):
                    script_output.append(
                        f"{script_el.get('id', '')}: {script_el.get('output', '')}"
                    )

                description = (
                    f"Open port {portid}/{protocol} on {ip}. "
                    f"Service: {service_str}."
                )
                if script_output:
                    description += "\nNSE output:\n" + "\n".join(script_output)

                # Elevate severity for well-known sensitive ports
                severity = self._port_severity(int(portid) if portid.isdigit() else 0, service_name)

                findings.append(
                    EngineResult(
                        engine_id=self.ENGINE_ID,
                        engine_name=self.ENGINE_NAME,
                        title=f"Open port {portid}/{protocol} – {service_str}",
                        description=description,
                        severity=severity,
                        confidence=0.95,
                        url=f"{protocol}://{ip}:{portid}",
                        category="port_scan",
                        evidence=description,
                        remediation=(
                            f"Review whether port {portid} should be publicly accessible. "
                            "Close unnecessary services or restrict access via firewall rules."
                        ),
                        raw_output={
                            "ip": ip,
                            "port": portid,
                            "protocol": protocol,
                            "service": service_str,
                            "scripts": script_output,
                        },
                    )
                )
        return findings

    @staticmethod
    def _port_severity(port: int, service: str) -> str:
        """Heuristic severity based on port number / service name."""
        high_risk_ports = {21, 22, 23, 25, 110, 143, 3389, 5900, 6379, 27017}
        medium_risk_ports = {80, 443, 8080, 8443, 3306, 5432, 1433}
        if port in high_risk_ports or service.lower() in ("telnet", "ftp", "rdp", "vnc", "redis", "mongodb"):
            return "high"
        if port in medium_risk_ports or service.lower() in ("http", "https", "mysql", "postgresql", "mssql"):
            return "medium"
        return "info"


# ---------------------------------------------------------------------------
# Application Analyzer
# ---------------------------------------------------------------------------

class ApplicationAnalyzer:
    """
    Application-layer analysis using **nikto** and/or **whatweb**.

    Both tools are run independently and their findings are merged.
    """

    ENGINE_ID = "application_analysis"
    ENGINE_NAME = "Application Analyzer"

    def is_available(self) -> bool:
        """Return *True* if at least one tool is available."""
        return _is_available("nikto") or _is_available("whatweb")

    # ---- public API ---------------------------------------------------------

    def scan(
        self,
        target_url: str,
        run_nikto: bool = True,
        run_whatweb: bool = True,
        nikto_timeout: int = 300,
        whatweb_timeout: int = 60,
        extra_nikto_args: Optional[List[str]] = None,
        extra_whatweb_args: Optional[List[str]] = None,
    ) -> List[EngineResult]:
        """
        Analyse *target_url* with nikto and/or whatweb.

        Args:
            target_url:        URL to analyse.
            run_nikto:         Include nikto scan.
            run_whatweb:       Include whatweb fingerprinting.
            nikto_timeout:     Timeout for nikto command.
            whatweb_timeout:   Timeout for whatweb command.
            extra_nikto_args:  Additional nikto arguments.
            extra_whatweb_args: Additional whatweb arguments.

        Returns:
            Combined list of :class:`EngineResult` findings.
        """
        findings: List[EngineResult] = []

        if run_nikto and _is_available("nikto"):
            try:
                findings.extend(
                    self._scan_nikto(target_url, nikto_timeout, extra_nikto_args)
                )
            except Exception as exc:
                logger.error("nikto scan failed: %s", exc)

        if run_whatweb and _is_available("whatweb"):
            try:
                findings.extend(
                    self._scan_whatweb(target_url, whatweb_timeout, extra_whatweb_args)
                )
            except Exception as exc:
                logger.error("whatweb scan failed: %s", exc)

        return findings

    # ---- nikto --------------------------------------------------------------

    def _scan_nikto(
        self,
        target_url: str,
        timeout: int,
        extra_args: Optional[List[str]],
    ) -> List[EngineResult]:
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            out = f.name
        try:
            cmd = [
                "nikto",
                "-h", target_url,
                "-Format", "json",
                "-output", out,
                "-nointeractive",
            ]
            if extra_args:
                cmd.extend(extra_args)
            proc = _run(cmd, timeout=timeout)
            if proc.returncode not in (0, 1):
                logger.warning("nikto exited %d: %s", proc.returncode, proc.stderr[:300])
            return self._parse_nikto(out)
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    def _parse_nikto(self, path: str) -> List[EngineResult]:
        findings: List[EngineResult] = []
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.debug("Nikto JSON parse failed: %s", exc)
            return findings

        # Nikto JSON schema: {"vulnerabilities": [...]}
        vulns = data.get("vulnerabilities", [])
        if not vulns and isinstance(data, list):
            vulns = data

        for item in vulns:
            msg = item.get("msg", item.get("message", "Nikto finding"))
            url = item.get("url", item.get("host", ""))
            osvdb = item.get("OSVDB", "")
            severity = "medium"  # Nikto doesn't provide severity; default to medium
            if osvdb:
                description = f"{msg} (OSVDB-{osvdb})"
            else:
                description = msg
            findings.append(
                EngineResult(
                    engine_id=self.ENGINE_ID,
                    engine_name=self.ENGINE_NAME,
                    title=f"Nikto: {msg[:100]}",
                    description=description,
                    severity=severity,
                    confidence=0.70,
                    url=url or None,
                    category="web_application",
                    evidence=msg,
                    remediation="Investigate the flagged issue and apply appropriate mitigations.",
                    raw_output=item,
                )
            )
        return findings

    # ---- whatweb ------------------------------------------------------------

    def _scan_whatweb(
        self,
        target_url: str,
        timeout: int,
        extra_args: Optional[List[str]],
    ) -> List[EngineResult]:
        cmd = [
            "whatweb",
            "--log-json=/dev/stdout",
            "--quiet",
            "--no-errors",
            target_url,
        ]
        if extra_args:
            cmd.extend(extra_args)
        proc = _run(cmd, timeout=timeout)
        return self._parse_whatweb(proc.stdout, target_url)

    def _parse_whatweb(self, output: str, target_url: str) -> List[EngineResult]:
        """
        Parse whatweb JSON output.

        Whatweb outputs one JSON object per line when ``--log-json`` is used.
        """
        findings: List[EngineResult] = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            target = record.get("target", target_url)
            plugins = record.get("plugins", {})
            if not plugins:
                continue

            detected: List[str] = []
            for plugin_name, plugin_data in plugins.items():
                if isinstance(plugin_data, dict):
                    version = plugin_data.get("version", [])
                    if version:
                        detected.append(f"{plugin_name} {version[0]}")
                    else:
                        detected.append(plugin_name)
                else:
                    detected.append(plugin_name)

            if detected:
                findings.append(
                    EngineResult(
                        engine_id=self.ENGINE_ID,
                        engine_name=self.ENGINE_NAME,
                        title=f"Technology fingerprint: {target}",
                        description=(
                            "WhatWeb identified the following technologies:\n"
                            + "\n".join(f"  - {d}" for d in detected)
                        ),
                        severity="info",
                        confidence=0.80,
                        url=target,
                        category="tech_fingerprinting",
                        evidence=", ".join(detected[:20]),
                        remediation=(
                            "Review exposed version information; consider removing "
                            "or obfuscating server/technology headers."
                        ),
                        raw_output=record,
                    )
                )
        return findings


# ---------------------------------------------------------------------------
# Parameter Analyzer
# ---------------------------------------------------------------------------

class ParameterAnalyzer:
    """
    Discover hidden / undocumented HTTP parameters using **arjun** and/or
    **paramspider**.
    """

    ENGINE_ID = "parameter_analysis"
    ENGINE_NAME = "Parameter Analyzer"

    def is_available(self) -> bool:
        """Return *True* if arjun or paramspider is on PATH."""
        return _is_available("arjun") or _is_available("paramspider")

    def scan(
        self,
        target_url: str,
        run_arjun: bool = True,
        run_paramspider: bool = True,
        arjun_timeout: int = 180,
        paramspider_timeout: int = 120,
        extra_arjun_args: Optional[List[str]] = None,
        extra_paramspider_args: Optional[List[str]] = None,
    ) -> List[EngineResult]:
        """
        Discover parameters in *target_url*.

        Args:
            target_url:             URL to analyse.
            run_arjun:              Run arjun parameter discovery.
            run_paramspider:        Run paramspider discovery.
            arjun_timeout:          Timeout for arjun command.
            paramspider_timeout:    Timeout for paramspider command.
            extra_arjun_args:       Additional arjun arguments.
            extra_paramspider_args: Additional paramspider arguments.

        Returns:
            Combined list of :class:`EngineResult` findings.
        """
        findings: List[EngineResult] = []

        if run_arjun and _is_available("arjun"):
            try:
                findings.extend(
                    self._scan_arjun(target_url, arjun_timeout, extra_arjun_args)
                )
            except Exception as exc:
                logger.error("arjun scan failed: %s", exc)

        if run_paramspider and _is_available("paramspider"):
            try:
                findings.extend(
                    self._scan_paramspider(target_url, paramspider_timeout, extra_paramspider_args)
                )
            except Exception as exc:
                logger.error("paramspider scan failed: %s", exc)

        return findings

    # ---- arjun --------------------------------------------------------------

    def _scan_arjun(
        self,
        target_url: str,
        timeout: int,
        extra_args: Optional[List[str]],
    ) -> List[EngineResult]:
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            out = f.name
        try:
            cmd = [
                "arjun",
                "-u", target_url,
                "--export-json", out,
                "-q",  # quiet
            ]
            if extra_args:
                cmd.extend(extra_args)
            proc = _run(cmd, timeout=timeout)
            if proc.returncode not in (0, 1):
                logger.warning("arjun exited %d: %s", proc.returncode, proc.stderr[:300])
            return self._parse_arjun(out, target_url)
        finally:
            try:
                os.unlink(out)
            except OSError:
                pass

    def _parse_arjun(self, path: str, target_url: str) -> List[EngineResult]:
        findings: List[EngineResult] = []
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            logger.debug("arjun parse failed: %s", exc)
            return findings

        # arjun JSON: {url: [param1, param2, ...]}
        for url, params in data.items():
            if not params:
                continue
            findings.append(
                EngineResult(
                    engine_id=self.ENGINE_ID,
                    engine_name=self.ENGINE_NAME,
                    title=f"Hidden parameters discovered: {url}",
                    description=(
                        f"arjun discovered {len(params)} hidden parameter(s) at {url}:\n"
                        + ", ".join(str(p) for p in params)
                    ),
                    severity="medium",
                    confidence=0.75,
                    url=url,
                    category="parameter_discovery",
                    evidence=f"Parameters: {', '.join(str(p) for p in params)}",
                    remediation=(
                        "Review each discovered parameter for injection vulnerabilities "
                        "(SQLi, XSS, SSRF, etc.) and remove unused parameters."
                    ),
                    raw_output={"url": url, "parameters": params},
                )
            )
        return findings

    # ---- paramspider --------------------------------------------------------

    def _scan_paramspider(
        self,
        target_url: str,
        timeout: int,
        extra_args: Optional[List[str]],
    ) -> List[EngineResult]:
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path

        with tempfile.TemporaryDirectory() as tmpdir:
            cmd = [
                "paramspider",
                "--domain", domain,
                "--output", tmpdir,
                "--quiet",
            ]
            if extra_args:
                cmd.extend(extra_args)
            proc = _run(cmd, timeout=timeout)
            if proc.returncode not in (0, 1):
                logger.warning("paramspider exited %d: %s", proc.returncode, proc.stderr[:300])

            output_file = os.path.join(tmpdir, f"{domain}.txt")
            return self._parse_paramspider(output_file, target_url)

    def _parse_paramspider(self, path: str, target_url: str) -> List[EngineResult]:
        """
        Parse paramspider output file (one URL per line with ``FUZZ`` placeholder).
        """
        findings: List[EngineResult] = []
        try:
            with open(path, encoding="utf-8") as fh:
                lines = [l.strip() for l in fh if l.strip()]
        except FileNotFoundError:
            return findings

        if not lines:
            return findings

        findings.append(
            EngineResult(
                engine_id=self.ENGINE_ID,
                engine_name=self.ENGINE_NAME,
                title=f"paramspider: {len(lines)} parameterised URLs found",
                description=(
                    f"paramspider discovered {len(lines)} URLs with injectable parameters "
                    f"for the domain derived from {target_url}."
                ),
                severity="info",
                confidence=0.70,
                url=target_url,
                category="parameter_discovery",
                evidence="\n".join(lines[:30]) + ("\n..." if len(lines) > 30 else ""),
                remediation=(
                    "Test each discovered URL for injection vulnerabilities "
                    "(SQLi, XSS, open redirect, SSRF) and remove or sanitise unused parameters."
                ),
                raw_output={"urls": lines},
            )
        )
        return findings


# ---------------------------------------------------------------------------
# ExternalToolOrchestrator – top-level coordinator
# ---------------------------------------------------------------------------

@dataclass
class ExternalToolScanConfig:
    """
    Configuration container for :class:`ExternalToolOrchestrator`.

    All boolean flags default to *True*; individual tools are only executed if
    they are also available on the system PATH.
    """
    # --- Nuclei ---
    run_nuclei: bool = True
    nuclei_tags: Optional[List[str]] = None
    nuclei_severity: Optional[List[str]] = None
    nuclei_rate_limit: int = 150
    nuclei_timeout: int = 600
    nuclei_extra_args: Optional[List[str]] = None

    # --- Content Discovery ---
    run_content_discovery: bool = True
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
    content_extensions: Optional[List[str]] = None
    content_threads: int = 40
    content_timeout: int = 300
    content_extra_args: Optional[List[str]] = None

    # --- Port Scanning ---
    run_port_scan: bool = True
    port_range: str = "1-65535"
    nmap_scan_type: str = "-sV"
    nmap_timing: str = "-T4"
    nmap_scripts: Optional[List[str]] = None
    nmap_timeout: int = 600
    nmap_extra_args: Optional[List[str]] = None

    # --- Application Analysis ---
    run_application_analysis: bool = True
    run_nikto: bool = True
    run_whatweb: bool = True
    nikto_timeout: int = 300
    whatweb_timeout: int = 60
    nikto_extra_args: Optional[List[str]] = None
    whatweb_extra_args: Optional[List[str]] = None

    # --- Parameter Analysis ---
    run_parameter_analysis: bool = True
    run_arjun: bool = True
    run_paramspider: bool = True
    arjun_timeout: int = 180
    paramspider_timeout: int = 120
    arjun_extra_args: Optional[List[str]] = None
    paramspider_extra_args: Optional[List[str]] = None

    # --- General ---
    target_file: Optional[str] = None   # File with one URL/host per line
    nmap_target: Optional[str] = None   # Explicit nmap target (hostname/IP)


class ExternalToolOrchestrator:
    """
    Top-level orchestrator that coordinates all external tool integrations.

    Tool integrations included:

    * :class:`NucleiScanner`          – template-based vulnerability scanning
    * :class:`ContentDiscoveryScanner` – directory/file brute-forcing
    * :class:`PortScanOrchestrator`   – nmap port + service enumeration
    * :class:`ApplicationAnalyzer`    – nikto + whatweb analysis
    * :class:`ParameterAnalyzer`      – arjun + paramspider parameter discovery

    Usage::

        orc = ExternalToolOrchestrator()
        results = orc.run_all(
            target_url="https://example.com",
            config=ExternalToolScanConfig(run_port_scan=False),
        )
        for finding in results:
            print(f"[{finding.severity.upper()}] {finding.title}")
    """

    def __init__(self) -> None:
        self._nuclei = NucleiScanner()
        self._content = ContentDiscoveryScanner()
        self._ports = PortScanOrchestrator()
        self._app = ApplicationAnalyzer()
        self._params = ParameterAnalyzer()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def available_tools(self) -> Dict[str, bool]:
        """Return a mapping of tool name → availability."""
        return {
            "nuclei": self._nuclei.is_available(),
            "content_discovery": self._content.is_available(),
            "nmap": self._ports.is_available(),
            "application_analysis": self._app.is_available(),
            "parameter_analysis": self._params.is_available(),
        }

    def run_all(
        self,
        target_url: str,
        config: Optional[ExternalToolScanConfig] = None,
    ) -> List[EngineResult]:
        """
        Run all enabled and available external tools against *target_url*.

        Each tool that is not installed is skipped with a warning log; this
        allows the orchestrator to operate gracefully in environments where
        only a subset of tools are available.

        Args:
            target_url: Primary URL / host to scan.
            config:     :class:`ExternalToolScanConfig` instance.  If *None*,
                        a default configuration is used.

        Returns:
            Aggregated list of :class:`EngineResult` findings from all tools.
        """
        cfg = config or ExternalToolScanConfig()
        all_results: List[EngineResult] = []

        # ── Nuclei ────────────────────────────────────────────────────
        if cfg.run_nuclei:
            if self._nuclei.is_available():
                logger.info("ExternalToolOrchestrator: running Nuclei against %s", target_url)
                try:
                    results = self._nuclei.scan(
                        target_url=target_url,
                        target_file=cfg.target_file,
                        tags=cfg.nuclei_tags,
                        severity=cfg.nuclei_severity,
                        rate_limit=cfg.nuclei_rate_limit,
                        timeout=cfg.nuclei_timeout,
                        extra_args=cfg.nuclei_extra_args,
                    )
                    logger.info("Nuclei: %d findings", len(results))
                    all_results.extend(results)
                except Exception as exc:
                    logger.error("Nuclei scan failed: %s", exc)
            else:
                logger.warning("Nuclei not available; skipping.")

        # ── Content Discovery ─────────────────────────────────────────
        if cfg.run_content_discovery:
            if self._content.is_available():
                logger.info("ExternalToolOrchestrator: running content discovery against %s", target_url)
                if os.path.isfile(cfg.wordlist):
                    try:
                        results = self._content.scan(
                            target_url=target_url,
                            wordlist=cfg.wordlist,
                            extensions=cfg.content_extensions,
                            threads=cfg.content_threads,
                            timeout=cfg.content_timeout,
                            extra_args=cfg.content_extra_args,
                        )
                        logger.info("Content discovery: %d paths found", len(results))
                        all_results.extend(results)
                    except Exception as exc:
                        logger.error("Content discovery failed: %s", exc)
                else:
                    logger.warning(
                        "Content discovery wordlist not found (%s); skipping.", cfg.wordlist
                    )
            else:
                logger.warning("No content discovery tool available (ffuf/feroxbuster/gobuster); skipping.")

        # ── Port Scanning ─────────────────────────────────────────────
        if cfg.run_port_scan:
            if self._ports.is_available():
                # Resolve nmap target: prefer explicit setting, fall back to URL hostname
                from urllib.parse import urlparse
                nmap_target = cfg.nmap_target or urlparse(target_url).hostname or target_url
                logger.info("ExternalToolOrchestrator: running nmap against %s", nmap_target)
                try:
                    results = self._ports.scan(
                        target=nmap_target,
                        ports=cfg.port_range,
                        scan_type=cfg.nmap_scan_type,
                        timing=cfg.nmap_timing,
                        scripts=cfg.nmap_scripts,
                        timeout=cfg.nmap_timeout,
                        extra_args=cfg.nmap_extra_args,
                    )
                    logger.info("Port scan: %d open ports found", len(results))
                    all_results.extend(results)
                except Exception as exc:
                    logger.error("Port scan failed: %s", exc)
            else:
                logger.warning("nmap not available; skipping port scan.")

        # ── Application Analysis ──────────────────────────────────────
        if cfg.run_application_analysis:
            if self._app.is_available():
                logger.info("ExternalToolOrchestrator: running application analysis against %s", target_url)
                try:
                    results = self._app.scan(
                        target_url=target_url,
                        run_nikto=cfg.run_nikto,
                        run_whatweb=cfg.run_whatweb,
                        nikto_timeout=cfg.nikto_timeout,
                        whatweb_timeout=cfg.whatweb_timeout,
                        extra_nikto_args=cfg.nikto_extra_args,
                        extra_whatweb_args=cfg.whatweb_extra_args,
                    )
                    logger.info("Application analysis: %d findings", len(results))
                    all_results.extend(results)
                except Exception as exc:
                    logger.error("Application analysis failed: %s", exc)
            else:
                logger.warning("No application analysis tool available (nikto/whatweb); skipping.")

        # ── Parameter Analysis ────────────────────────────────────────
        if cfg.run_parameter_analysis:
            if self._params.is_available():
                logger.info("ExternalToolOrchestrator: running parameter analysis against %s", target_url)
                try:
                    results = self._params.scan(
                        target_url=target_url,
                        run_arjun=cfg.run_arjun,
                        run_paramspider=cfg.run_paramspider,
                        arjun_timeout=cfg.arjun_timeout,
                        paramspider_timeout=cfg.paramspider_timeout,
                        extra_arjun_args=cfg.arjun_extra_args,
                        extra_paramspider_args=cfg.paramspider_extra_args,
                    )
                    logger.info("Parameter analysis: %d findings", len(results))
                    all_results.extend(results)
                except Exception as exc:
                    logger.error("Parameter analysis failed: %s", exc)
            else:
                logger.warning("No parameter analysis tool available (arjun/paramspider); skipping.")

        logger.info(
            "ExternalToolOrchestrator: scan complete – %d total findings", len(all_results)
        )
        return all_results

    async def run_all_async(
        self,
        target_url: str,
        config: Optional[ExternalToolScanConfig] = None,
    ) -> List[EngineResult]:
        """
        Async variant of :meth:`run_all`.

        Nuclei is run asynchronously; other tools currently use the synchronous
        path in a thread pool executor.

        Args:
            target_url: Primary URL / host to scan.
            config:     Scan configuration.

        Returns:
            Aggregated list of :class:`EngineResult` findings.
        """
        cfg = config or ExternalToolScanConfig()
        loop = asyncio.get_event_loop()
        all_results: List[EngineResult] = []

        if cfg.run_nuclei and self._nuclei.is_available():
            try:
                results = await self._nuclei.scan_async(
                    target_url=target_url,
                    target_file=cfg.target_file,
                    tags=cfg.nuclei_tags,
                    severity=cfg.nuclei_severity,
                    rate_limit=cfg.nuclei_rate_limit,
                    timeout=cfg.nuclei_timeout,
                    extra_args=cfg.nuclei_extra_args,
                )
                all_results.extend(results)
            except Exception as exc:
                logger.error("Async Nuclei scan failed: %s", exc)

        # Run remaining tools in a thread pool to avoid blocking the event loop
        import concurrent.futures
        sync_tasks = []
        if cfg.run_content_discovery and self._content.is_available() and os.path.isfile(cfg.wordlist):
            sync_tasks.append(
                lambda: self._content.scan(
                    target_url=target_url,
                    wordlist=cfg.wordlist,
                    extensions=cfg.content_extensions,
                    threads=cfg.content_threads,
                    timeout=cfg.content_timeout,
                    extra_args=cfg.content_extra_args,
                )
            )
        if cfg.run_application_analysis and self._app.is_available():
            sync_tasks.append(
                lambda: self._app.scan(
                    target_url=target_url,
                    run_nikto=cfg.run_nikto,
                    run_whatweb=cfg.run_whatweb,
                    nikto_timeout=cfg.nikto_timeout,
                    whatweb_timeout=cfg.whatweb_timeout,
                    extra_nikto_args=cfg.nikto_extra_args,
                    extra_whatweb_args=cfg.whatweb_extra_args,
                )
            )
        if cfg.run_parameter_analysis and self._params.is_available():
            sync_tasks.append(
                lambda: self._params.scan(
                    target_url=target_url,
                    run_arjun=cfg.run_arjun,
                    run_paramspider=cfg.run_paramspider,
                    arjun_timeout=cfg.arjun_timeout,
                    paramspider_timeout=cfg.paramspider_timeout,
                    extra_arjun_args=cfg.arjun_extra_args,
                    extra_paramspider_args=cfg.paramspider_extra_args,
                )
            )

        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [loop.run_in_executor(executor, task) for task in sync_tasks]
            for future in asyncio.as_completed(futures):
                try:
                    results = await future
                    all_results.extend(results)
                except Exception as exc:
                    logger.error("Async task failed: %s", exc)

        # Port scan last – nmap can be slow
        if cfg.run_port_scan and self._ports.is_available():
            from urllib.parse import urlparse
            nmap_target = cfg.nmap_target or urlparse(target_url).hostname or target_url
            try:
                results = await loop.run_in_executor(
                    None,
                    lambda: self._ports.scan(
                        target=nmap_target,
                        ports=cfg.port_range,
                        scan_type=cfg.nmap_scan_type,
                        timing=cfg.nmap_timing,
                        scripts=cfg.nmap_scripts,
                        timeout=cfg.nmap_timeout,
                        extra_args=cfg.nmap_extra_args,
                    ),
                )
                all_results.extend(results)
            except Exception as exc:
                logger.error("Async port scan failed: %s", exc)

        logger.info(
            "ExternalToolOrchestrator (async): scan complete – %d total findings",
            len(all_results),
        )
        return all_results
