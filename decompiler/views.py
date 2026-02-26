"""
Views for the Browser Extension Decompiler app.
"""
import hashlib
import json
import os
import zipfile
import tempfile
from io import BytesIO

from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.http import JsonResponse, FileResponse, StreamingHttpResponse
from django.core.exceptions import ValidationError
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone

from .models import (
    ExtensionPackage,
    DecompilationJob,
    ObfuscationTechnique,
    DetectedObfuscation,
    ExtensionAnalysis,
    TrafficInterception,
    ExtensionPermission,
    ExtensionManifest,
    VulnerabilityFinding,
    DecompilationArtifact,
)
from .engine import (
    DecompilationEngine,
    ObfuscationDetector,
    CodeAnalyzer,
    TrafficAnalyzer,
    RecompilationEngine,
)
from .config import MAX_UPLOAD_SIZE, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from .utils.file_utils import calculate_checksums, detect_type_from_magic

import ipaddress
import urllib.parse


def _validate_url(url: str) -> bool:
    """
    Validate that a URL is safe to request (no SSRF to internal resources).

    Returns True if the URL is safe, False otherwise.
    """
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        hostname = parsed.hostname
        if not hostname:
            return False
        # Block private/loopback/link-local IP addresses
        try:
            addr = ipaddress.ip_address(hostname)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return False
        except ValueError:
            # Not an IP address — check for localhost/internal hostnames
            blocked = ("localhost", "169.254.", "metadata.google")
            if any(hostname == b or hostname.endswith("." + b) for b in blocked):
                return False
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _paginate(queryset, request, default_size=DEFAULT_PAGE_SIZE):
    try:
        page = max(1, int(request.GET.get("page", 1)))
    except (ValueError, TypeError):
        page = 1
    try:
        page_size = min(MAX_PAGE_SIZE, max(1, int(request.GET.get("page_size", default_size))))
    except (ValueError, TypeError):
        page_size = default_size
    paginator = Paginator(queryset, page_size)
    page_obj = paginator.get_page(page)
    return page_obj, {
        "page": page_obj.number,
        "page_size": page_size,
        "total": paginator.count,
        "total_pages": paginator.num_pages,
        "has_next": page_obj.has_next(),
        "has_previous": page_obj.has_previous(),
    }


_ALLOWED_PACKAGE_SORTS = [
    "name", "-name", "downloaded_at", "-downloaded_at",
    "file_size", "-file_size", "extension_type",
]

@login_required
@csrf_protect
@require_http_methods(["POST"])
def upload_extension_package(request):
    """Upload a browser extension package for analysis."""
    if "file" not in request.FILES:
        return JsonResponse({"error": "No file uploaded"}, status=400)

    uploaded = request.FILES["file"]
    name = request.POST.get("name", uploaded.name)
    download_url = request.POST.get("download_url", "http://localhost/uploaded")

    # File size validation
    if uploaded.size > MAX_UPLOAD_SIZE:
        return JsonResponse(
            {"error": f"File too large. Maximum size is {MAX_UPLOAD_SIZE // (1024*1024)} MB"},
            status=400,
        )

    # Save to temp to read magic bytes and compute checksums
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded.name)[1]) as tmp:
        for chunk in uploaded.chunks():
            tmp.write(chunk)
        tmp_path = tmp.name

    try:
        # Detect type and compute checksums
        ext_type = detect_type_from_magic(tmp_path) or "unknown"
        checksums = calculate_checksums(tmp_path)

        # Map to valid EXTENSION_TYPES choices
        valid_types = [t[0] for t in ExtensionPackage.EXTENSION_TYPES]
        if ext_type not in valid_types:
            ext_type = "unknown"

        # Create the package
        package = ExtensionPackage(
            name=name,
            extension_type=ext_type,
            download_url=download_url,
            downloaded_by=request.user,
            file_size=uploaded.size,
            checksum_md5=checksums.get("md5", ""),
            checksum_sha256=checksums.get("sha256", ""),
            status="downloaded",
        )
        uploaded.seek(0)
        package.bytecode_file.save(uploaded.name, uploaded, save=False)
        package.save()

        return JsonResponse({
            "success": True,
            "package_id": str(package.package_id),
            "name": package.name,
            "extension_type": package.extension_type,
            "file_size": package.file_size,
            "checksum_md5": package.checksum_md5,
            "checksum_sha256": package.checksum_sha256,
        }, status=201)
    except Exception as exc:
        return JsonResponse({"error": str(exc)}, status=500)
    finally:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass


@login_required
@require_http_methods(["GET"])
def list_extension_packages(request):
    """List extension packages with filtering and pagination."""
    qs = ExtensionPackage.objects.all()

    ext_type = request.GET.get("extension_type")
    if ext_type:
        qs = qs.filter(extension_type=ext_type)

    status = request.GET.get("status")
    if status:
        qs = qs.filter(status=status)

    search = request.GET.get("search")
    if search:
        qs = qs.filter(Q(name__icontains=search) | Q(download_url__icontains=search))

    sort = request.GET.get("sort", "-downloaded_at")
    if sort in _ALLOWED_PACKAGE_SORTS:
        qs = qs.order_by(sort)

    page_obj, pagination = _paginate(qs, request)
    data = []
    for pkg in page_obj:
        data.append({
            "package_id": str(pkg.package_id),
            "name": pkg.name,
            "extension_type": pkg.extension_type,
            "file_size": pkg.file_size,
            "status": pkg.status,
            "downloaded_at": pkg.downloaded_at.isoformat(),
            "checksum_sha256": pkg.checksum_sha256,
        })
    return JsonResponse({"packages": data, "pagination": pagination})


@login_required
@require_http_methods(["GET"])
def get_extension_package(request, package_id):
    """Get details of a specific extension package."""
    package = get_object_or_404(ExtensionPackage, package_id=package_id)
    jobs = list(
        package.decompilation_jobs.values(
            "job_id", "status", "created_at", "decompiler_tool"
        )
    )
    for job in jobs:
        job["job_id"] = str(job["job_id"])
        job["created_at"] = job["created_at"].isoformat()

    result = {
        "package_id": str(package.package_id),
        "name": package.name,
        "extension_type": package.extension_type,
        "download_url": package.download_url,
        "downloaded_at": package.downloaded_at.isoformat(),
        "file_size": package.file_size,
        "checksum_md5": package.checksum_md5,
        "checksum_sha256": package.checksum_sha256,
        "version": package.version,
        "status": package.status,
        "notes": package.notes,
        "decompilation_jobs": jobs,
    }
    return JsonResponse(result)


@login_required
@require_http_methods(["GET"])
def download_extension_bytecode(request, package_id):
    """Download the original bytecode file for an extension package."""
    package = get_object_or_404(ExtensionPackage, package_id=package_id)
    if not package.bytecode_file:
        return JsonResponse({"error": "No bytecode file available"}, status=404)
    response = FileResponse(
        package.bytecode_file.open("rb"),
        as_attachment=True,
        filename=os.path.basename(package.bytecode_file.name),
    )
    return response


# ---------------------------------------------------------------------------
# Decompilation Workflow
# ---------------------------------------------------------------------------

@login_required
@csrf_protect
@require_http_methods(["POST"])
def start_decompilation_job(request):
    """Start a new decompilation job for an extension package."""
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    package_id = body.get("package_id")
    if not package_id:
        return JsonResponse({"error": "package_id is required"}, status=400)

    package = get_object_or_404(ExtensionPackage, package_id=package_id)

    # Select decompiler tool based on extension type
    tool_map = {
        "java_applet": "cfr",
        "flash": "jpexs",
        "silverlight": "ilspy",
        "chrome_crx": "builtin",
        "firefox_xpi": "builtin",
        "webextension": "builtin",
        "electron_asar": "builtin",
        "wasm": "wasm-tools",
        "userscript": "builtin",
        "javascript": "jsbeautifier",
        "browser_addon": "builtin",
    }
    decompiler_tool = body.get("decompiler_tool") or tool_map.get(package.extension_type, "builtin")

    job = DecompilationJob.objects.create(
        extension_package=package,
        status="in_progress",
        created_by=request.user,
        decompiler_tool=decompiler_tool,
        options=body.get("options", {}),
        started_at=timezone.now(),
    )

    # Run decompilation synchronously
    engine = DecompilationEngine()
    if not package.bytecode_file:
        job.status = "failed"
        job.error_message = "No bytecode file available"
        job.completed_at = timezone.now()
        job.save()
        return JsonResponse({"error": "No bytecode file on the package"}, status=400)

    output_dir = tempfile.mkdtemp(prefix=f"decompile_{job.job_id}_")
    try:
        result = engine.decompile(
            package.bytecode_file.path,
            output_dir,
            extension_type=package.extension_type,
            options=body.get("options"),
        )
        job.num_classes_found = result.get("num_classes", result.get("num_js_files", 0))
        job.num_methods_found = result.get("num_methods", 0)
        job.log_output = result.get("log", "")

        if result.get("success"):
            job.status = "completed"
            # Save artifacts
            _save_artifacts(job, output_dir)
        else:
            job.status = "failed"
            job.error_message = result.get("error", "Unknown error")
    except Exception as exc:
        job.status = "failed"
        job.error_message = str(exc)
    finally:
        job.completed_at = timezone.now()
        job.save()

    package.status = "analyzed" if job.status == "completed" else "failed"
    package.save(update_fields=["status"])

    return JsonResponse({
        "job_id": str(job.job_id),
        "status": job.status,
        "decompiler_tool": job.decompiler_tool,
        "num_classes": job.num_classes_found,
        "error": job.error_message if job.status == "failed" else None,
    }, status=201)


def _save_artifacts(job, output_dir):
    """Save decompiled files as DecompilationArtifact records."""
    ext_to_lang = {
        ".java": "java", ".py": "python", ".js": "javascript",
        ".ts": "typescript", ".cs": "csharp", ".as": "actionscript",
        ".wat": "wasm", ".html": "html", ".css": "css",
        ".json": "json", ".xml": "xml",
    }
    for root, _, files in os.walk(output_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, output_dir)
            ext = os.path.splitext(fname)[1].lower()
            lang = ext_to_lang.get(ext, "")
            try:
                fsize = os.path.getsize(fpath)
                artifact_type = "source" if lang else "resource"
                if fname in ("manifest.json", "install.rdf", "AppManifest.xaml"):
                    artifact_type = "manifest"
                elif ext == ".json":
                    artifact_type = "config"

                content = ""
                if fsize < 500_000 and ext in ext_to_lang:
                    try:
                        content = open(fpath, encoding="utf-8", errors="replace").read()
                    except Exception:
                        pass

                DecompilationArtifact.objects.get_or_create(
                    decompilation_job=job,
                    file_path=rel_path,
                    defaults={
                        "artifact_type": artifact_type,
                        "file_size": fsize,
                        "language": lang,
                        "content": content[:50000],  # cap at 50KB
                    },
                )
            except Exception:
                pass


@login_required
@require_http_methods(["GET"])
def get_decompilation_job_status(request, job_id):
    """Get the status of a decompilation job."""
    job = get_object_or_404(DecompilationJob, job_id=job_id)
    result = {
        "job_id": str(job.job_id),
        "status": job.status,
        "decompiler_tool": job.decompiler_tool,
        "decompiler_version": job.decompiler_version,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "completed_at": job.completed_at.isoformat() if job.completed_at else None,
        "num_classes_found": job.num_classes_found,
        "num_methods_found": job.num_methods_found,
        "obfuscation_detected": job.obfuscation_detected,
        "error_message": job.error_message,
        "package_id": str(job.extension_package.package_id),
    }
    if job.completed_at and job.started_at:
        duration = (job.completed_at - job.started_at).total_seconds()
        result["duration_seconds"] = duration
    return JsonResponse(result)


@login_required
@require_http_methods(["GET"])
def download_decompiled_source(request, job_id):
    """Download a ZIP archive of the decompiled source code."""
    job = get_object_or_404(DecompilationJob, job_id=job_id)
    artifacts = job.artifacts.filter(artifact_type__in=["source", "config", "manifest"])
    if not artifacts.exists():
        return JsonResponse({"error": "No decompiled source available for this job"}, status=404)

    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for artifact in artifacts:
            if artifact.content:
                zf.writestr(artifact.file_path, artifact.content)
    buffer.seek(0)

    response = StreamingHttpResponse(
        buffer,
        content_type="application/zip",
    )
    response["Content-Disposition"] = f'attachment; filename="decompiled_{job_id}.zip"'
    return response


@login_required
@require_http_methods(["GET"])
def view_decompiled_source(request, job_id):
    """View decompiled source code in a web interface."""
    job = get_object_or_404(DecompilationJob, job_id=job_id)
    artifacts = job.artifacts.order_by("file_path")

    # Build file tree
    file_tree = []
    for artifact in artifacts:
        file_tree.append({
            "path": artifact.file_path,
            "type": artifact.artifact_type,
            "language": artifact.language,
            "size": artifact.file_size,
        })

    selected_path = request.GET.get("file")
    selected_content = ""
    selected_language = ""
    if selected_path:
        try:
            artifact = artifacts.get(file_path=selected_path)
            selected_content = artifact.content or ""
            selected_language = artifact.language or "text"
        except DecompilationArtifact.DoesNotExist:
            pass

    return render(request, "decompiler/source_viewer.html", {
        "job": job,
        "package": job.extension_package,
        "file_tree": file_tree,
        "selected_file": selected_path,
        "selected_content": selected_content,
        "selected_language": selected_language,
    })


# ---------------------------------------------------------------------------
# Analysis and Recompilation
# ---------------------------------------------------------------------------

@login_required
@csrf_protect
@require_http_methods(["POST"])
def analyze_decompiled_code(request):
    """Perform automated analysis on decompiled source code."""
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    job_id = body.get("job_id")
    if not job_id:
        return JsonResponse({"error": "job_id is required"}, status=400)

    job = get_object_or_404(DecompilationJob, job_id=job_id)

    # Collect all decompiled source text
    artifacts = job.artifacts.filter(artifact_type="source")
    combined_source = "\n".join(a.content for a in artifacts if a.content)

    analyzer = CodeAnalyzer()
    detector = ObfuscationDetector()

    api_endpoints = analyzer.extract_api_endpoints(combined_source)
    network_requests = analyzer.extract_network_requests(combined_source)
    data_flows = analyzer.analyze_data_flows(combined_source)
    vulnerabilities = analyzer.find_vulnerabilities(combined_source)
    js_hooks = analyzer.find_javascript_hooks(combined_source)
    malicious = analyzer.detect_malicious_patterns(combined_source)
    secrets = analyzer.extract_secrets(combined_source)
    obfuscation = detector.generate_obfuscation_report(combined_source)

    # Determine risk level
    risk_level = "low"
    if secrets or any(v["severity"] == "critical" for v in vulnerabilities):
        risk_level = "critical"
    elif malicious or any(v["severity"] == "high" for v in vulnerabilities):
        risk_level = "high"
    elif vulnerabilities:
        risk_level = "medium"

    # Create or update ExtensionAnalysis
    analysis, _ = ExtensionAnalysis.objects.update_or_create(
        decompilation_job=job,
        defaults={
            "analyzed_by": request.user,
            "api_endpoints": api_endpoints,
            "network_requests": network_requests,
            "data_flows": data_flows,
            "vulnerabilities": vulnerabilities + malicious,
            "privacy_concerns": [f for f in data_flows if "cookie" in f["type"]
                                  or "storage" in f["type"]],
            "javascript_hooks": js_hooks,
            "risk_level": risk_level,
            "summary": (
                f"Found {len(api_endpoints)} API endpoints, "
                f"{len(vulnerabilities)} vulnerabilities, "
                f"{len(secrets)} secrets, "
                f"obfuscation score {obfuscation['overall_obfuscation_score']:.2f}"
            ),
        },
    )

    # Create VulnerabilityFinding records
    for vuln in vulnerabilities:
        VulnerabilityFinding.objects.get_or_create(
            analysis=analysis,
            title=vuln["type"].replace("_", " ").title(),
            defaults={
                "description": f"Pattern: {vuln['type']}",
                "severity": vuln["severity"],
                "evidence": vuln.get("sample", ""),
            },
        )

    # Update job obfuscation flag
    if obfuscation["techniques_detected"] > 0:
        job.obfuscation_detected = True
        job.save(update_fields=["obfuscation_detected"])

    return JsonResponse({
        "analysis_id": str(analysis.analysis_id),
        "risk_level": risk_level,
        "api_endpoints_count": len(api_endpoints),
        "vulnerabilities_count": len(vulnerabilities),
        "secrets_count": len(secrets),
        "obfuscation_score": obfuscation["overall_obfuscation_score"],
    }, status=201)


@login_required
@require_http_methods(["GET"])
def get_analysis_results(request, analysis_id):
    """Get detailed analysis results."""
    analysis = get_object_or_404(ExtensionAnalysis, analysis_id=analysis_id)
    findings = list(analysis.vulnerability_findings.values(
        "finding_id", "title", "severity", "cvss_score",
        "cwe_id", "file_path", "line_number", "evidence", "recommendation",
    ))
    for f in findings:
        f["finding_id"] = str(f["finding_id"])

    return JsonResponse({
        "analysis_id": str(analysis.analysis_id),
        "risk_level": analysis.risk_level,
        "analyzed_at": analysis.analyzed_at.isoformat(),
        "api_endpoints": analysis.api_endpoints,
        "network_requests": analysis.network_requests,
        "data_flows": analysis.data_flows,
        "vulnerabilities": analysis.vulnerabilities,
        "privacy_concerns": analysis.privacy_concerns,
        "javascript_hooks": analysis.javascript_hooks,
        "dom_elements": analysis.dom_elements,
        "summary": analysis.summary,
        "recommendations": analysis.recommendations,
        "vulnerability_findings": findings,
    })


@login_required
@csrf_protect
@require_http_methods(["POST"])
def recompile_and_execute(request):
    """Recompile modified source code."""
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    job_id = body.get("job_id")
    if not job_id:
        return JsonResponse({"error": "job_id is required"}, status=400)

    job = get_object_or_404(DecompilationJob, job_id=job_id)
    package = job.extension_package

    engine = RecompilationEngine()
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Write source files
        artifacts = job.artifacts.filter(artifact_type="source")
        for artifact in artifacts:
            if artifact.content:
                out_path = os.path.join(tmp_dir, artifact.file_path)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as fh:
                    fh.write(artifact.content)

        output_path = os.path.join(tmp_dir, "recompiled_output")
        if package.extension_type == "java_applet":
            result = engine.recompile_java(tmp_dir, output_path + ".jar")
        elif package.extension_type == "flash":
            result = engine.recompile_actionscript(tmp_dir, output_path + ".swf")
        elif package.extension_type == "silverlight":
            result = engine.recompile_csharp(tmp_dir, output_path + ".xap")
        elif package.extension_type in ("chrome_crx", "webextension", "browser_addon"):
            result = engine.repackage_chrome_extension(tmp_dir, output_path + ".zip")
        elif package.extension_type == "firefox_xpi":
            result = engine.repackage_firefox_extension(tmp_dir, output_path + ".xpi")
        else:
            return JsonResponse(
                {"error": f"Recompilation not supported for {package.extension_type}"},
                status=400,
            )

        return JsonResponse({
            "success": result.get("success", False),
            "error": result.get("error"),
            "log": result.get("log", ""),
            "note": result.get("note", ""),
        })


# ---------------------------------------------------------------------------
# JavaScript Manipulation
# ---------------------------------------------------------------------------

@login_required
@csrf_protect
@require_http_methods(["POST"])
def inject_javascript_hook(request):
    """Inject JavaScript hooks to manipulate extension components."""
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    job_id = body.get("job_id")
    target_file = body.get("target_file")
    hook_code = body.get("hook_code")
    injection_point = body.get("injection_point", "end")

    if not all([job_id, target_file, hook_code]):
        return JsonResponse(
            {"error": "job_id, target_file, and hook_code are required"}, status=400
        )

    job = get_object_or_404(DecompilationJob, job_id=job_id)
    engine = RecompilationEngine()

    with tempfile.TemporaryDirectory() as tmp_dir:
        # Write the target artifact
        try:
            artifact = job.artifacts.get(file_path=target_file)
        except DecompilationArtifact.DoesNotExist:
            return JsonResponse({"error": f"File not found: {target_file}"}, status=404)

        out_path = os.path.join(tmp_dir, target_file)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(artifact.content or "")

        result = engine.inject_payload(tmp_dir, target_file, hook_code, injection_point)
        if result.get("success"):
            # Update the artifact content
            with open(out_path, encoding="utf-8", errors="replace") as fh:
                artifact.content = fh.read()
            artifact.save(update_fields=["content"])

        return JsonResponse(result)


@login_required
@require_http_methods(["GET"])
def list_javascript_hooks(request):
    """List available JavaScript hooks for an extension."""
    job_id = request.GET.get("job_id")
    if not job_id:
        return JsonResponse({"error": "job_id is required"}, status=400)

    job = get_object_or_404(DecompilationJob, job_id=job_id)
    artifacts = job.artifacts.filter(language="javascript")
    combined = "\n".join(a.content for a in artifacts if a.content)

    analyzer = CodeAnalyzer()
    hooks = analyzer.find_javascript_hooks(combined)
    return JsonResponse({"hooks": hooks, "count": len(hooks)})


# ---------------------------------------------------------------------------
# Obfuscation
# ---------------------------------------------------------------------------

@login_required
@require_http_methods(["GET"])
def list_obfuscation_techniques(request):
    """List known obfuscation techniques."""
    qs = ObfuscationTechnique.objects.all()
    obf_type = request.GET.get("obfuscation_type")
    if obf_type:
        qs = qs.filter(obfuscation_type=obf_type)
    severity = request.GET.get("severity")
    if severity:
        try:
            qs = qs.filter(severity=int(severity))
        except ValueError:
            pass

    page_obj, pagination = _paginate(qs, request)
    data = []
    for t in page_obj:
        data.append({
            "technique_id": str(t.technique_id),
            "name": t.name,
            "obfuscation_type": t.obfuscation_type,
            "description": t.description,
            "severity": t.severity,
            "common_tools": t.common_tools,
        })
    return JsonResponse({"techniques": data, "pagination": pagination})


@login_required
@csrf_protect
@require_http_methods(["POST"])
def detect_obfuscation(request):
    """Detect obfuscation techniques in decompiled code."""
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    job_id = body.get("job_id")
    if not job_id:
        return JsonResponse({"error": "job_id is required"}, status=400)

    job = get_object_or_404(DecompilationJob, job_id=job_id)
    artifacts = job.artifacts.filter(artifact_type="source")
    combined = "\n".join(a.content for a in artifacts if a.content)

    if not combined:
        return JsonResponse({"error": "No source code available for analysis"}, status=400)

    detector = ObfuscationDetector()
    report = detector.generate_obfuscation_report(combined)

    # Store detected obfuscations
    stored = []
    for finding in report["findings"]:
        technique_name = finding["technique"].replace("_", " ").title()
        technique, _ = ObfuscationTechnique.objects.get_or_create(
            name=technique_name,
            defaults={
                "obfuscation_type": finding["technique"] if finding["technique"] in
                                    [t[0] for t in ObfuscationTechnique.OBFUSCATION_TYPES]
                                    else "other",
                "description": f"Detected: {finding['evidence']}",
                "severity": max(1, min(10, int(finding["confidence"] * 10))),
            },
        )
        try:
            detection, _ = DetectedObfuscation.objects.get_or_create(
                decompilation_job=job,
                obfuscation_technique=technique,
                location="combined_source",
                defaults={
                    "confidence_score": finding["confidence"],
                    "evidence": finding["evidence"],
                },
            )
            stored.append(str(detection.detection_id))
        except Exception:
            pass

    # Update job flag
    if report["techniques_detected"] > 0:
        job.obfuscation_detected = True
        job.save(update_fields=["obfuscation_detected"])

    return JsonResponse({
        "overall_obfuscation_score": report["overall_obfuscation_score"],
        "techniques_detected": report["techniques_detected"],
        "findings": report["findings"],
        "detection_ids": stored,
    })


@login_required
@csrf_protect
@require_http_methods(["POST"])
def deobfuscate_code(request):
    """Attempt to deobfuscate detected obfuscation."""
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    detection_id = body.get("detection_id")
    if not detection_id:
        return JsonResponse({"error": "detection_id is required"}, status=400)

    detection = get_object_or_404(DetectedObfuscation, detection_id=detection_id)
    obf_type = detection.obfuscation_technique.obfuscation_type

    # Basic deobfuscation strategies
    result_notes = []
    if obf_type in ("name_mangling",):
        result_notes.append("Rename-based deobfuscation requires manual analysis or tools like de4js.")
    elif obf_type in ("string_encryption", "packing"):
        result_notes.append(
            "String/packing deobfuscation: try running the code in a sandboxed environment "
            "or use de4js / deobfuscate.io."
        )
    elif obf_type in ("control_flow",):
        result_notes.append("Control flow deobfuscation: use synchrony or similar tools.")
    else:
        result_notes.append("No automated deobfuscation strategy available for this technique.")

    detection.deobfuscated = True
    detection.deobfuscation_success = False
    detection.save(update_fields=["deobfuscated", "deobfuscation_success"])

    return JsonResponse({
        "detection_id": str(detection.detection_id),
        "technique": detection.obfuscation_technique.name,
        "deobfuscation_notes": result_notes,
        "automated_success": False,
    })


# ---------------------------------------------------------------------------
# Traffic Interception
# ---------------------------------------------------------------------------

@login_required
@require_http_methods(["GET"])
def list_intercepted_traffic(request):
    """List intercepted browser extension traffic."""
    qs = TrafficInterception.objects.all()

    package_id = request.GET.get("extension_package")
    if package_id:
        qs = qs.filter(extension_package__package_id=package_id)

    protocol = request.GET.get("protocol")
    if protocol:
        qs = qs.filter(protocol=protocol)

    start_date = request.GET.get("start_date")
    if start_date:
        qs = qs.filter(timestamp__gte=start_date)

    end_date = request.GET.get("end_date")
    if end_date:
        qs = qs.filter(timestamp__lte=end_date)

    page_obj, pagination = _paginate(qs, request)
    data = []
    for t in page_obj:
        data.append({
            "interception_id": str(t.interception_id),
            "protocol": t.protocol,
            "request_url": t.request_url,
            "request_method": t.request_method,
            "response_status": t.response_status,
            "timestamp": t.timestamp.isoformat(),
            "is_serialized": t.is_serialized,
        })
    return JsonResponse({"traffic": data, "pagination": pagination})


@login_required
@csrf_protect
@require_http_methods(["POST"])
def capture_traffic(request):
    """Record a manually submitted traffic interception entry."""
    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    request_url = body.get("request_url")
    if not request_url:
        return JsonResponse({"error": "request_url is required"}, status=400)

    package_id = body.get("extension_package_id")
    package = None
    if package_id:
        try:
            package = ExtensionPackage.objects.get(package_id=package_id)
        except ExtensionPackage.DoesNotExist:
            pass

    traffic = TrafficInterception.objects.create(
        extension_package=package,
        protocol=body.get("protocol", "http"),
        request_url=request_url,
        request_method=body.get("request_method", "GET").upper(),
        request_headers=body.get("request_headers", {}),
        response_status=body.get("response_status"),
        response_headers=body.get("response_headers", {}),
        notes=body.get("notes", ""),
    )
    return JsonResponse({
        "interception_id": str(traffic.interception_id),
        "protocol": traffic.protocol,
        "request_url": traffic.request_url,
    }, status=201)


@login_required
@require_http_methods(["GET"])
def view_traffic_details(request, interception_id):
    """View detailed information about intercepted traffic."""
    traffic = get_object_or_404(TrafficInterception, interception_id=interception_id)
    analyzer = TrafficAnalyzer()

    parsed = {}
    if traffic.request_body:
        raw = bytes(traffic.request_body)
        protocol = analyzer.identify_protocol(raw)
        if protocol == "java_serialization":
            parsed["request_parsed"] = analyzer.parse_java_serialization(raw)
        elif protocol == "amf":
            parsed["request_parsed"] = analyzer.parse_amf(raw)
        elif protocol == "json":
            try:
                parsed["request_parsed"] = json.loads(raw)
            except Exception:
                pass
        parsed["request_protocol"] = protocol
        parsed["request_hex"] = raw[:256].hex()

    return JsonResponse({
        "interception_id": str(traffic.interception_id),
        "protocol": traffic.protocol,
        "request_url": traffic.request_url,
        "request_method": traffic.request_method,
        "request_headers": traffic.request_headers,
        "response_status": traffic.response_status,
        "response_headers": traffic.response_headers,
        "is_serialized": traffic.is_serialized,
        "serialization_format": traffic.serialization_format,
        "deserialized_data": traffic.deserialized_data,
        "timestamp": traffic.timestamp.isoformat(),
        "parsed": parsed,
    })


@login_required
@csrf_protect
@require_http_methods(["POST"])
def replay_traffic(request):
    """Replay intercepted traffic, optionally with modifications."""
    import requests as req_lib

    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    interception_id = body.get("interception_id")
    if not interception_id:
        return JsonResponse({"error": "interception_id is required"}, status=400)

    traffic = get_object_or_404(TrafficInterception, interception_id=interception_id)

    # Apply optional modifications
    url = body.get("url", traffic.request_url)
    if not _validate_url(url):
        return JsonResponse({"error": "URL is not allowed (blocked or invalid)"}, status=400)
    method = body.get("method", traffic.request_method).upper()
    headers = {**traffic.request_headers, **body.get("headers", {})}
    data = body.get("body")
    if data is None and traffic.request_body:
        try:
            data = bytes(traffic.request_body).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            data = None

    try:
        resp = req_lib.request(method, url, headers=headers, data=data, timeout=30)
        return JsonResponse({
            "success": True,
            "status_code": resp.status_code,
            "response_headers": dict(resp.headers),
            "response_body": resp.text[:10000],
            "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
        })
    except req_lib.RequestException as exc:
        return JsonResponse({"success": False, "error": str(exc)})


# ---------------------------------------------------------------------------
# Web App Interaction
# ---------------------------------------------------------------------------

@login_required
@csrf_protect
@require_http_methods(["POST"])
def interact_with_webapp(request):
    """Programmatically interact with target web app via analysis findings."""
    import requests as req_lib

    try:
        body = json.loads(request.body)
    except (json.JSONDecodeError, TypeError):
        return JsonResponse({"error": "Invalid JSON body"}, status=400)

    analysis_id = body.get("analysis_id")
    if not analysis_id:
        return JsonResponse({"error": "analysis_id is required"}, status=400)

    analysis = get_object_or_404(ExtensionAnalysis, analysis_id=analysis_id)
    interaction_type = body.get("interaction_type", "api_call")
    interaction_data = body.get("interaction_data", {})

    if interaction_type == "api_call":
        url = interaction_data.get("url")
        if not url:
            # Pick first discovered API endpoint
            endpoints = analysis.api_endpoints
            if not endpoints:
                return JsonResponse({"error": "No API endpoints discovered"}, status=400)
            url = endpoints[0].get("url", "")

        if not _validate_url(url):
            return JsonResponse({"error": "URL is not allowed (blocked or invalid)"}, status=400)
        method = interaction_data.get("method", "GET").upper()
        headers = interaction_data.get("headers", {})
        payload = interaction_data.get("body")
        try:
            resp = req_lib.request(method, url, headers=headers, json=payload, timeout=30)
            return JsonResponse({
                "success": True,
                "url": url,
                "status_code": resp.status_code,
                "response": resp.text[:5000],
            })
        except req_lib.RequestException as exc:
            return JsonResponse({"success": False, "error": str(exc)})

    return JsonResponse({"error": f"Unsupported interaction type: {interaction_type}"}, status=400)


# ---------------------------------------------------------------------------
# Home / Dashboard
# ---------------------------------------------------------------------------

@login_required
def decompiler_home(request):
    """Home page/dashboard for the Decompiler app."""
    total_packages = ExtensionPackage.objects.count()
    jobs_by_status = dict(
        DecompilationJob.objects.values("status").annotate(count=Count("job_id"))
        .values_list("status", "count")
    )
    total_analyses = ExtensionAnalysis.objects.count()
    recent_packages = ExtensionPackage.objects.order_by("-downloaded_at")[:5]
    recent_jobs = DecompilationJob.objects.select_related("extension_package").order_by(
        "-created_at"
    )[:5]

    return render(request, "decompiler/home.html", {
        "title": "Browser Extension Decompiler",
        "description": "Analyze and decompile browser extensions for security research",
        "total_packages": total_packages,
        "jobs_by_status": jobs_by_status,
        "total_analyses": total_analyses,
        "recent_packages": recent_packages,
        "recent_jobs": recent_jobs,
    })
