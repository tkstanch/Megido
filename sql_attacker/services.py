"""
SQL Attacker service layer.

Contains the business logic for executing SQL injection tasks.  Both the Celery
task workers (``tasks.py``) and the Django views (``views.py``) delegate to
these functions so that workers never need to import Django view code.
"""

import logging
import os

from django.utils import timezone

from .models import SQLInjectionTask, SQLInjectionResult
from .sqli_engine import SQLInjectionEngine
from .param_discovery import ParameterDiscoveryEngine
from .oob_payloads import OOBPayloadGenerator, DatabaseType as OOBDatabaseType
from response_analyser.analyse import save_vulnerability

logger = logging.getLogger(__name__)

# Maximum length for OOB payload strings stored in the database.
_OOB_PAYLOAD_MAX_STORE_LENGTH = 200


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _get_default_data_to_exfiltrate(db_type):
    """Return the default SQL expression to exfiltrate for a given OOB DB type."""
    DEFAULT_EXFIL_EXPRESSIONS = {
        OOBDatabaseType.MSSQL: '@@version',
        OOBDatabaseType.ORACLE: 'user',
        OOBDatabaseType.MYSQL: '@@version',
    }
    if db_type is None:
        return 'user'
    return DEFAULT_EXFIL_EXPRESSIONS.get(db_type, 'user')


def _map_visual_evidence_to_fields(visual_evidence: dict) -> dict:
    """
    Map a visual_evidence package to SQLInjectionResult model field values.

    Only intended to be applied to *verified* (exploited) results.
    """
    screenshots = visual_evidence.get('screenshots', []) or []
    gif_path = visual_evidence.get('gif')
    timeline = visual_evidence.get('timeline', []) or []

    fields: dict = {
        'screenshots': screenshots or None,
        'evidence_timeline': timeline or None,
    }

    if gif_path:
        fields['gif_evidence'] = gif_path
        fields['visual_proof_path'] = gif_path
        fields['visual_proof_type'] = 'gif'
        try:
            fields['visual_proof_size'] = os.path.getsize(gif_path)
        except OSError:
            pass
    elif screenshots:
        primary = screenshots[0]
        fields['visual_proof_path'] = primary
        fields['visual_proof_type'] = 'screenshot'
        try:
            fields['visual_proof_size'] = os.path.getsize(primary)
        except OSError:
            pass

    return fields


def _db_type_to_oob_db_type(db_type_str: str):
    """Map a database type string to an OOBDatabaseType enum value, or None."""
    mapping = {
        'mysql': OOBDatabaseType.MYSQL,
        'mariadb': OOBDatabaseType.MYSQL,
        'mssql': OOBDatabaseType.MSSQL,
        'sqlserver': OOBDatabaseType.MSSQL,
        'oracle': OOBDatabaseType.ORACLE,
    }
    return mapping.get((db_type_str or '').lower().strip())


def forward_to_response_analyser(task, result):
    """Forward SQL injection findings to response_analyser app."""

    class MockResponse:
        def __init__(self, response_data):
            self.status_code = response_data.get('status_code', 200)
            self.headers = {}
            self.text = response_data.get('body_snippet', '')

    response_data = result.response_data or {}
    mock_response = MockResponse(response_data)
    request_data = result.request_data or {}

    notes = f"""SQL Injection detected via sql_attacker app.

Injection Type: {result.get_injection_type_display()}
Vulnerable Parameter: {result.vulnerable_parameter} ({result.parameter_type})
Test Payload: {result.test_payload}
Detection Evidence: {result.detection_evidence}

Database Type: {result.database_type}
"""

    if result.is_exploitable:
        notes += "\nExploitation Results:\n"
        if result.database_version:
            notes += f"- Database Version: {result.database_version}\n"
        if result.current_database:
            notes += f"- Current Database: {result.current_database}\n"
        if result.current_user:
            notes += f"- Current User: {result.current_user}\n"
        if result.extracted_tables:
            notes += f"- Extracted Tables: {', '.join(result.extracted_tables)}\n"

    save_vulnerability(
        attack_type='sqli',
        target_url=task.target_url,
        payload=result.test_payload,
        response=mock_response,
        severity='critical',
        request_method=task.http_method,
        request_headers=task.get_headers_dict(),
        request_params=request_data,
        notes=notes,
    )


# ---------------------------------------------------------------------------
# Public service functions
# ---------------------------------------------------------------------------

def execute_task(task_id: int) -> None:
    """
    Execute a SQL injection attack task.

    Sets ``status='running'`` / ``started_at`` before beginning, then sets
    ``status='completed'`` / ``completed_at`` on success, or
    ``status='failed'`` / ``error_message`` / ``completed_at`` on failure.
    """
    try:
        task = SQLInjectionTask.objects.get(id=task_id)
        task.status = 'running'
        task.started_at = timezone.now()
        task.save()

        # Configure engine with advanced features enabled
        config = {
            'use_random_delays': task.use_random_delays,
            'min_delay': task.min_delay,
            'max_delay': task.max_delay,
            'randomize_user_agent': task.randomize_user_agent,
            'use_payload_obfuscation': task.use_payload_obfuscation,
            'verify_ssl': False,
            'enable_advanced_payloads': True,
            'enable_false_positive_reduction': True,
            'enable_impact_demonstration': True,
            'enable_stealth': True,
            'max_requests_per_minute': task.max_requests_per_minute,
            'enable_jitter': task.enable_jitter,
            'randomize_headers': task.randomize_headers,
            'max_retries': task.max_retries,
        }

        engine = SQLInjectionEngine(config)

        params = task.get_params_dict()
        data = task.get_post_dict()
        cookies = task.get_cookies_dict()
        headers = task.get_headers_dict()

        # Automatic parameter discovery
        discovered_params_list = []
        if task.auto_discover_params:
            try:
                logger.info(f"Starting parameter discovery for {task.target_url}")
                discovery_engine = ParameterDiscoveryEngine(
                    timeout=30,
                    verify_ssl=False,
                )

                merged_params, discovered_params_list = discovery_engine.discover_parameters(
                    url=task.target_url,
                    method=task.http_method,
                    headers=headers,
                )

                task.discovered_params = [p.to_dict() for p in discovered_params_list]
                task.save()

                if task.require_confirmation and discovered_params_list:
                    logger.info(
                        f"Pausing for confirmation - discovered {len(discovered_params_list)} parameters"
                    )
                    task.status = 'awaiting_confirmation'
                    task.awaiting_confirmation = True
                    task.save()
                    return

                if merged_params.get('GET'):
                    for param_name, param_value in merged_params['GET'].items():
                        if param_name not in params:
                            params[param_name] = param_value

                if merged_params.get('POST'):
                    for param_name, param_value in merged_params['POST'].items():
                        if param_name not in data:
                            data[param_name] = param_value

                logger.info(
                    f"Discovered {len(discovered_params_list)} parameters. "
                    f"Total GET params: {len(params)}, Total POST params: {len(data)}"
                )

            except Exception as e:
                logger.error(f"Parameter discovery failed: {e}", exc_info=True)

        merged_params_dict = {**params, **data}

        evidence_result = engine.execute_attack_with_evidence(
            task=task,
            params_to_test=merged_params_dict,
            enable_visual_capture=True,
        )
        findings = evidence_result.get('_raw_findings', [])
        visual_evidence = evidence_result.get('visual_evidence', {})
        all_injection_points = evidence_result.get('all_injection_points', [])
        successful_payloads = evidence_result.get('successful_payloads', {})
        extracted_sensitive_data = evidence_result.get('extracted_sensitive_data', {})

        vulnerabilities_count = 0
        oob_payloads_generated = 0
        for finding in findings:
            exploitation = finding.pop('exploitation', {})
            impact_analysis = finding.pop('impact_analysis', {})

            param_name = finding.get('vulnerable_parameter', 'unknown')
            param_method = finding.get('parameter_type', 'GET')
            parameter_source = 'manual'

            for discovered_param in discovered_params_list:
                if (
                    discovered_param.name == param_name
                    and discovered_param.method == param_method
                ):
                    parameter_source = discovered_param.source
                    break

            severity = finding.get('severity', impact_analysis.get('severity', 'critical'))
            risk_score = finding.get('risk_score', impact_analysis.get('risk_score', 50))
            confidence_score = finding.get('confidence_score', 0.7)

            is_exploitable = exploitation.get('is_exploitable', False) or impact_analysis.get('exploitable', False)
            verified = bool(is_exploitable)

            create_kwargs = dict(
                task=task,
                injection_type=finding.get('injection_type', 'error_based'),
                vulnerable_parameter=param_name,
                parameter_type=param_method,
                parameter_source=parameter_source,
                test_payload=finding.get('test_payload', ''),
                detection_evidence=finding.get('detection_evidence', ''),
                request_data=finding.get('request_data', {}),
                response_data=finding.get('response_data', {}),
                is_exploitable=is_exploitable,
                verified=verified,
                database_type=finding.get('database_type', 'unknown'),
                database_version=exploitation.get('database_version', '') or impact_analysis.get('extracted_info', {}).get('database_version', ''),
                current_database=exploitation.get('current_database', '') or impact_analysis.get('extracted_info', {}).get('current_database', ''),
                current_user=exploitation.get('current_user', '') or impact_analysis.get('extracted_info', {}).get('database_user', ''),
                extracted_tables=exploitation.get('extracted_tables', []) or impact_analysis.get('extracted_info', {}).get('schema', {}).get('tables', []),
                extracted_data=exploitation.get('extracted_data', {}) or impact_analysis.get('extracted_info', {}).get('sample_data', []),
                severity=severity,
                confidence_score=confidence_score,
                risk_score=risk_score,
                impact_analysis=impact_analysis,
                proof_of_concept=impact_analysis.get('proof_of_concept', []),
                all_injection_points=all_injection_points or None,
                successful_payloads=successful_payloads or None,
                extracted_sensitive_data=extracted_sensitive_data or None,
            )

            if verified:
                create_kwargs.update(_map_visual_evidence_to_fields(visual_evidence))

            result = SQLInjectionResult.objects.create(**create_kwargs)
            vulnerabilities_count += 1

            if task.enable_oob and oob_payloads_generated < task.oob_max_payloads:
                try:
                    oob_db_type = _db_type_to_oob_db_type(finding.get('database_type', ''))
                    exfil_expr = (
                        task.oob_exfil_expression.strip()
                        or _get_default_data_to_exfiltrate(oob_db_type)
                    )
                    oob_host = task.oob_attacker_host.strip() or 'ATTACKER_HOST_PLACEHOLDER'
                    oob_gen = OOBPayloadGenerator(attacker_host=oob_host, attacker_port=80)
                    raw_payloads = oob_gen.generate_all_payloads(oob_db_type, exfil_expr)
                    slots_remaining = task.oob_max_payloads - oob_payloads_generated
                    oob_findings_list = []
                    for _db, pl_list in raw_payloads.items():
                        for pl in pl_list[:slots_remaining]:
                            oob_findings_list.append({
                                'technique': pl.technique.value,
                                'payload': pl.payload[:_OOB_PAYLOAD_MAX_STORE_LENGTH],
                                'listener_type': pl.listener_type,
                                'requires_privileges': pl.requires_privileges,
                                'privilege_level': pl.privilege_level,
                                'description': pl.description[:_OOB_PAYLOAD_MAX_STORE_LENGTH],
                            })
                            oob_payloads_generated += 1
                            if oob_payloads_generated >= task.oob_max_payloads:
                                break
                        if oob_payloads_generated >= task.oob_max_payloads:
                            break
                    if oob_findings_list:
                        result.oob_findings = oob_findings_list
                        result.save(update_fields=['oob_findings'])
                except Exception as oob_exc:
                    logger.warning(
                        "OOB payload generation failed for result %s: %s", result.id, oob_exc
                    )

            if (
                result.injection_type == 'union_based'
                and result.is_exploitable
                and result.extracted_data
            ):
                try:
                    from .union_sql_injection import UnionSQLInjectionAttacker
                    db_info = {}
                    if result.database_version:
                        db_info['Database Version'] = result.database_version
                    if result.current_database:
                        db_info['Current Database'] = result.current_database
                    if result.current_user:
                        db_info['Database User'] = result.current_user
                    extracted = result.extracted_data
                    if isinstance(extracted, list) and extracted and isinstance(extracted[0], dict):
                        table_name = (
                            result.extracted_tables[0]
                            if isinstance(result.extracted_tables, list) and result.extracted_tables
                            else 'Unknown'
                        )
                        poc_html = UnionSQLInjectionAttacker.generate_html_evidence_table(
                            extracted_data=extracted,
                            table_name=table_name,
                            db_info=db_info if db_info else None,
                        )
                        result.union_poc_html = poc_html
                        result.save(update_fields=['union_poc_html'])
                except Exception as exc:
                    logger.warning(
                        "Could not generate union PoC HTML for result %s: %s", result.id, exc
                    )

            try:
                forward_to_response_analyser(task, result)
            except Exception as e:
                logger.error(f"Error forwarding to response_analyser: {e}", exc_info=True)

        task.status = 'completed'
        task.completed_at = timezone.now()
        task.vulnerabilities_found = vulnerabilities_count
        task.save()

    except Exception as e:
        logger.error(f"Task {task_id} failed: {e}", exc_info=True)
        try:
            task = SQLInjectionTask.objects.get(id=task_id)
        except SQLInjectionTask.DoesNotExist:
            logger.error(f"SQLInjectionTask {task_id} not found when recording failure")
            return
        task.status = 'failed'
        task.error_message = str(e)
        task.completed_at = timezone.now()
        task.save()


def execute_task_with_selection(task_id: int) -> None:
    """
    Execute a SQL injection task using only the manually selected parameters.

    Delegates to :func:`execute_task` after reconstructing the parameter list
    from ``task.selected_params``.
    """
    try:
        task = SQLInjectionTask.objects.get(id=task_id)
        task.status = 'running'
        task.started_at = timezone.now()
        task.save()

        execute_task(task_id)

    except Exception as e:
        logger.error(f"Error executing task with selection {task_id}: {e}", exc_info=True)
        try:
            task = SQLInjectionTask.objects.get(id=task_id)
        except SQLInjectionTask.DoesNotExist:
            logger.error(f"SQLInjectionTask {task_id} not found when recording failure")
            return
        task.status = 'failed'
        task.error_message = str(e)
        task.completed_at = timezone.now()
        task.save()
