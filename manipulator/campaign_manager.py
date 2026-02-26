"""
Campaign Manager - Orchestrates the complete attack campaign workflow.
Ties together discovery -> variant generation -> injection -> analysis -> PoC.
"""
import logging
import threading
from typing import Callable, Dict, List, Optional
from django.utils import timezone

logger = logging.getLogger(__name__)


class CampaignManager:
    """
    Orchestrates a complete automated attack campaign.
    """

    def __init__(self, campaign_id: int,
                 on_status_update: Optional[Callable] = None,
                 on_result: Optional[Callable] = None):
        self.campaign_id = campaign_id
        self.on_status_update = on_status_update
        self.on_result = on_result
        self._thread = None
        self._stop_event = threading.Event()

    def _get_campaign(self):
        from .models import AttackCampaign
        return AttackCampaign.objects.get(id=self.campaign_id)

    def _update_status(self, status: str, **kwargs):
        """Update campaign status in the database."""
        from .models import AttackCampaign
        try:
            campaign = AttackCampaign.objects.get(id=self.campaign_id)
            campaign.status = status
            for key, val in kwargs.items():
                setattr(campaign, key, val)
            campaign.save()
            if self.on_status_update:
                self.on_status_update(status)
        except Exception as e:
            logger.error(f"Failed to update campaign status: {e}")

    def _run_campaign(self):
        """Main campaign execution logic."""
        from .models import AttackCampaign, DiscoveredInjectionPoint, InjectionResult, Payload
        from .injection_discovery import InjectionPointDiscovery
        from .variant_generator import PayloadVariantGenerator
        from .auto_injector import AutoInjector

        try:
            campaign = self._get_campaign()

            # Phase 1: Crawl and discover injection points
            self._update_status('crawling', started_at=timezone.now())

            discovery = InjectionPointDiscovery(
                target_url=campaign.target_url,
                max_depth=campaign.max_depth,
                custom_headers=campaign.custom_headers,
                auth_cookies=campaign.authentication,
                include_headers=campaign.include_headers,
                include_cookies=campaign.include_cookies,
            )

            discovered_points = discovery.discover()

            if self._stop_event.is_set():
                self._update_status('paused')
                return

            # Save discovered injection points
            saved_points = []
            for point_data in discovered_points:
                try:
                    ip = DiscoveredInjectionPoint.objects.create(
                        campaign=campaign,
                        url=point_data['url'][:2000],
                        parameter_name=point_data['parameter_name'][:500],
                        parameter_type=point_data['parameter_type'],
                        injection_location=point_data.get('injection_location', '')[:200],
                        original_value=point_data.get('original_value', ''),
                        form_action=point_data.get('form_action', '')[:2000],
                        form_method=point_data.get('form_method', '')[:10],
                    )
                    saved_points.append((ip, point_data))
                except Exception as e:
                    logger.warning(f"Failed to save injection point: {e}")

            campaign.total_injection_points = len(saved_points)
            campaign.save(update_fields=['total_injection_points'])

            if not saved_points:
                self._update_status('completed', completed_at=timezone.now())
                return

            # Phase 2: Generate payload variants
            self._update_status('injecting')

            variant_gen = PayloadVariantGenerator(level=campaign.manipulation_level)

            base_payloads = []

            if campaign.use_builtin_payloads:
                vuln_filter = campaign.vuln_types_to_test
                if vuln_filter:
                    qs = Payload.objects.filter(vulnerability__name__in=vuln_filter)
                else:
                    qs = Payload.objects.all()
                base_payloads.extend(list(qs.values_list('payload_text', flat=True)[:200]))

            if campaign.use_custom_payloads and campaign.custom_payload_text:
                from .payload_learner import PayloadLearner
                learner = PayloadLearner()
                custom = learner.parse_payload_list(campaign.custom_payload_text)
                base_payloads.extend(custom)

            all_payloads = []
            seen = set()
            for base in base_payloads[:50]:
                variants = variant_gen.generate_all(base)
                for v in variants:
                    if v not in seen:
                        seen.add(v)
                        all_payloads.append(v)

            if not all_payloads:
                self._update_status('completed', completed_at=timezone.now())
                return

            # Phase 3: Run injections
            injector = AutoInjector(
                concurrency=campaign.concurrency,
                custom_headers=campaign.custom_headers,
                auth_cookies=campaign.authentication,
                follow_redirects=campaign.follow_redirects,
            )

            total_requests = 0
            total_tested = 0
            successful = 0

            for ip_obj, ip_data in saved_points:
                if self._stop_event.is_set():
                    self._update_status('paused')
                    return

                results = injector.test_injection_point(ip_data, all_payloads)
                total_requests += injector._request_count
                injector._request_count = 0
                total_tested += len(all_payloads)

                for result in results:
                    self._save_result(result, campaign, ip_obj)
                    if result.get('is_successful'):
                        successful += 1
                        if self.on_result:
                            self.on_result(result)

            campaign.refresh_from_db()
            campaign.total_payloads_tested = total_tested
            campaign.total_requests_sent = total_requests
            campaign.successful_exploits = successful
            campaign.save(update_fields=['total_payloads_tested', 'total_requests_sent', 'successful_exploits'])

            self._update_status('completed', completed_at=timezone.now())

        except Exception as e:
            logger.error(f"Campaign {self.campaign_id} failed: {e}", exc_info=True)
            self._update_status('failed')

    def _save_result(self, result: Dict, campaign, ip_obj) -> None:
        """Persist a single injection result to the database."""
        from .models import InjectionResult
        try:
            InjectionResult.objects.create(
                campaign=campaign,
                injection_point=ip_obj,
                payload_text=result.get('payload_text', '')[:2000],
                manipulations_applied=result.get('manipulations_applied', []),
                encodings_applied=result.get('encodings_applied', []),
                request_method=result.get('request_method', 'GET')[:10],
                request_url=result.get('request_url', '')[:2000],
                request_headers=result.get('request_headers', {}),
                request_body=result.get('request_body', ''),
                response_status=result.get('response_status'),
                response_headers=result.get('response_headers', {}),
                response_body=result.get('response_body', ''),
                response_time_ms=result.get('response_time_ms'),
                is_successful=result.get('is_successful', False),
                vulnerability_type=result.get('vulnerability_type', '')[:100],
                detection_method=result.get('detection_method', '')[:100],
                confidence=result.get('confidence', 0.0),
                evidence=result.get('evidence', ''),
                poc_curl_command=result.get('poc_curl_command', ''),
                poc_python_script=result.get('poc_python_script', ''),
                poc_report=result.get('poc_report', ''),
                severity=result.get('severity', 'info'),
            )
        except Exception as e:
            logger.warning(f"Failed to save result: {e}")

    def start(self):
        """Start the campaign in a background thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_campaign, daemon=True)
        self._thread.start()

    def pause(self):
        """Signal the campaign to pause."""
        self._stop_event.set()

    def is_running(self) -> bool:
        """Check if the campaign is still running."""
        return self._thread is not None and self._thread.is_alive()
