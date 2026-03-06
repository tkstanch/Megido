"""
VPoC Detector Mixin — reusable evidence helper for detection plugins.

All detection plugins can inherit :class:`VPoCDetectorMixin` to gain access
to :meth:`_attach_vpoc`, a single helper that builds and attaches a
:class:`~scanner.scan_plugins.vpoc.VPoCEvidence` object to any
:class:`~scanner.scan_plugins.base_scan_plugin.VulnerabilityFinding`.

Usage example::

    from scanner.scan_plugins.vpoc_mixin import VPoCDetectorMixin
    from scanner.scan_plugins.base_scan_plugin import BaseScanPlugin, VulnerabilityFinding

    class MyDetector(VPoCDetectorMixin, BaseScanPlugin):
        ...
        def _check_something(self, url, response, payload):
            finding = VulnerabilityFinding(
                vulnerability_type='something',
                ...
            )
            self._attach_vpoc(
                finding=finding,
                response=response,
                payload=payload,
                confidence=0.9,
                reproduction_steps='1. Send request\\n2. Observe response',
            )
            return finding
"""

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from scanner.scan_plugins.base_scan_plugin import VulnerabilityFinding
    from scanner.scan_plugins.vpoc import VPoCEvidence


class VPoCDetectorMixin:
    """
    Mixin for detection plugins to easily attach VPoC evidence to findings.

    Inheriting this mixin gives each detector a single, consistent method
    for capturing HTTP request/response evidence and attaching it to a
    :class:`~scanner.scan_plugins.base_scan_plugin.VulnerabilityFinding`.

    Sensitive headers are automatically redacted and large bodies truncated
    before any data is stored.
    """

    def _attach_vpoc(
        self,
        finding: 'VulnerabilityFinding',
        response: Any,
        payload: str,
        confidence: float,
        reproduction_steps: Optional[str] = None,
        redirect_chain: Optional[list] = None,
    ) -> None:
        """
        Build a :class:`~scanner.scan_plugins.vpoc.VPoCEvidence` from *response*
        and attach it to *finding*.

        Parameters
        ----------
        finding : VulnerabilityFinding
            The finding object to enrich with evidence.
        response : requests.Response
            The HTTP response captured during the probe.
        payload : str
            The payload or crafted input that triggered the finding.
        confidence : float
            Confidence score in the range [0.0, 1.0].
        reproduction_steps : str, optional
            Human-readable instructions for reproducing the finding.
        redirect_chain : list of str, optional
            Ordered list of redirect URLs (for redirect-type findings).
        """
        try:
            from scanner.scan_plugins.vpoc import capture_request_response_evidence
            finding.vpoc = capture_request_response_evidence(
                response=response,
                plugin_name=getattr(self, 'plugin_id', self.__class__.__name__),
                payload=payload,
                confidence=confidence,
                target_url=finding.url,
                redirect_chain=redirect_chain,
                reproduction_steps=reproduction_steps,
            )
        except Exception:
            # Evidence capture is best-effort; never fail the detection flow
            pass
