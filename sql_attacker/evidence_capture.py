"""
Visual Evidence Capture Module for SQL Attacker

Captures screenshots, generates animated GIFs, and maintains an evidence
timeline during SQL injection attack execution.

Selenium is optional – the module degrades gracefully if it is not available
or if a compatible browser/driver cannot be found.
"""

import logging
import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Optional dependency – fail gracefully if not installed / no browser available
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service as ChromeService
    from selenium.common.exceptions import WebDriverException
    SELENIUM_AVAILABLE = True
except ImportError:
    SELENIUM_AVAILABLE = False
    WebDriverException = Exception

# Optional dependency – fail gracefully if not installed
try:
    import imageio
    IMAGEIO_AVAILABLE = True
except ImportError:
    IMAGEIO_AVAILABLE = False

# Optional dependency
try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False


class VisualEvidenceCapture:
    """
    Captures visual evidence (screenshots, animated GIFs) during SQL injection
    attack execution and maintains a timestamped evidence timeline.
    """

    def __init__(self, evidence_dir: Optional[str] = None):
        """
        Args:
            evidence_dir: Directory where captured files will be stored.
                          Falls back to a temporary directory if not provided.
        """
        self.evidence_dir = evidence_dir or tempfile.mkdtemp(prefix="sqli_evidence_")
        os.makedirs(self.evidence_dir, exist_ok=True)

        self.driver = None
        self.screenshots: List[str] = []
        self.timeline: List[Dict[str, Any]] = []
        self._browser_available = False

    # ------------------------------------------------------------------
    # Browser lifecycle
    # ------------------------------------------------------------------

    def initialize_browser(self, headless: bool = True) -> bool:
        """
        Set up a Selenium WebDriver instance.

        Returns:
            True if the browser was initialised successfully, False otherwise.
        """
        if not SELENIUM_AVAILABLE:
            logger.warning("Selenium is not installed – visual capture disabled")
            return False

        try:
            options = ChromeOptions()
            if headless:
                options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument("--disable-gpu")
            options.add_argument("--window-size=1280,720")

            self.driver = webdriver.Chrome(options=options)
            self._browser_available = True
            logger.info("Headless browser initialised for visual evidence capture")
            return True
        except WebDriverException as exc:
            logger.warning("Could not initialise browser for visual capture: %s", exc)
            self._browser_available = False
            return False
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unexpected error initialising browser: %s", exc)
            self._browser_available = False
            return False

    def cleanup(self) -> None:
        """Close the browser and release resources."""
        if self.driver:
            try:
                self.driver.quit()
            except Exception:  # noqa: BLE001
                pass
            finally:
                self.driver = None
        self._browser_available = False

    # ------------------------------------------------------------------
    # Screenshot capture helpers
    # ------------------------------------------------------------------

    def _save_screenshot(self, label: str) -> Optional[str]:
        """
        Capture a screenshot from the current browser state and save it.

        Returns the file path on success, or None if capture is unavailable.
        """
        if not self._browser_available or not self.driver:
            return None

        try:
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
            filename = f"{label}_{timestamp}.png"
            filepath = os.path.join(self.evidence_dir, filename)
            self.driver.save_screenshot(filepath)
            self.screenshots.append(filepath)
            logger.debug("Screenshot saved: %s", filepath)
            return filepath
        except Exception as exc:  # noqa: BLE001
            logger.warning("Screenshot capture failed: %s", exc)
            return None

    def _add_timeline_entry(
        self,
        step: str,
        description: str,
        screenshot: Optional[str] = None,
        payload: Optional[str] = None,
    ) -> None:
        """Append an entry to the evidence timeline."""
        self.timeline.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "step": step,
                "description": description,
                "screenshot": screenshot,
                "payload": payload,
            }
        )

    # ------------------------------------------------------------------
    # Public capture methods
    # ------------------------------------------------------------------

    def capture_baseline_screenshot(self, url: str, params: Dict) -> Optional[str]:
        """
        Load the target URL with normal parameters and capture a baseline screenshot.
        """
        if not self._browser_available:
            self._add_timeline_entry(
                "baseline",
                f"Baseline request to {url} (no browser available)",
            )
            return None

        try:
            # Build a simple query string for the GET request
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qs
            parsed = urlparse(url)
            existing_qs = parse_qs(parsed.query)
            merged = {k: v[0] for k, v in existing_qs.items()}
            merged.update(params)
            new_query = urlencode(merged)
            target = urlunparse(parsed._replace(query=new_query))

            self.driver.get(target)
            time.sleep(1)  # allow page to settle
            path = self._save_screenshot("baseline")
            self._add_timeline_entry(
                "baseline",
                f"Baseline screenshot of {url}",
                screenshot=path,
            )
            return path
        except Exception as exc:  # noqa: BLE001
            logger.warning("Baseline screenshot failed: %s", exc)
            return None

    def capture_injection_screenshot(
        self,
        url: str,
        params: Dict,
        payload: str,
        injection_type: str,
    ) -> Optional[str]:
        """
        Navigate to the URL with an injected payload and capture a screenshot.
        """
        if not self._browser_available:
            self._add_timeline_entry(
                "injection",
                f"Injection attempt on {url} [{injection_type}] (no browser)",
                payload=payload,
            )
            return None

        try:
            from urllib.parse import urlencode, urlparse, urlunparse
            parsed = urlparse(url)
            injected_params = dict(params)
            # Inject into the first parameter as a simple demonstration
            if injected_params:
                first_key = next(iter(injected_params))
                injected_params[first_key] = payload
            new_query = urlencode(injected_params)
            target = urlunparse(parsed._replace(query=new_query))

            self.driver.get(target)
            time.sleep(1)
            path = self._save_screenshot(f"injection_{injection_type}")
            self._add_timeline_entry(
                "injection",
                f"Injection attempt [{injection_type}] on {url}",
                screenshot=path,
                payload=payload,
            )
            return path
        except Exception as exc:  # noqa: BLE001
            logger.warning("Injection screenshot failed: %s", exc)
            return None

    def capture_exploitation_screenshot(
        self,
        url: str,
        params: Dict,
        extracted_data: Dict,
    ) -> Optional[str]:
        """
        Capture a screenshot demonstrating successful data extraction.
        """
        if not self._browser_available:
            self._add_timeline_entry(
                "exploitation",
                f"Data extraction on {url} (no browser)",
            )
            return None

        try:
            self.driver.get(url)
            time.sleep(1)
            path = self._save_screenshot("exploitation")
            self._add_timeline_entry(
                "exploitation",
                f"Exploitation result – extracted {len(extracted_data)} data categories",
                screenshot=path,
            )
            return path
        except Exception as exc:  # noqa: BLE001
            logger.warning("Exploitation screenshot failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # GIF generation
    # ------------------------------------------------------------------

    def generate_gif_from_screenshots(self, duration: float = 0.8) -> Optional[str]:
        """
        Create an animated GIF from the captured screenshots.

        Args:
            duration: Seconds each frame is displayed.

        Returns:
            Path to the generated GIF, or None if generation failed.
        """
        if not self.screenshots:
            logger.debug("No screenshots available for GIF generation")
            return None

        if not IMAGEIO_AVAILABLE:
            logger.warning("imageio is not installed – GIF generation disabled")
            return None

        if not PILLOW_AVAILABLE:
            logger.warning("Pillow is not installed – GIF generation disabled")
            return None

        try:
            gif_path = os.path.join(self.evidence_dir, "attack_animation.gif")
            frames = []
            for screenshot_path in self.screenshots:
                if os.path.exists(screenshot_path):
                    img = Image.open(screenshot_path).convert("RGB")
                    # Resize to a consistent size to avoid GIF dimension errors
                    img = img.resize((1280, 720), Image.LANCZOS)
                    frames.append(img)

            if frames:
                imageio.mimsave(gif_path, frames, duration=duration, loop=0)
                logger.info("Animated GIF generated: %s", gif_path)
                return gif_path
        except Exception as exc:  # noqa: BLE001
            logger.warning("GIF generation failed: %s", exc)

        return None

    # ------------------------------------------------------------------
    # Evidence package
    # ------------------------------------------------------------------

    def get_evidence_package(self) -> Dict[str, Any]:
        """
        Return a complete evidence bundle including screenshot paths, GIF path,
        and the attack timeline.
        """
        gif_path = self.generate_gif_from_screenshots()
        return {
            "screenshots": list(self.screenshots),
            "gif": gif_path,
            "timeline": list(self.timeline),
        }
