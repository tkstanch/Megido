"""
Visual Proof of Exploitation Capture Module

This module provides automated visual proof generation for all vulnerability types.
After successful exploitation, it captures screenshots or GIFs to demonstrate the
real impact of the vulnerability in the dashboard.

Features:
- Screenshot capture for static proofs
- Animated GIF for dynamic exploits
- Automatic file size optimization (<10MB)
- Support for all vulnerability types
- Integration with exploit plugins

Security Features:
- URL sanitization and validation
- File size limits (max 10MB)
- Proper error handling
- Temporary file cleanup
- Secure file naming

Dependencies:
- playwright or selenium for browser automation
- Pillow (PIL) for image processing
"""

import os
import re
import logging
import hashlib
import time
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import urlparse
import io

logger = logging.getLogger(__name__)

# Dependency status logging - thread-safe
_dependencies_lock = threading.Lock()
_DEPENDENCIES_LOGGED = False

def _log_dependencies_status():
    """Log the status of visual proof dependencies once (thread-safe)."""
    global _DEPENDENCIES_LOGGED
    with _dependencies_lock:
        if not _DEPENDENCIES_LOGGED:
            if not HAS_PLAYWRIGHT and not HAS_SELENIUM:
                logger.warning(
                    "Visual proof capture requires Playwright or Selenium for browser automation.\n"
                    "Install with: pip install playwright (preferred) or pip install selenium\n"
                    "For Playwright, also run: playwright install chromium"
                )
            if not HAS_PIL:
                logger.warning(
                    "Visual proof capture requires Pillow for image processing.\n"
                    "Install with: pip install Pillow"
                )
            _DEPENDENCIES_LOGGED = True

# Try to import Playwright (preferred)
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False
    logger.warning("Playwright not available. Install with: pip install playwright")

# Fallback to Selenium
try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.common.exceptions import TimeoutException, WebDriverException
    HAS_SELENIUM = True
except ImportError:
    HAS_SELENIUM = False
    logger.warning("Selenium not available. Install with: pip install selenium")

# Image processing
try:
    from PIL import Image, ImageDraw, ImageFont
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    logger.warning("PIL/Pillow not available. Install with: pip install Pillow")


class VisualProofCapture:
    """
    Automated visual proof generator for vulnerability exploits.
    
    Captures browser interaction with exploited vulnerabilities
    and generates screenshots or animated GIFs as proof.
    """
    
    # Security constraints
    MAX_DURATION_SECONDS = 5  # Maximum recording duration
    MAX_FILE_SIZE_MB = 10  # Maximum file size
    MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
    SCREENSHOT_INTERVAL = 0.5  # Seconds between screenshots
    MAX_SCREENSHOTS = 10  # Maximum number of screenshots
    COMPRESSION_QUALITY = 85  # Image compression quality (1-100)
    
    # URL validation regex
    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    def __init__(self, output_dir: str = 'media/exploit_proofs'):
        """
        Initialize the visual proof capture module.
        
        Args:
            output_dir: Directory to save proof files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Check dependencies
        if not HAS_PIL:
            raise ImportError(
                "PIL/Pillow is required for image processing. "
                "Install with: pip install Pillow"
            )
        
        if not HAS_PLAYWRIGHT and not HAS_SELENIUM:
            raise ImportError(
                "Either Playwright or Selenium is required for browser automation. "
                "Install with: pip install playwright or pip install selenium"
            )
    
    def sanitize_url(self, url: str) -> bool:
        """
        Validate and sanitize URL for security.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid and safe
        """
        if not url or not isinstance(url, str):
            return False
        
        # Basic pattern check
        if not self.URL_PATTERN.match(url):
            return False
        
        # Additional checks
        try:
            parsed = urlparse(url)
            # Ensure scheme is http/https
            if parsed.scheme not in ['http', 'https']:
                return False
            return True
        except Exception:
            return False
    
    def generate_filename(self, vuln_type: str, vuln_id: int, 
                         file_type: str = 'png') -> str:
        """
        Generate secure filename for visual proof.
        
        Args:
            vuln_type: Type of vulnerability (e.g., 'xss', 'sqli')
            vuln_id: Vulnerability ID
            file_type: File extension (png, gif, mp4)
            
        Returns:
            Safe filename
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        # Create hash for uniqueness
        hash_input = f"{vuln_type}_{vuln_id}_{timestamp}"
        hash_str = hashlib.md5(hash_input.encode()).hexdigest()[:8]
        
        return f"{vuln_type}_{vuln_id}_{hash_str}_{timestamp}.{file_type}"
    
    def capture_screenshot(self, url: str, wait_time: float = 2.0,
                          viewport_size: Tuple[int, int] = (1280, 720)) -> Optional[bytes]:
        """
        Capture a single screenshot of the URL.
        
        Args:
            url: URL to capture
            wait_time: Time to wait before capturing (seconds)
            viewport_size: Browser viewport size (width, height)
            
        Returns:
            Screenshot bytes or None on failure
        """
        if not self.sanitize_url(url):
            logger.error(f"Invalid URL: {url}")
            return None
        
        try:
            if HAS_PLAYWRIGHT:
                return self._capture_screenshot_playwright(url, wait_time, viewport_size)
            elif HAS_SELENIUM:
                return self._capture_screenshot_selenium(url, wait_time, viewport_size)
            else:
                logger.error("No browser automation library available")
                return None
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
            return None
    
    def _capture_screenshot_playwright(self, url: str, wait_time: float,
                                      viewport_size: Tuple[int, int]) -> Optional[bytes]:
        """Capture screenshot using Playwright."""
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={'width': viewport_size[0], 'height': viewport_size[1]},
                    ignore_https_errors=True
                )
                page = context.new_page()
                page.set_default_timeout(5000)
                
                logger.info(f"Navigating to {url}")
                page.goto(url, wait_until='domcontentloaded')
                
                # Wait for specified time
                time.sleep(wait_time)
                
                # Capture screenshot
                screenshot_bytes = page.screenshot(full_page=False)
                
                browser.close()
                logger.info("Screenshot captured successfully")
                return screenshot_bytes
                
        except PlaywrightTimeoutError as e:
            logger.warning(f"Playwright timeout: {e}")
            return None
        except Exception as e:
            logger.error(f"Playwright capture error: {e}")
            return None
    
    def _capture_screenshot_selenium(self, url: str, wait_time: float,
                                    viewport_size: Tuple[int, int]) -> Optional[bytes]:
        """Capture screenshot using Selenium."""
        driver = None
        try:
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument(f'--window-size={viewport_size[0]},{viewport_size[1]}')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(5)
            
            logger.info(f"Navigating to {url}")
            driver.get(url)
            
            # Wait for specified time
            time.sleep(wait_time)
            
            # Capture screenshot
            screenshot_bytes = driver.get_screenshot_as_png()
            
            logger.info("Screenshot captured successfully")
            return screenshot_bytes
            
        except (TimeoutException, WebDriverException) as e:
            logger.warning(f"Selenium error: {e}")
            return None
        except Exception as e:
            logger.error(f"Selenium capture error: {e}")
            return None
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
    
    def capture_gif(self, url: str, duration: float = 3.0,
                   viewport_size: Tuple[int, int] = (1280, 720)) -> Optional[List[bytes]]:
        """
        Capture multiple screenshots for GIF creation.
        
        Args:
            url: URL to capture
            duration: Capture duration in seconds
            viewport_size: Browser viewport size
            
        Returns:
            List of screenshot bytes or None on failure
        """
        if not self.sanitize_url(url):
            logger.error(f"Invalid URL: {url}")
            return None
        
        # Limit duration for security
        duration = min(duration, self.MAX_DURATION_SECONDS)
        
        try:
            if HAS_PLAYWRIGHT:
                return self._capture_gif_playwright(url, duration, viewport_size)
            elif HAS_SELENIUM:
                return self._capture_gif_selenium(url, duration, viewport_size)
            else:
                logger.error("No browser automation library available")
                return None
        except Exception as e:
            logger.error(f"GIF capture failed: {e}")
            return None
    
    def _capture_gif_playwright(self, url: str, duration: float,
                               viewport_size: Tuple[int, int]) -> List[bytes]:
        """Capture multiple screenshots using Playwright."""
        screenshots = []
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={'width': viewport_size[0], 'height': viewport_size[1]},
                    ignore_https_errors=True
                )
                page = context.new_page()
                page.set_default_timeout(5000)
                
                logger.info(f"Navigating to {url}")
                page.goto(url, wait_until='domcontentloaded')
                
                # Capture screenshots at intervals
                start_time = time.time()
                screenshot_count = 0
                
                while (time.time() - start_time) < duration and screenshot_count < self.MAX_SCREENSHOTS:
                    screenshot_bytes = page.screenshot(full_page=False)
                    screenshots.append(screenshot_bytes)
                    screenshot_count += 1
                    
                    logger.debug(f"Captured screenshot {screenshot_count}/{self.MAX_SCREENSHOTS}")
                    time.sleep(self.SCREENSHOT_INTERVAL)
                
                browser.close()
                logger.info(f"Captured {len(screenshots)} screenshots")
                return screenshots
                
        except PlaywrightTimeoutError as e:
            logger.warning(f"Playwright timeout: {e}")
            return screenshots
        except Exception as e:
            logger.error(f"Playwright GIF capture error: {e}")
            return screenshots
    
    def _capture_gif_selenium(self, url: str, duration: float,
                            viewport_size: Tuple[int, int]) -> List[bytes]:
        """Capture multiple screenshots using Selenium."""
        screenshots = []
        driver = None
        try:
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument(f'--window-size={viewport_size[0]},{viewport_size[1]}')
            
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(5)
            
            logger.info(f"Navigating to {url}")
            driver.get(url)
            
            # Capture screenshots at intervals
            start_time = time.time()
            screenshot_count = 0
            
            while (time.time() - start_time) < duration and screenshot_count < self.MAX_SCREENSHOTS:
                screenshot_bytes = driver.get_screenshot_as_png()
                screenshots.append(screenshot_bytes)
                screenshot_count += 1
                
                logger.debug(f"Captured screenshot {screenshot_count}/{self.MAX_SCREENSHOTS}")
                time.sleep(self.SCREENSHOT_INTERVAL)
            
            logger.info(f"Captured {len(screenshots)} screenshots")
            return screenshots
            
        except (TimeoutException, WebDriverException) as e:
            logger.warning(f"Selenium error: {e}")
            return screenshots
        except Exception as e:
            logger.error(f"Selenium GIF capture error: {e}")
            return screenshots
        finally:
            if driver:
                try:
                    driver.quit()
                except Exception:
                    pass
    
    def create_gif(self, screenshots: List[bytes], output_path: Path,
                   duration_per_frame: int = 500) -> bool:
        """
        Create an animated GIF from screenshots.
        
        Args:
            screenshots: List of screenshot bytes
            output_path: Path to save GIF
            duration_per_frame: Milliseconds per frame
            
        Returns:
            True if successful
        """
        if not screenshots:
            logger.error("No screenshots to create GIF")
            return False
        
        try:
            # Convert bytes to PIL Images
            images = []
            for screenshot_bytes in screenshots:
                img = Image.open(io.BytesIO(screenshot_bytes))
                # Convert to RGB if necessary
                if img.mode != 'RGB':
                    img = img.convert('RGB')
                images.append(img)
            
            if not images:
                logger.error("No valid images for GIF")
                return False
            
            # Save as GIF
            images[0].save(
                output_path,
                save_all=True,
                append_images=images[1:],
                duration=duration_per_frame,
                loop=0,
                optimize=True
            )
            
            # Check file size
            file_size = output_path.stat().st_size
            if file_size > self.MAX_FILE_SIZE_BYTES:
                logger.warning(f"GIF size ({file_size} bytes) exceeds limit, optimizing...")
                return self._optimize_gif(output_path)
            
            logger.info(f"GIF created: {output_path} ({file_size} bytes)")
            return True
            
        except Exception as e:
            logger.error(f"GIF creation failed: {e}")
            return False
    
    def _optimize_gif(self, gif_path: Path) -> bool:
        """
        Optimize GIF file size.
        
        Args:
            gif_path: Path to GIF file
            
        Returns:
            True if optimization successful
        """
        try:
            # Open GIF
            gif = Image.open(gif_path)
            
            # Reduce colors
            frames = []
            try:
                while True:
                    # Convert to palette mode with fewer colors
                    frame = gif.copy().convert('RGB').convert('P', palette=Image.ADAPTIVE, colors=128)
                    frames.append(frame)
                    gif.seek(gif.tell() + 1)
            except EOFError:
                pass
            
            if not frames:
                return False
            
            # Save optimized GIF
            frames[0].save(
                gif_path,
                save_all=True,
                append_images=frames[1:],
                duration=gif.info.get('duration', 500),
                loop=0,
                optimize=True
            )
            
            # Check if still too large
            file_size = gif_path.stat().st_size
            if file_size > self.MAX_FILE_SIZE_BYTES:
                # Further reduce by removing frames
                logger.warning("Still too large, reducing frames...")
                reduced_frames = frames[::2]  # Take every other frame
                if reduced_frames:
                    reduced_frames[0].save(
                        gif_path,
                        save_all=True,
                        append_images=reduced_frames[1:],
                        duration=gif.info.get('duration', 500) * 2,
                        loop=0,
                        optimize=True
                    )
                    file_size = gif_path.stat().st_size
            
            logger.info(f"Optimized GIF size: {file_size} bytes")
            return file_size <= self.MAX_FILE_SIZE_BYTES
            
        except Exception as e:
            logger.error(f"GIF optimization failed: {e}")
            return False
    
    def optimize_image(self, image_bytes: bytes) -> bytes:
        """
        Optimize image file size while maintaining quality.
        
        Args:
            image_bytes: Original image bytes
            
        Returns:
            Optimized image bytes
        """
        try:
            img = Image.open(io.BytesIO(image_bytes))
            
            # Convert to RGB if necessary
            if img.mode not in ['RGB', 'RGBA']:
                img = img.convert('RGB')
            
            # Compress image
            output = io.BytesIO()
            img.save(output, format='PNG', optimize=True, quality=self.COMPRESSION_QUALITY)
            optimized_bytes = output.getvalue()
            
            # If still too large, reduce dimensions
            if len(optimized_bytes) > self.MAX_FILE_SIZE_BYTES:
                scale_factor = 0.8
                new_size = (int(img.width * scale_factor), int(img.height * scale_factor))
                img = img.resize(new_size, Image.LANCZOS)
                
                output = io.BytesIO()
                img.save(output, format='PNG', optimize=True, quality=self.COMPRESSION_QUALITY)
                optimized_bytes = output.getvalue()
            
            return optimized_bytes
            
        except Exception as e:
            logger.error(f"Image optimization failed: {e}")
            return image_bytes
    
    def capture_exploit_proof(self, vuln_type: str, vuln_id: int, url: str,
                             capture_type: str = 'screenshot',
                             duration: float = 3.0) -> Optional[Dict[str, Any]]:
        """
        Capture visual proof of exploitation.
        
        Args:
            vuln_type: Type of vulnerability
            vuln_id: Vulnerability ID
            url: Exploited URL
            capture_type: 'screenshot' or 'gif'
            duration: Capture duration for GIFs
            
        Returns:
            Dict with proof details or None on failure
        """
        if not self.sanitize_url(url):
            logger.error(f"Invalid URL for visual proof: {url}")
            return None
        
        try:
            if capture_type == 'screenshot':
                # Capture single screenshot
                screenshot_bytes = self.capture_screenshot(url)
                if not screenshot_bytes:
                    return None
                
                # Optimize
                optimized_bytes = self.optimize_image(screenshot_bytes)
                
                # Save to file
                filename = self.generate_filename(vuln_type, vuln_id, 'png')
                file_path = self.output_dir / filename
                file_path.write_bytes(optimized_bytes)
                
                file_size = len(optimized_bytes)
                logger.info(f"Screenshot saved: {file_path} ({file_size} bytes)")
                
                return {
                    'path': str(file_path.relative_to(Path.cwd())),
                    'type': 'screenshot',
                    'size': file_size,
                    'url': url,
                    'timestamp': datetime.now().isoformat()
                }
                
            elif capture_type == 'gif':
                # Capture multiple screenshots
                screenshots = self.capture_gif(url, duration)
                if not screenshots:
                    return None
                
                # Create GIF
                filename = self.generate_filename(vuln_type, vuln_id, 'gif')
                file_path = self.output_dir / filename
                
                if not self.create_gif(screenshots, file_path):
                    return None
                
                file_size = file_path.stat().st_size
                logger.info(f"GIF saved: {file_path} ({file_size} bytes)")
                
                return {
                    'path': str(file_path.relative_to(Path.cwd())),
                    'type': 'gif',
                    'size': file_size,
                    'url': url,
                    'timestamp': datetime.now().isoformat()
                }
            else:
                logger.error(f"Unknown capture type: {capture_type}")
                return None
                
        except Exception as e:
            logger.error(f"Visual proof capture failed: {e}")
            return None


# Global instance for easy access
_global_capture_instance = None


def get_visual_proof_capture(output_dir: str = 'media/exploit_proofs') -> Optional[VisualProofCapture]:
    """
    Get or create global VisualProofCapture instance.
    
    Args:
        output_dir: Output directory for proofs
        
    Returns:
        VisualProofCapture instance or None if dependencies missing
    """
    global _global_capture_instance
    
    # Log dependency status on first call
    _log_dependencies_status()
    
    if _global_capture_instance is None:
        try:
            _global_capture_instance = VisualProofCapture(output_dir)
        except ImportError as e:
            logger.warning(f"Cannot create VisualProofCapture: {e}")
            return None
    
    return _global_capture_instance
