"""
XSS Visual Proof (GIF) Generation Module

This module provides automated visual proof generation for XSS exploits.
When an XSS exploit is confirmed, it:
1. Launches the exploited URL in a headless browser (Playwright)
2. Captures screenshots during exploitation (e.g., alert boxes)
3. Converts screenshots to an animated GIF
4. Returns the GIF file path for inclusion in reports

Security Features:
- URL sanitization and validation
- Resource limits (duration, file size)
- Proper error handling without interrupting main flow
- Temporary file cleanup

Dependencies:
- playwright (preferred) or selenium (fallback)
- Pillow (PIL) for image processing
"""

import os
import re
import logging
import hashlib
import time
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

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
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False
    logger.warning("PIL/Pillow not available. Install with: pip install Pillow")


class XSSGifCapture:
    """
    Automated visual proof generator for XSS exploits.
    
    Captures browser interaction with exploited XSS vulnerability
    and generates an animated GIF proof.
    """
    
    # Security constraints
    MAX_DURATION_SECONDS = 5  # Maximum recording duration
    MAX_FILE_SIZE_MB = 10  # Maximum GIF file size
    SCREENSHOT_INTERVAL = 0.5  # Seconds between screenshots
    MAX_SCREENSHOTS = 10  # Maximum number of screenshots
    
    # URL validation regex (basic security check)
    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    def __init__(self, output_dir: str = 'media/xss_gif_proofs'):
        """
        Initialize the GIF capture module.
        
        Args:
            output_dir: Directory to save GIF files (default: media/xss_gif_proofs)
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Check dependencies
        if not HAS_PIL:
            raise ImportError("PIL/Pillow is required for GIF generation. Install with: pip install Pillow")
        
        if not HAS_PLAYWRIGHT and not HAS_SELENIUM:
            raise ImportError(
                "Either Playwright or Selenium is required for browser automation. "
                "Install with: pip install playwright && playwright install chromium OR pip install selenium"
            )
        
        self.use_playwright = HAS_PLAYWRIGHT
        logger.info(f"XSSGifCapture initialized using {'Playwright' if self.use_playwright else 'Selenium'}")
    
    def sanitize_url(self, url: str) -> bool:
        """
        Validate and sanitize URL for security.
        
        Args:
            url: URL to validate
            
        Returns:
            True if URL is valid and safe, False otherwise
        """
        if not url or not isinstance(url, str):
            logger.warning("Invalid URL: empty or not a string")
            return False
        
        # Basic pattern matching
        if not self.URL_PATTERN.match(url):
            logger.warning(f"Invalid URL format: {url}")
            return False
        
        # Parse URL
        try:
            parsed = urlparse(url)
            
            # Check for file:// and other dangerous schemes
            if parsed.scheme not in ['http', 'https']:
                logger.warning(f"Unsafe URL scheme: {parsed.scheme}")
                return False
            
            # Basic length check (prevent extremely long URLs)
            if len(url) > 2048:
                logger.warning("URL too long")
                return False
            
            return True
        except Exception as e:
            logger.warning(f"URL parsing error: {e}")
            return False
    
    def generate_filename(self, url: str, payload: str) -> str:
        """
        Generate a unique filename for the GIF based on URL and payload.
        
        Args:
            url: Target URL
            payload: XSS payload used
            
        Returns:
            Filename (without path)
        """
        # Create hash from URL + payload + timestamp
        timestamp = datetime.now().isoformat()
        combined = f"{url}|{payload}|{timestamp}"
        hash_obj = hashlib.sha256(combined.encode())
        file_hash = hash_obj.hexdigest()[:16]
        
        # Format: xss_proof_<hash>_<timestamp>.gif
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"xss_proof_{file_hash}_{timestamp_str}.gif"
        
        return filename
    
    def capture_with_playwright(self, url: str, duration: float = 3.0) -> List[bytes]:
        """
        Capture screenshots using Playwright.
        
        Args:
            url: URL to capture
            duration: Recording duration in seconds
            
        Returns:
            List of screenshot bytes
        """
        screenshots = []
        
        try:
            with sync_playwright() as p:
                # Launch browser in headless mode
                browser = p.chromium.launch(headless=True)
                context = browser.new_context(
                    viewport={'width': 1280, 'height': 720},
                    ignore_https_errors=True
                )
                page = context.new_page()
                
                # Set timeout
                page.set_default_timeout(5000)
                
                # Navigate to URL
                logger.info(f"Navigating to {url}")
                page.goto(url, wait_until='domcontentloaded')
                
                # Capture screenshots at intervals
                start_time = time.time()
                screenshot_count = 0
                
                while (time.time() - start_time) < duration and screenshot_count < self.MAX_SCREENSHOTS:
                    # Take screenshot
                    screenshot_bytes = page.screenshot(full_page=False)
                    screenshots.append(screenshot_bytes)
                    screenshot_count += 1
                    
                    logger.debug(f"Captured screenshot {screenshot_count}/{self.MAX_SCREENSHOTS}")
                    
                    # Wait before next screenshot
                    time.sleep(self.SCREENSHOT_INTERVAL)
                
                # Close browser
                browser.close()
                
                logger.info(f"Captured {len(screenshots)} screenshots")
                return screenshots
                
        except PlaywrightTimeoutError as e:
            logger.warning(f"Playwright timeout: {e}")
            return screenshots  # Return what we have
        except Exception as e:
            logger.error(f"Playwright capture error: {e}")
            return screenshots
    
    def capture_with_selenium(self, url: str, duration: float = 3.0) -> List[bytes]:
        """
        Capture screenshots using Selenium (fallback).
        
        Args:
            url: URL to capture
            duration: Recording duration in seconds
            
        Returns:
            List of screenshot bytes
        """
        screenshots = []
        driver = None
        
        try:
            # Setup Chrome options
            options = ChromeOptions()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--window-size=1280,720')
            
            # Create driver
            driver = webdriver.Chrome(options=options)
            driver.set_page_load_timeout(5)
            
            # Navigate to URL
            logger.info(f"Navigating to {url}")
            driver.get(url)
            
            # Capture screenshots at intervals
            start_time = time.time()
            screenshot_count = 0
            
            while (time.time() - start_time) < duration and screenshot_count < self.MAX_SCREENSHOTS:
                # Take screenshot
                screenshot_bytes = driver.get_screenshot_as_png()
                screenshots.append(screenshot_bytes)
                screenshot_count += 1
                
                logger.debug(f"Captured screenshot {screenshot_count}/{self.MAX_SCREENSHOTS}")
                
                # Wait before next screenshot
                time.sleep(self.SCREENSHOT_INTERVAL)
            
            logger.info(f"Captured {len(screenshots)} screenshots")
            return screenshots
            
        except TimeoutException as e:
            logger.warning(f"Selenium timeout: {e}")
            return screenshots  # Return what we have
        except Exception as e:
            logger.error(f"Selenium capture error: {e}")
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
        Create animated GIF from screenshots.
        
        Args:
            screenshots: List of screenshot bytes
            output_path: Output file path
            duration_per_frame: Duration per frame in milliseconds
            
        Returns:
            True if successful, False otherwise
        """
        if not screenshots:
            logger.warning("No screenshots to create GIF")
            return False
        
        try:
            # Convert screenshot bytes to PIL Images
            images = []
            for screenshot_bytes in screenshots:
                from io import BytesIO
                img = Image.open(BytesIO(screenshot_bytes))
                # Resize if too large to keep file size reasonable
                if img.width > 1280 or img.height > 720:
                    img = img.resize((1280, 720), Image.Resampling.LANCZOS)
                images.append(img)
            
            if not images:
                logger.warning("Failed to convert screenshots to images")
                return False
            
            # Save as animated GIF
            images[0].save(
                output_path,
                save_all=True,
                append_images=images[1:],
                duration=duration_per_frame,
                loop=0,
                optimize=True
            )
            
            # Check file size
            file_size_mb = output_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.MAX_FILE_SIZE_MB:
                logger.warning(f"GIF file size ({file_size_mb:.2f}MB) exceeds limit ({self.MAX_FILE_SIZE_MB}MB)")
                output_path.unlink()  # Delete oversized file
                return False
            
            logger.info(f"Created GIF: {output_path} ({file_size_mb:.2f}MB)")
            return True
            
        except Exception as e:
            logger.error(f"Error creating GIF: {e}")
            return False
    
    def capture_xss_proof(self, url: str, payload: str, 
                          duration: float = 3.0) -> Optional[str]:
        """
        Capture visual proof of XSS exploitation as GIF.
        
        This is the main entry point for generating XSS proof GIFs.
        
        Args:
            url: Exploited URL (with payload injected)
            payload: XSS payload that was used
            duration: Recording duration in seconds (max: MAX_DURATION_SECONDS)
            
        Returns:
            Relative path to GIF file (for storage in finding dict), or None on failure
        """
        # Validate inputs
        if not self.sanitize_url(url):
            logger.error(f"URL validation failed: {url}")
            return None
        
        # Limit duration
        duration = min(duration, self.MAX_DURATION_SECONDS)
        
        try:
            # Capture screenshots
            logger.info(f"Starting XSS proof capture for URL: {url}")
            
            if self.use_playwright:
                screenshots = self.capture_with_playwright(url, duration)
            else:
                screenshots = self.capture_with_selenium(url, duration)
            
            if not screenshots:
                logger.warning("No screenshots captured")
                return None
            
            # Generate filename and path
            filename = self.generate_filename(url, payload)
            output_path = self.output_dir / filename
            
            # Create GIF
            if self.create_gif(screenshots, output_path):
                # Return relative path from media root
                relative_path = f"/media/xss_gif_proofs/{filename}"
                logger.info(f"Successfully generated XSS proof GIF: {relative_path}")
                return relative_path
            else:
                return None
                
        except Exception as e:
            logger.error(f"Error capturing XSS proof: {e}", exc_info=True)
            return None
    
    def cleanup_old_files(self, max_age_days: int = 7):
        """
        Clean up old GIF files to prevent disk space issues.
        
        Args:
            max_age_days: Maximum age of files to keep (default: 7 days)
        """
        try:
            current_time = time.time()
            max_age_seconds = max_age_days * 24 * 60 * 60
            
            deleted_count = 0
            for gif_file in self.output_dir.glob("*.gif"):
                file_age = current_time - gif_file.stat().st_mtime
                if file_age > max_age_seconds:
                    gif_file.unlink()
                    deleted_count += 1
                    logger.debug(f"Deleted old GIF: {gif_file}")
            
            if deleted_count > 0:
                logger.info(f"Cleaned up {deleted_count} old GIF files")
                
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")


def get_xss_gif_capture(output_dir: str = 'media/xss_gif_proofs') -> Optional[XSSGifCapture]:
    """
    Factory function to get XSSGifCapture instance.
    
    Returns None if dependencies are not available.
    
    Args:
        output_dir: Directory to save GIF files
        
    Returns:
        XSSGifCapture instance or None
    """
    try:
        return XSSGifCapture(output_dir=output_dir)
    except ImportError as e:
        logger.warning(f"XSS GIF capture not available: {e}")
        return None
