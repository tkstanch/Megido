"""
Media Management Utility for Exploit Visual Proof

This module handles storage, retrieval, and management of visual proof media files
for vulnerability exploits including screenshots, GIFs, and videos.
"""

import os
import logging
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Tuple
from django.conf import settings

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

logger = logging.getLogger(__name__)


class MediaManager:
    """
    Manages visual proof media files for exploits.
    
    Features:
    - Store multiple media files per vulnerability
    - Support for screenshots, GIFs, and videos
    - Automatic file optimization
    - Secure file naming and storage
    - Database integration
    """
    
    # File size limits
    MAX_SCREENSHOT_SIZE_MB = 5
    MAX_GIF_SIZE_MB = 10
    MAX_VIDEO_SIZE_MB = 50
    
    # Media types
    MEDIA_TYPES = {
        'screenshot': {
            'extensions': ['.png', '.jpg', '.jpeg'],
            'mime_types': ['image/png', 'image/jpeg'],
            'max_size': MAX_SCREENSHOT_SIZE_MB * 1024 * 1024
        },
        'gif': {
            'extensions': ['.gif'],
            'mime_types': ['image/gif'],
            'max_size': MAX_GIF_SIZE_MB * 1024 * 1024
        },
        'video': {
            'extensions': ['.mp4', '.webm'],
            'mime_types': ['video/mp4', 'video/webm'],
            'max_size': MAX_VIDEO_SIZE_MB * 1024 * 1024
        }
    }
    
    def __init__(self, base_dir: str = 'media/exploit_proofs'):
        """
        Initialize media manager.
        
        Args:
            base_dir: Base directory for storing media files
        """
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        logger.info(f"MediaManager initialized with base_dir: {self.base_dir}")
    
    def generate_secure_filename(self, vuln_id: int, vuln_type: str, 
                                 media_type: str, extension: str) -> str:
        """
        Generate a secure, unique filename for media.
        
        Args:
            vuln_id: Vulnerability ID
            vuln_type: Vulnerability type (xss, sqli, etc.)
            media_type: Media type (screenshot, gif, video)
            extension: File extension (with dot, e.g., '.png')
            
        Returns:
            Secure filename
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
        hash_input = f"{vuln_id}_{vuln_type}_{media_type}_{timestamp}"
        hash_str = hashlib.sha256(hash_input.encode()).hexdigest()[:12]
        
        # Ensure extension starts with dot
        if not extension.startswith('.'):
            extension = '.' + extension
        
        return f"{vuln_type}_{vuln_id}_{media_type}_{hash_str}_{timestamp}{extension}"
    
    def get_media_path(self, vuln_id: int, vuln_type: str, filename: str) -> Path:
        """
        Get the full path for a media file organized by vulnerability type and ID.
        
        Args:
            vuln_id: Vulnerability ID
            vuln_type: Vulnerability type
            filename: Media filename
            
        Returns:
            Full path to the media file
        """
        # Organize files: base_dir/vuln_type/vuln_id/filename
        media_dir = self.base_dir / vuln_type / str(vuln_id)
        media_dir.mkdir(parents=True, exist_ok=True)
        return media_dir / filename
    
    def save_media(self, vuln_id: int, vuln_type: str, media_type: str,
                   file_data: bytes, extension: str = '.png',
                   title: Optional[str] = None, description: Optional[str] = None,
                   exploit_step: Optional[str] = None, payload: Optional[str] = None,
                   sequence_order: int = 0) -> Optional[Dict[str, Any]]:
        """
        Save media file and return metadata for database storage.
        
        Args:
            vuln_id: Vulnerability ID
            vuln_type: Vulnerability type
            media_type: Type of media (screenshot, gif, video)
            file_data: Raw file data as bytes
            extension: File extension
            title: Optional title for the media
            description: Optional description
            exploit_step: Which step of the exploit this represents
            payload: The payload used in this capture
            sequence_order: Display order (0 = first)
            
        Returns:
            Dictionary with media metadata for database storage, or None on failure
        """
        try:
            # Validate media type
            if media_type not in self.MEDIA_TYPES:
                logger.error(f"Invalid media type: {media_type}")
                return None
            
            # Generate filename
            filename = self.generate_secure_filename(vuln_id, vuln_type, media_type, extension)
            file_path = self.get_media_path(vuln_id, vuln_type, filename)
            
            # Check file size
            file_size = len(file_data)
            max_size = self.MEDIA_TYPES[media_type]['max_size']
            
            if file_size > max_size:
                logger.warning(f"File size {file_size} exceeds maximum {max_size}, attempting optimization...")
                if media_type in ['screenshot', 'gif'] and HAS_PIL:
                    file_data = self._optimize_image(file_data, max_size)
                    file_size = len(file_data)
                    if file_size > max_size:
                        logger.error(f"File still too large after optimization: {file_size}")
                        return None
                else:
                    logger.error(f"Cannot optimize {media_type}, file too large")
                    return None
            
            # Save file
            with open(file_path, 'wb') as f:
                f.write(file_data)
            
            logger.info(f"Saved media: {file_path} ({file_size} bytes)")
            
            # Get image dimensions if applicable
            width, height, frame_count = None, None, None
            if media_type in ['screenshot', 'gif'] and HAS_PIL:
                try:
                    img = Image.open(file_path)
                    width, height = img.size
                    if media_type == 'gif':
                        frame_count = getattr(img, 'n_frames', 1)
                except Exception as e:
                    logger.warning(f"Could not get image dimensions: {e}")
            
            # Determine MIME type
            mime_type = 'application/octet-stream'
            for ext in self.MEDIA_TYPES[media_type]['extensions']:
                if filename.lower().endswith(ext):
                    idx = self.MEDIA_TYPES[media_type]['extensions'].index(ext)
                    if idx < len(self.MEDIA_TYPES[media_type]['mime_types']):
                        mime_type = self.MEDIA_TYPES[media_type]['mime_types'][idx]
                    break
            
            # Build relative path for database storage
            relative_path = f"{vuln_type}/{vuln_id}/{filename}"
            
            # Return metadata
            return {
                'media_type': media_type,
                'file_path': relative_path,
                'file_name': filename,
                'file_size': file_size,
                'mime_type': mime_type,
                'title': title or f"{media_type.capitalize()} for {vuln_type}",
                'description': description,
                'sequence_order': sequence_order,
                'width': width,
                'height': height,
                'frame_count': frame_count,
                'exploit_step': exploit_step,
                'payload_used': payload,
            }
            
        except Exception as e:
            logger.error(f"Failed to save media: {e}")
            return None
    
    def _optimize_image(self, image_data: bytes, max_size: int) -> bytes:
        """
        Optimize image to fit within size limit.
        
        Args:
            image_data: Raw image data
            max_size: Maximum size in bytes
            
        Returns:
            Optimized image data
        """
        if not HAS_PIL:
            return image_data
        
        try:
            import io
            img = Image.open(io.BytesIO(image_data))
            
            # Try reducing quality first
            for quality in [85, 75, 65, 50]:
                output = io.BytesIO()
                if img.mode in ['RGBA', 'LA']:
                    # Convert to RGB for JPEG
                    img_rgb = Image.new('RGB', img.size, (255, 255, 255))
                    img_rgb.paste(img, mask=img.split()[-1] if img.mode == 'RGBA' else None)
                    img_rgb.save(output, format='JPEG', quality=quality, optimize=True)
                else:
                    img.save(output, format='JPEG', quality=quality, optimize=True)
                
                optimized_data = output.getvalue()
                if len(optimized_data) <= max_size:
                    logger.info(f"Optimized image to {len(optimized_data)} bytes (quality={quality})")
                    return optimized_data
            
            # If quality reduction isn't enough, resize
            scale_factor = 0.8
            while len(optimized_data) > max_size and scale_factor > 0.3:
                new_size = (int(img.width * scale_factor), int(img.height * scale_factor))
                resized = img.resize(new_size, Image.Resampling.LANCZOS)
                
                output = io.BytesIO()
                resized.save(output, format='JPEG', quality=75, optimize=True)
                optimized_data = output.getvalue()
                
                if len(optimized_data) <= max_size:
                    logger.info(f"Optimized image to {len(optimized_data)} bytes (scale={scale_factor})")
                    return optimized_data
                
                scale_factor -= 0.1
            
            # Return best effort
            return optimized_data
            
        except Exception as e:
            logger.error(f"Image optimization failed: {e}")
            return image_data
    
    def get_media_url(self, relative_path: str) -> str:
        """
        Get the URL for accessing a media file.
        
        Args:
            relative_path: Relative path from base_dir
            
        Returns:
            URL to access the media file
        """
        # In Django, media files are typically served from MEDIA_URL
        media_url = getattr(settings, 'MEDIA_URL', '/media/')
        return f"{media_url}exploit_proofs/{relative_path}"
    
    def delete_media(self, relative_path: str) -> bool:
        """
        Delete a media file.
        
        Args:
            relative_path: Relative path from base_dir
            
        Returns:
            True if deletion was successful
        """
        try:
            file_path = self.base_dir / relative_path
            if file_path.exists():
                file_path.unlink()
                logger.info(f"Deleted media: {file_path}")
                return True
            else:
                logger.warning(f"Media file not found: {file_path}")
                return False
        except Exception as e:
            logger.error(f"Failed to delete media: {e}")
            return False
    
    def create_media_record(self, vulnerability_id: int, metadata: Dict[str, Any]):
        """
        Create a database record for the media file.
        
        Args:
            vulnerability_id: Vulnerability ID
            metadata: Media metadata from save_media()
            
        Returns:
            ExploitMedia instance or None on failure
        """
        try:
            from scanner.models import ExploitMedia, Vulnerability
            
            vulnerability = Vulnerability.objects.get(id=vulnerability_id)
            
            media = ExploitMedia.objects.create(
                vulnerability=vulnerability,
                media_type=metadata['media_type'],
                file_path=metadata['file_path'],
                file_name=metadata['file_name'],
                file_size=metadata['file_size'],
                mime_type=metadata['mime_type'],
                title=metadata.get('title'),
                description=metadata.get('description'),
                sequence_order=metadata.get('sequence_order', 0),
                width=metadata.get('width'),
                height=metadata.get('height'),
                frame_count=metadata.get('frame_count'),
                exploit_step=metadata.get('exploit_step'),
                payload_used=metadata.get('payload_used'),
            )
            
            logger.info(f"Created media record: {media.id}")
            return media
            
        except Exception as e:
            logger.error(f"Failed to create media record: {e}")
            return None
