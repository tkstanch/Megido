"""
Fresh Payload Integration System

Allows integration of attack payloads from:
- Public datasets (PayloadAllTheThings, SecLists, etc.)
- Community benchmarks
- Custom payload libraries
- CI/CD integration for automated updates
"""

import json
import logging
import hashlib
import requests
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class PayloadSource:
    """Represents a payload source"""
    name: str
    url: str
    format: str  # json, txt, csv
    category: str  # sqli, xss, xxe, etc.
    last_updated: Optional[str] = None
    enabled: bool = True


@dataclass
class Payload:
    """Represents a single attack payload"""
    id: str
    content: str
    category: str
    source: str
    effectiveness_score: float
    database_type: Optional[str] = None
    technique: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class PayloadIntegration:
    """
    System for integrating fresh attack payloads from multiple sources.
    Supports automated updates via CI/CD.
    """
    
    # Default public payload sources
    DEFAULT_SOURCES = [
        PayloadSource(
            name="PayloadAllTheThings-MySQL",
            url="https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/MySQL%20Injection.md",
            format="markdown",
            category="sqli-mysql"
        ),
        PayloadSource(
            name="PayloadAllTheThings-PostgreSQL",
            url="https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/PostgreSQL%20Injection.md",
            format="markdown",
            category="sqli-postgresql"
        ),
        PayloadSource(
            name="SecLists-SQLi",
            url="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/Databases/sqli.txt",
            format="txt",
            category="sqli-generic"
        ),
    ]
    
    def __init__(self, storage_path: str = "/tmp/payloads"):
        """
        Initialize payload integration system.
        
        Args:
            storage_path: Path to store downloaded payloads
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.sources: List[PayloadSource] = []
        self.payloads: Dict[str, Payload] = {}
        self.payload_hashes: Set[str] = set()
        
        # Load default sources
        self._load_default_sources()
    
    def _load_default_sources(self):
        """Load default payload sources"""
        for source in self.DEFAULT_SOURCES:
            self.add_source(source)
    
    def add_source(self, source: PayloadSource):
        """Add a payload source"""
        self.sources.append(source)
        logger.info(f"Added payload source: {source.name}")
    
    def remove_source(self, source_name: str):
        """Remove a payload source"""
        self.sources = [s for s in self.sources if s.name != source_name]
        logger.info(f"Removed payload source: {source_name}")
    
    def fetch_payloads(self, source: PayloadSource) -> List[str]:
        """
        Fetch payloads from a source.
        
        Args:
            source: PayloadSource to fetch from
            
        Returns:
            List of payload strings
        """
        try:
            logger.info(f"Fetching payloads from {source.name}...")
            
            # Download content
            response = requests.get(source.url, timeout=30)
            response.raise_for_status()
            
            content = response.text
            
            # Parse based on format
            if source.format == "txt":
                payloads = self._parse_txt(content)
            elif source.format == "json":
                payloads = self._parse_json(content)
            elif source.format == "markdown":
                payloads = self._parse_markdown(content)
            elif source.format == "csv":
                payloads = self._parse_csv(content)
            else:
                logger.warning(f"Unknown format: {source.format}")
                payloads = []
            
            # Update last_updated
            source.last_updated = datetime.utcnow().isoformat()
            
            logger.info(f"Fetched {len(payloads)} payloads from {source.name}")
            return payloads
            
        except Exception as e:
            logger.error(f"Error fetching payloads from {source.name}: {e}")
            return []
    
    def _parse_txt(self, content: str) -> List[str]:
        """Parse plain text payload file"""
        lines = content.strip().split('\n')
        # Filter out comments and empty lines
        payloads = [
            line.strip() for line in lines
            if line.strip() and not line.strip().startswith('#')
        ]
        return payloads
    
    def _parse_json(self, content: str) -> List[str]:
        """Parse JSON payload file"""
        try:
            data = json.loads(content)
            if isinstance(data, list):
                return [str(item) for item in data]
            elif isinstance(data, dict) and 'payloads' in data:
                return [str(item) for item in data['payloads']]
            else:
                return []
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}")
            return []
    
    def _parse_markdown(self, content: str) -> List[str]:
        """Parse markdown payload file"""
        payloads = []
        
        # Look for code blocks
        in_code_block = False
        for line in content.split('\n'):
            if line.strip().startswith('```'):
                in_code_block = not in_code_block
                continue
            
            if in_code_block:
                payload = line.strip()
                if payload and not payload.startswith('#'):
                    payloads.append(payload)
        
        return payloads
    
    def _parse_csv(self, content: str) -> List[str]:
        """Parse CSV payload file"""
        import csv
        import io
        
        payloads = []
        reader = csv.reader(io.StringIO(content))
        
        # Skip header if present
        try:
            next(reader)
        except StopIteration:
            return []
        
        for row in reader:
            if row and row[0]:
                payloads.append(row[0].strip())
        
        return payloads
    
    def update_all_payloads(self) -> Dict[str, int]:
        """
        Update payloads from all enabled sources.
        
        Returns:
            Dictionary with source names and payload counts
        """
        results = {}
        
        for source in self.sources:
            if not source.enabled:
                continue
            
            payloads = self.fetch_payloads(source)
            
            # Add to payload library
            added = 0
            for payload_content in payloads:
                if self._add_payload(payload_content, source):
                    added += 1
            
            results[source.name] = added
        
        logger.info(f"Updated payloads from {len(results)} sources")
        return results
    
    def _add_payload(self, content: str, source: PayloadSource) -> bool:
        """
        Add a payload to the library.
        
        Args:
            content: Payload content
            source: Source of the payload
            
        Returns:
            True if added (not duplicate), False otherwise
        """
        # Generate hash to detect duplicates
        payload_hash = hashlib.md5(content.encode()).hexdigest()
        
        if payload_hash in self.payload_hashes:
            return False  # Duplicate
        
        # Create payload object
        payload_id = f"PL-{payload_hash[:12].upper()}"
        payload = Payload(
            id=payload_id,
            content=content,
            category=source.category,
            source=source.name,
            effectiveness_score=0.5,  # Default, will be updated with usage
            tags=self._extract_tags(content)
        )
        
        self.payloads[payload_id] = payload
        self.payload_hashes.add(payload_hash)
        
        return True
    
    def _extract_tags(self, content: str) -> List[str]:
        """Extract tags from payload content"""
        tags = []
        
        content_upper = content.upper()
        
        # Technique tags
        if 'UNION' in content_upper:
            tags.append('union-based')
        if 'SLEEP' in content_upper or 'WAITFOR' in content_upper or 'PG_SLEEP' in content_upper:
            tags.append('time-based')
        if 'OR' in content_upper or 'AND' in content_upper:
            tags.append('boolean-based')
        if '--' in content or '/*' in content or '#' in content:
            tags.append('comment-injection')
        if 'LOAD_FILE' in content_upper or 'INTO OUTFILE' in content_upper:
            tags.append('file-access')
        
        return tags
    
    def get_payloads_by_category(self, category: str) -> List[Payload]:
        """Get payloads by category"""
        return [p for p in self.payloads.values() if p.category == category]
    
    def get_payloads_by_tag(self, tag: str) -> List[Payload]:
        """Get payloads by tag"""
        return [p for p in self.payloads.values() if p.tags and tag in p.tags]
    
    def update_payload_effectiveness(self, payload_id: str, success: bool):
        """
        Update payload effectiveness based on usage.
        
        Args:
            payload_id: Payload ID
            success: Whether the payload was successful
        """
        if payload_id not in self.payloads:
            return
        
        payload = self.payloads[payload_id]
        
        # Update effectiveness using exponential moving average
        alpha = 0.1
        new_score = 1.0 if success else 0.0
        payload.effectiveness_score = (
            alpha * new_score + (1 - alpha) * payload.effectiveness_score
        )
    
    def export_payloads(self, output_path: str, format: str = "json"):
        """
        Export payloads to file.
        
        Args:
            output_path: Output file path
            format: Export format (json, txt, csv)
        """
        output_file = Path(output_path)
        
        if format == "json":
            data = {
                'metadata': {
                    'total_payloads': len(self.payloads),
                    'sources': [asdict(s) for s in self.sources],
                    'exported_at': datetime.utcnow().isoformat()
                },
                'payloads': [asdict(p) for p in self.payloads.values()]
            }
            
            with output_file.open('w') as f:
                json.dump(data, f, indent=2)
        
        elif format == "txt":
            with output_file.open('w') as f:
                for payload in self.payloads.values():
                    f.write(f"{payload.content}\n")
        
        elif format == "csv":
            import csv
            with output_file.open('w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['id', 'content', 'category', 'source', 'effectiveness'])
                for payload in self.payloads.values():
                    writer.writerow([
                        payload.id,
                        payload.content,
                        payload.category,
                        payload.source,
                        payload.effectiveness_score
                    ])
        
        logger.info(f"Exported {len(self.payloads)} payloads to {output_path}")
    
    def import_custom_payloads(self, file_path: str, category: str, source_name: str = "custom"):
        """
        Import custom payloads from file.
        
        Args:
            file_path: Path to payload file
            category: Category for payloads
            source_name: Name of the source
        """
        try:
            with open(file_path, 'r') as f:
                content = f.read()
            
            # Detect format
            if file_path.endswith('.json'):
                payloads = self._parse_json(content)
            elif file_path.endswith('.csv'):
                payloads = self._parse_csv(content)
            else:
                payloads = self._parse_txt(content)
            
            # Create custom source
            source = PayloadSource(
                name=source_name,
                url=f"file://{file_path}",
                format="custom",
                category=category
            )
            
            # Add payloads
            added = 0
            for payload_content in payloads:
                if self._add_payload(payload_content, source):
                    added += 1
            
            logger.info(f"Imported {added} custom payloads from {file_path}")
            return added
            
        except Exception as e:
            logger.error(f"Error importing custom payloads: {e}")
            return 0
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get payload library statistics"""
        stats = {
            'total_payloads': len(self.payloads),
            'total_sources': len(self.sources),
            'enabled_sources': sum(1 for s in self.sources if s.enabled),
            'payloads_by_category': {},
            'average_effectiveness': 0.0,
            'last_update': None
        }
        
        # Count by category
        for payload in self.payloads.values():
            category = payload.category
            stats['payloads_by_category'][category] = stats['payloads_by_category'].get(category, 0) + 1
        
        # Calculate average effectiveness
        if self.payloads:
            stats['average_effectiveness'] = sum(
                p.effectiveness_score for p in self.payloads.values()
            ) / len(self.payloads)
        
        # Get last update time
        update_times = [s.last_updated for s in self.sources if s.last_updated]
        if update_times:
            stats['last_update'] = max(update_times)
        
        return stats


def setup_ci_integration():
    """
    Setup CI/CD integration for automatic payload updates.
    
    Returns:
        Example CI configuration
    """
    ci_config = {
        'github_actions': {
            'name': 'Update SQL Injection Payloads',
            'on': {
                'schedule': [
                    {'cron': '0 0 * * 0'}  # Weekly on Sunday
                ],
                'workflow_dispatch': {}  # Manual trigger
            },
            'jobs': {
                'update-payloads': {
                    'runs-on': 'ubuntu-latest',
                    'steps': [
                        {'uses': 'actions/checkout@v3'},
                        {
                            'name': 'Setup Python',
                            'uses': 'actions/setup-python@v4',
                            'with': {'python-version': '3.11'}
                        },
                        {
                            'name': 'Install dependencies',
                            'run': 'pip install requests'
                        },
                        {
                            'name': 'Update payloads',
                            'run': 'python -m sql_attacker.payload_integration update'
                        },
                        {
                            'name': 'Commit changes',
                            'run': '''
                                git config --local user.email "action@github.com"
                                git config --local user.name "GitHub Action"
                                git add payloads/
                                git commit -m "Auto-update SQL injection payloads" || echo "No changes"
                                git push
                            '''
                        }
                    ]
                }
            }
        }
    }
    
    return ci_config


if __name__ == "__main__":
    # Example usage
    integrator = PayloadIntegration()
    
    # Update from all sources
    results = integrator.update_all_payloads()
    print(f"Updated payloads: {results}")
    
    # Get statistics
    stats = integrator.get_statistics()
    print(f"Statistics: {json.dumps(stats, indent=2)}")
    
    # Export payloads
    integrator.export_payloads("/tmp/all_payloads.json", format="json")
