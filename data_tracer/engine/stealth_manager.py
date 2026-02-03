"""
Stealth manager module for implementing stealth scanning techniques.
Includes timing randomization, slow scanning, packet crafting, and evasion.
"""

import random
import time
from typing import Dict, Optional, List


class StealthManager:
    """
    Stealth operation manager for minimizing detection.
    """
    
    # Timing templates (similar to Nmap)
    TIMING_TEMPLATES = {
        0: {  # Paranoid - extremely slow
            'name': 'Paranoid',
            'scan_delay': 300,
            'max_scan_delay': 600,
            'min_rate': 0,
            'max_rate': 1,
            'max_retries': 1,
            'host_timeout': 3600,
        },
        1: {  # Sneaky - very slow
            'name': 'Sneaky',
            'scan_delay': 15,
            'max_scan_delay': 30,
            'min_rate': 0,
            'max_rate': 10,
            'max_retries': 2,
            'host_timeout': 1800,
        },
        2: {  # Polite - slow
            'name': 'Polite',
            'scan_delay': 0.4,
            'max_scan_delay': 1,
            'min_rate': 0,
            'max_rate': 100,
            'max_retries': 3,
            'host_timeout': 900,
        },
        3: {  # Normal - default
            'name': 'Normal',
            'scan_delay': 0,
            'max_scan_delay': 0,
            'min_rate': 0,
            'max_rate': 0,
            'max_retries': 3,
            'host_timeout': 900,
        },
        4: {  # Aggressive - fast
            'name': 'Aggressive',
            'scan_delay': 0,
            'max_scan_delay': 0,
            'min_rate': 50,
            'max_rate': 250,
            'max_retries': 2,
            'host_timeout': 300,
        },
        5: {  # Insane - very fast
            'name': 'Insane',
            'scan_delay': 0,
            'max_scan_delay': 0,
            'min_rate': 100,
            'max_rate': 300,
            'max_retries': 1,
            'host_timeout': 75,
        },
    }
    
    def __init__(self, timing_template: int = 3):
        """
        Initialize stealth manager.
        
        Args:
            timing_template: Timing template (0-5, default 3 for Normal)
        """
        self.timing_template = timing_template
        self.config = self.TIMING_TEMPLATES.get(timing_template, self.TIMING_TEMPLATES[3])
        self.scan_delay = self.config['scan_delay']
        self.max_scan_delay = self.config['max_scan_delay']
    
    def get_timing_delay(self) -> float:
        """
        Get timing delay with randomization.
        
        Returns:
            Delay in seconds
        """
        if self.max_scan_delay > self.scan_delay:
            return random.uniform(self.scan_delay, self.max_scan_delay)
        return self.scan_delay
    
    def apply_timing_delay(self):
        """Apply timing delay (sleep)."""
        delay = self.get_timing_delay()
        if delay > 0:
            time.sleep(delay)
    
    def randomize_target_order(self, targets: List) -> List:
        """
        Randomize order of targets to avoid patterns.
        
        Args:
            targets: List of targets
        
        Returns:
            Randomized list
        """
        randomized = targets.copy()
        random.shuffle(randomized)
        return randomized
    
    def randomize_port_order(self, ports: List[int]) -> List[int]:
        """
        Randomize order of ports to avoid patterns.
        
        Args:
            ports: List of port numbers
        
        Returns:
            Randomized list
        """
        randomized = ports.copy()
        random.shuffle(randomized)
        return randomized
    
    def generate_decoy_ips(self, count: int = 5) -> List[str]:
        """
        Generate decoy IP addresses for decoy scanning.
        
        Args:
            count: Number of decoy IPs to generate
        
        Returns:
            List of decoy IP addresses
        """
        decoys = []
        for _ in range(count):
            # Generate random IP address
            ip = '.'.join([str(random.randint(1, 254)) for _ in range(4)])
            decoys.append(ip)
        return decoys
    
    def fragment_packet_size(self, 
                           original_size: int,
                           mtu: int = 576) -> List[int]:
        """
        Calculate packet fragmentation sizes.
        
        Args:
            original_size: Original packet size
            mtu: Maximum Transmission Unit (default 576 bytes)
        
        Returns:
            List of fragment sizes
        """
        fragments = []
        remaining = original_size
        
        while remaining > 0:
            fragment_size = min(mtu - 20, remaining)  # Account for IP header
            fragments.append(fragment_size)
            remaining -= fragment_size
        
        return fragments
    
    def generate_random_mac(self) -> str:
        """
        Generate random MAC address for MAC spoofing.
        
        Returns:
            Random MAC address string
        """
        # Generate random MAC with locally administered bit set
        mac = [
            0x02,  # Locally administered
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff),
            random.randint(0x00, 0xff)
        ]
        
        return ':'.join([f'{byte:02x}' for byte in mac])
    
    def get_random_source_port(self) -> int:
        """
        Get random source port for scanning.
        
        Returns:
            Random port number
        """
        # Use high port range to appear like normal client
        return random.randint(49152, 65535)
    
    def calculate_adaptive_delay(self,
                                success_rate: float,
                                current_delay: float) -> float:
        """
        Calculate adaptive delay based on success rate.
        
        Args:
            success_rate: Current success rate (0.0 to 1.0)
            current_delay: Current delay in seconds
        
        Returns:
            Adjusted delay
        """
        # If success rate is low, increase delay to avoid detection/blocking
        if success_rate < 0.5:
            return min(current_delay * 1.5, 10.0)
        # If success rate is high, slightly decrease delay
        elif success_rate > 0.8:
            return max(current_delay * 0.8, 0.1)
        
        return current_delay
    
    def get_random_data_payload(self, size: int = 32) -> bytes:
        """
        Generate random data payload to append to packets.
        
        Args:
            size: Payload size in bytes
        
        Returns:
            Random bytes
        """
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    def should_retry(self, attempt: int) -> bool:
        """
        Determine if operation should be retried.
        
        Args:
            attempt: Current attempt number (0-indexed)
        
        Returns:
            True if should retry, False otherwise
        """
        return attempt < self.config['max_retries']
    
    def get_retry_delay(self, attempt: int) -> float:
        """
        Get delay before retry with exponential backoff.
        
        Args:
            attempt: Current attempt number (0-indexed)
        
        Returns:
            Delay in seconds
        """
        base_delay = self.scan_delay if self.scan_delay > 0 else 1.0
        
        # Exponential backoff with jitter
        delay = base_delay * (2 ** attempt)
        jitter = random.uniform(0, delay * 0.1)
        
        return delay + jitter
    
    def evade_ids_ips(self) -> Dict:
        """
        Get configuration for IDS/IPS evasion techniques.
        
        Returns:
            Dictionary of evasion settings
        """
        return {
            'fragment_packets': True,
            'randomize_order': True,
            'use_decoys': True,
            'spoof_mac': True,
            'vary_ttl': True,
            'add_random_data': True,
            'timing_variation': True,
        }
    
    def get_safe_scan_rate(self, 
                          target_type: str = 'standard') -> Dict:
        """
        Get safe scan rate based on target type.
        
        Args:
            target_type: Type of target (standard, sensitive, aggressive)
        
        Returns:
            Dictionary with rate limits
        """
        rates = {
            'paranoid': {
                'packets_per_second': 0.1,
                'concurrent_targets': 1,
                'delay_between_probes': 10.0,
            },
            'sensitive': {
                'packets_per_second': 1,
                'concurrent_targets': 3,
                'delay_between_probes': 1.0,
            },
            'standard': {
                'packets_per_second': 10,
                'concurrent_targets': 10,
                'delay_between_probes': 0.1,
            },
            'aggressive': {
                'packets_per_second': 100,
                'concurrent_targets': 50,
                'delay_between_probes': 0.01,
            },
        }
        
        return rates.get(target_type, rates['standard'])
    
    def generate_scan_pattern(self, 
                            num_targets: int,
                            pattern: str = 'random') -> List[int]:
        """
        Generate scan pattern for target ordering.
        
        Args:
            num_targets: Number of targets
            pattern: Pattern type (sequential, random, round_robin)
        
        Returns:
            List of target indices
        """
        if pattern == 'sequential':
            return list(range(num_targets))
        
        elif pattern == 'random':
            indices = list(range(num_targets))
            random.shuffle(indices)
            return indices
        
        elif pattern == 'round_robin':
            # Interleave targets to avoid sequential patterns
            indices = []
            step = max(1, num_targets // 10)
            for offset in range(step):
                for i in range(offset, num_targets, step):
                    indices.append(i)
            return indices
        
        return list(range(num_targets))
    
    def get_stealth_config(self) -> Dict:
        """
        Get complete stealth configuration.
        
        Returns:
            Dictionary with all stealth settings
        """
        return {
            'timing_template': self.timing_template,
            'timing_name': self.config['name'],
            'scan_delay': self.scan_delay,
            'max_scan_delay': self.max_scan_delay,
            'min_rate': self.config['min_rate'],
            'max_rate': self.config['max_rate'],
            'max_retries': self.config['max_retries'],
            'host_timeout': self.config['host_timeout'],
            'randomize_hosts': True,
            'randomize_ports': True,
            'use_decoys': True,
            'fragment_packets': True,
            'spoof_mac': True,
        }
