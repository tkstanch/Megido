"""
Wireless network analysis engine for Data Tracer.
Implements WiFi scanning, access point analysis, client enumeration,
WPS analysis, and Bluetooth scanning.
"""

import random
import hashlib
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime


# WiFi encryption types and their security levels
ENCRYPTION_SECURITY = {
    'WPA3': {'level': 'strong', 'score': 10, 'description': 'WPA3 - Latest WiFi security standard'},
    'WPA2-EAP': {'level': 'strong', 'score': 9, 'description': 'WPA2 Enterprise - Strong authentication'},
    'WPA2': {'level': 'strong', 'score': 8, 'description': 'WPA2-Personal - Recommended minimum'},
    'WPA': {'level': 'weak', 'score': 5, 'description': 'WPA - Deprecated, vulnerable to TKIP attacks'},
    'WEP': {'level': 'critical', 'score': 1, 'description': 'WEP - Completely broken, do not use'},
    'OPEN': {'level': 'critical', 'score': 0, 'description': 'Open network - No encryption'},
}

# Common WiFi channel frequencies
WIFI_CHANNELS_2GHZ = {
    1: 2412, 2: 2417, 3: 2422, 4: 2427, 5: 2432,
    6: 2437, 7: 2442, 8: 2447, 9: 2452, 10: 2457,
    11: 2462, 12: 2467, 13: 2472, 14: 2484,
}

WIFI_CHANNELS_5GHZ = {
    36: 5180, 40: 5200, 44: 5220, 48: 5240,
    52: 5260, 56: 5280, 60: 5300, 64: 5320,
    100: 5500, 104: 5520, 108: 5540, 112: 5560,
    116: 5580, 120: 5600, 124: 5620, 128: 5640,
    132: 5660, 136: 5680, 140: 5700, 149: 5745,
    153: 5765, 157: 5785, 161: 5805, 165: 5825,
}

# Known rogue AP indicators
ROGUE_AP_INDICATORS = [
    'honeypot', 'freewifi', 'free_wifi', 'public_wifi',
    'airport_wifi', 'hotel_wifi', 'guest_network',
]

# AP vendor OUI database (subset)
AP_VENDORS = {
    '00:18:0a': 'Ubiquiti Networks',
    '04:18:d6': 'Ubiquiti Networks',
    'dc:9f:db': 'Ubiquiti Networks',
    '00:0b:86': 'Aruba Networks',
    '00:1a:1e': 'Aruba Networks',
    '00:24:6c': 'Aruba Networks',
    '00:22:b0': 'Cisco/Aironet',
    '00:21:d8': 'Cisco/Aironet',
    '00:40:96': 'Cisco/Aironet',
    '00:1d:7e': 'Cisco-Linksys',
    'c0:56:27': 'Cisco-Linksys',
    '14:cf:92': 'TP-Link',
    '50:c7:bf': 'TP-Link',
    'a0:f3:c1': 'TP-Link',
    '00:1b:2f': 'NETGEAR',
    '1c:1b:0d': 'NETGEAR',
    '28:c6:8e': 'NETGEAR',
    '74:9e:af': 'D-Link',
    'c8:be:19': 'D-Link',
    '1c:7e:e5': 'D-Link',
    '8c:04:ff': 'Asus',
    '00:15:5d': 'Microsoft',
    '58:ef:68': 'Belkin',
    'c0:56:27': 'Belkin',
    'ec:1a:59': 'Belkin',
    '00:1f:c6': 'Huawei',
    '00:46:4b': 'Huawei',
    '00:e0:fc': 'Huawei',
}

# BLE service UUIDs
BLE_SERVICES = {
    '1800': 'Generic Access',
    '1801': 'Generic Attribute',
    '1802': 'Immediate Alert',
    '1803': 'Link Loss',
    '1804': 'Tx Power',
    '1805': 'Current Time Service',
    '180a': 'Device Information',
    '180d': 'Heart Rate',
    '180f': 'Battery Service',
    '1810': 'Blood Pressure',
    '1811': 'Alert Notification Service',
    '1812': 'Human Interface Device',
    '1816': 'Cycling Speed and Cadence',
    '1818': 'Cycling Power',
    '1819': 'Location and Navigation',
    '181a': 'Environmental Sensing',
    '1826': 'Fitness Machine',
}


class WirelessAnalyzer:
    """
    Wireless network analysis engine implementing WiFi scanning,
    rogue AP detection, client enumeration, and Bluetooth analysis.
    """

    def __init__(self):
        """Initialize the wireless analyzer."""
        self.discovered_networks: List[Dict] = []
        self.access_points: List[Dict] = []
        self.clients: List[Dict] = []
        self.bluetooth_devices: List[Dict] = []
        self.rogues: List[Dict] = []

    def scan_wifi_networks(self, interface: str = 'wlan0') -> List[Dict]:
        """
        Scan for WiFi networks in range.

        Args:
            interface: Wireless interface to use for scanning

        Returns:
            List of discovered WiFi networks
        """
        networks = []

        # In production, would use scapy/aircrack-ng APIs or system commands
        # Here we return a structured result with simulated data for demo purposes
        simulated_networks = self._simulate_wifi_scan()

        for net in simulated_networks:
            # Analyze security
            security_info = self._analyze_wifi_security(net)
            net['security_analysis'] = security_info
            net['risk_level'] = self._assess_wifi_risk(net)
            net['vendor'] = self._lookup_ap_vendor(net.get('bssid', ''))
            networks.append(net)

        self.discovered_networks = networks
        return networks

    def _simulate_wifi_scan(self) -> List[Dict]:
        """Generate simulated WiFi scan results."""
        return [
            {
                'ssid': 'CorporateNet',
                'bssid': 'aa:bb:cc:dd:ee:01',
                'channel': 6,
                'frequency': WIFI_CHANNELS_2GHZ.get(6, 2437),
                'signal_dbm': -65,
                'encryption': 'WPA2',
                'cipher': 'AES',
                'auth': 'PSK',
                'band': '2.4GHz',
                'wps_enabled': False,
                'hidden': False,
                'beacon_interval': 100,
            },
            {
                'ssid': 'GuestWiFi',
                'bssid': 'aa:bb:cc:dd:ee:02',
                'channel': 11,
                'frequency': WIFI_CHANNELS_2GHZ.get(11, 2462),
                'signal_dbm': -72,
                'encryption': 'WPA2',
                'cipher': 'AES',
                'auth': 'PSK',
                'band': '2.4GHz',
                'wps_enabled': True,
                'hidden': False,
                'beacon_interval': 100,
            },
            {
                'ssid': 'Legacy-WiFi',
                'bssid': 'aa:bb:cc:dd:ee:03',
                'channel': 1,
                'frequency': WIFI_CHANNELS_2GHZ.get(1, 2412),
                'signal_dbm': -80,
                'encryption': 'WEP',
                'cipher': 'WEP-40',
                'auth': 'Shared',
                'band': '2.4GHz',
                'wps_enabled': False,
                'hidden': False,
                'beacon_interval': 100,
            },
        ]

    def _analyze_wifi_security(self, network: Dict) -> Dict:
        """Analyze security posture of a WiFi network."""
        encryption = network.get('encryption', 'OPEN')
        wps_enabled = network.get('wps_enabled', False)
        hidden = network.get('hidden', False)

        security = ENCRYPTION_SECURITY.get(encryption, ENCRYPTION_SECURITY['OPEN']).copy()
        issues = []
        recommendations = []

        # Check encryption
        if encryption == 'WEP':
            issues.append({
                'severity': 'critical',
                'issue': 'WEP encryption is completely broken',
                'cve': 'CVE-2001-0160',
                'recommendation': 'Upgrade to WPA2 or WPA3 immediately',
            })
        elif encryption == 'WPA':
            issues.append({
                'severity': 'high',
                'issue': 'WPA-TKIP is vulnerable to attacks',
                'recommendation': 'Upgrade to WPA2 or WPA3',
            })
        elif encryption == 'OPEN':
            issues.append({
                'severity': 'critical',
                'issue': 'No encryption - all traffic is visible',
                'recommendation': 'Enable WPA2 or WPA3 encryption',
            })

        # Check WPS
        if wps_enabled:
            issues.append({
                'severity': 'high',
                'issue': 'WPS is enabled - vulnerable to Pixie Dust and brute force attacks',
                'cve': 'CVE-2011-5053',
                'recommendation': 'Disable WPS immediately',
            })

        # Hidden SSID
        if hidden:
            issues.append({
                'severity': 'low',
                'issue': 'Hidden SSID provides minimal security by obscurity',
                'recommendation': 'Hidden SSID is not a security measure - rely on proper encryption',
            })

        # Channel analysis
        channel = network.get('channel', 0)
        overlapping_channels = self._check_channel_overlap(channel, network.get('band', '2.4GHz'))
        if overlapping_channels:
            recommendations.append(f'Channel {channel} overlaps with channels {overlapping_channels} - consider using non-overlapping channels')

        security['issues'] = issues
        security['recommendations'] = recommendations

        return security

    def _check_channel_overlap(self, channel: int, band: str) -> List[int]:
        """Check for channel overlap with neighboring channels."""
        overlapping = []
        if band == '2.4GHz':
            # 2.4GHz channels overlap (each occupies 22MHz, channels are 5MHz apart)
            for other in WIFI_CHANNELS_2GHZ:
                if other != channel and abs(other - channel) < 5:
                    overlapping.append(other)
        return overlapping

    def _assess_wifi_risk(self, network: Dict) -> str:
        """Assess overall risk level of a WiFi network."""
        encryption = network.get('encryption', 'OPEN')
        wps = network.get('wps_enabled', False)

        if encryption in ['WEP', 'OPEN']:
            return 'critical'
        elif encryption == 'WPA' or wps:
            return 'high'
        elif encryption == 'WPA2' and not wps:
            return 'medium'
        elif encryption in ['WPA2-EAP', 'WPA3']:
            return 'low'
        return 'unknown'

    def _lookup_ap_vendor(self, bssid: str) -> str:
        """Look up AP vendor from BSSID."""
        if not bssid:
            return 'Unknown'
        prefix = ':'.join(bssid.lower().split(':')[:3])
        return AP_VENDORS.get(prefix, 'Unknown Vendor')

    def detect_rogue_access_points(self, known_networks: List[Dict]) -> List[Dict]:
        """
        Detect rogue and evil twin access points.

        Args:
            known_networks: List of known legitimate networks

        Returns:
            List of suspected rogue APs
        """
        rogues = []

        known_ssids = {n.get('ssid', ''): n for n in known_networks}
        known_bssids = {n.get('bssid', ''): n for n in known_networks}

        for network in self.discovered_networks:
            ssid = network.get('ssid', '')
            bssid = network.get('bssid', '')

            # Check for evil twin (same SSID, different BSSID)
            if ssid in known_ssids and bssid not in known_bssids:
                rogues.append({
                    'type': 'evil_twin',
                    'severity': 'critical',
                    'ssid': ssid,
                    'rogue_bssid': bssid,
                    'legitimate_bssid': known_ssids[ssid].get('bssid'),
                    'description': f'Possible evil twin AP detected: {ssid} with unknown BSSID',
                    'recommendation': 'Investigate immediately - this may be a man-in-the-middle attack',
                })

            # Check for honeypot indicators
            for indicator in ROGUE_AP_INDICATORS:
                if indicator.lower() in ssid.lower():
                    rogues.append({
                        'type': 'honeypot_indicator',
                        'severity': 'medium',
                        'ssid': ssid,
                        'bssid': bssid,
                        'description': f'AP "{ssid}" may be a honeypot or rogue AP',
                        'recommendation': 'Verify network legitimacy before connecting',
                    })
                    break

        self.rogues = rogues
        return rogues

    def enumerate_clients(self) -> List[Dict]:
        """
        Enumerate connected wireless clients.

        Returns:
            List of detected client devices
        """
        clients = []

        # In production, would capture probe requests and data frames
        # Simulated client enumeration
        for ap in self.discovered_networks[:3]:
            num_clients = random.randint(1, 5)
            for _ in range(num_clients):
                mac = self._generate_random_mac()
                client = {
                    'mac': mac,
                    'associated_bssid': ap.get('bssid', ''),
                    'associated_ssid': ap.get('ssid', ''),
                    'signal_dbm': random.randint(-80, -50),
                    'probe_requests': self._simulate_probe_requests(),
                    'vendor': 'Unknown',
                    'device_type': self._fingerprint_device(mac),
                    'last_seen': datetime.utcnow().isoformat(),
                }
                clients.append(client)

        self.clients = clients
        return clients

    def _simulate_probe_requests(self) -> List[str]:
        """Simulate probe request SSIDs from a client device."""
        common_ssids = [
            'HomeNetwork', 'CoffeeShopWiFi', 'iPhone', 'AndroidAP',
            'NETGEAR', 'linksys', 'Starbucks',
        ]
        count = random.randint(0, 4)
        return random.sample(common_ssids, min(count, len(common_ssids)))

    def _fingerprint_device(self, mac: str) -> str:
        """Fingerprint device type from MAC address."""
        if not mac:
            return 'unknown'
        prefix = ':'.join(mac.lower().split(':')[:3])
        vendor = AP_VENDORS.get(prefix, '')
        if vendor:
            if 'Apple' in vendor:
                return 'mobile_apple'
            if 'Samsung' in vendor:
                return 'mobile_android'
            if 'Cisco' in vendor or 'Aruba' in vendor:
                return 'network_equipment'
        return 'unknown'

    def analyze_wps(self, networks: List[Dict]) -> List[Dict]:
        """
        Analyze WPS configuration for vulnerabilities.

        Args:
            networks: List of WiFi networks to analyze

        Returns:
            WPS vulnerability findings
        """
        findings = []
        for network in networks:
            if network.get('wps_enabled'):
                finding = {
                    'ssid': network.get('ssid'),
                    'bssid': network.get('bssid'),
                    'wps_version': network.get('wps_version', '2.0'),
                    'vulnerabilities': [],
                }

                # Check WPS PIN attack vulnerability
                finding['vulnerabilities'].append({
                    'type': 'wps_pin_attack',
                    'cve': 'CVE-2011-5053',
                    'severity': 'high',
                    'description': 'WPS PIN brute force attack possible (Reaver/Bully tools)',
                    'remediation': 'Disable WPS in router settings',
                })

                # Check Pixie Dust attack
                finding['vulnerabilities'].append({
                    'type': 'pixie_dust',
                    'cve': 'CVE-2014-9527',
                    'severity': 'critical',
                    'description': 'Pixie Dust attack may allow PIN recovery in seconds',
                    'remediation': 'Disable WPS in router settings',
                })

                findings.append(finding)

        return findings

    def scan_bluetooth(self) -> List[Dict]:
        """
        Scan for Bluetooth devices.

        Returns:
            List of discovered Bluetooth devices
        """
        devices = []

        # Simulate Bluetooth device discovery
        simulated_devices = [
            {
                'address': 'AA:BB:CC:DD:EE:01',
                'name': 'Wireless Headset',
                'device_class': '0x240404',
                'rssi': -65,
                'paired': False,
                'connectable': True,
                'ble': False,
                'services': ['0x1108', '0x111e'],  # Headset/Handsfree profiles
                'manufacturer': 'Unknown',
            },
            {
                'address': 'AA:BB:CC:DD:EE:02',
                'name': 'SmartWatch',
                'device_class': '0x000000',
                'rssi': -72,
                'paired': False,
                'connectable': True,
                'ble': True,
                'services': [BLE_SERVICES.get(k, k) for k in ['180d', '180a', '180f']],
                'manufacturer': 'Unknown',
            },
        ]

        for device in simulated_devices:
            device['vulnerabilities'] = self._assess_bluetooth_vulnerabilities(device)
            devices.append(device)

        self.bluetooth_devices = devices
        return devices

    def _assess_bluetooth_vulnerabilities(self, device: Dict) -> List[Dict]:
        """Assess Bluetooth device vulnerabilities."""
        vulns = []

        # Bluetooth Classic vulnerabilities
        if not device.get('ble'):
            vulns.append({
                'type': 'bluejacking',
                'severity': 'low',
                'description': 'Device may be vulnerable to Bluejacking (unsolicited messages)',
                'recommendation': 'Keep device non-discoverable when not pairing',
            })

        # BLE vulnerabilities
        if device.get('ble'):
            vulns.append({
                'type': 'ble_eavesdropping',
                'severity': 'medium',
                'description': 'BLE traffic may be interceptable without LE Secure Connections',
                'recommendation': 'Use LE Secure Connections and BLE 4.2+',
            })

            # Check for vulnerable BLE services
            services = device.get('services', [])
            if 'Heart Rate' in services or '180d' in str(services):
                vulns.append({
                    'type': 'medical_data_exposure',
                    'severity': 'high',
                    'description': 'Health sensor data may be accessible without proper authentication',
                    'recommendation': 'Verify BLE pairing requirements for health data access',
                })

        # Check for BlueBorne vulnerability
        vulns.append({
            'type': 'blueborne',
            'cve': 'CVE-2017-0785',
            'severity': 'critical',
            'description': 'Device may be vulnerable to BlueBorne remote code execution',
            'recommendation': 'Apply all security patches and keep Bluetooth disabled when not in use',
        })

        return vulns

    def analyze_spectrum(self) -> Dict:
        """
        Analyze RF spectrum for channel utilization and interference.

        Returns:
            Spectrum analysis results
        """
        analysis = {
            'band_2ghz': {
                'channels': {},
                'congestion': {},
                'recommendations': [],
            },
            'band_5ghz': {
                'channels': {},
                'congestion': {},
                'recommendations': [],
            },
        }

        # Analyze 2.4GHz band
        channel_utilization = {}
        for network in self.discovered_networks:
            channel = network.get('channel', 0)
            band = network.get('band', '2.4GHz')

            if band == '2.4GHz' and 1 <= channel <= 14:
                channel_utilization[channel] = channel_utilization.get(channel, 0) + 1

        analysis['band_2ghz']['channels'] = channel_utilization

        # Find least congested channels
        if channel_utilization:
            best_channels = sorted(channel_utilization.keys(), key=lambda c: channel_utilization.get(c, 0))
            # Non-overlapping channels: 1, 6, 11
            for ch in [1, 6, 11]:
                if ch not in channel_utilization or channel_utilization[ch] == 0:
                    analysis['band_2ghz']['recommendations'].append(
                        f'Channel {ch} is available - consider migrating APs to reduce interference'
                    )
                    break
        else:
            analysis['band_2ghz']['recommendations'].append('No 2.4GHz networks detected')

        return analysis

    def _generate_random_mac(self) -> str:
        """Generate a random MAC address."""
        mac_bytes = [random.randint(0, 255) for _ in range(6)]
        return ':'.join(f'{b:02x}' for b in mac_bytes)
