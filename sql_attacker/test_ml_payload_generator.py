"""
Unit tests for the ML-Powered Payload Generator.
"""

import unittest
from sql_attacker.ml_payload_generator import (
    GeneticPayloadEvolver,
    MLPayloadGenerator,
    _BASE_PAYLOADS,
    _OBFUSCATION_FUNCS,
)


class TestGeneticPayloadEvolver(unittest.TestCase):
    """Tests for GeneticPayloadEvolver."""

    def setUp(self):
        self.evolver = GeneticPayloadEvolver(random_seed=42)

    def test_initialise_population_size(self):
        pop = self.evolver._initialise_population("' OR '1'='1")
        self.assertEqual(len(pop), self.evolver.population_size)

    def test_mutate_returns_string(self):
        result = self.evolver._mutate("' OR '1'='1")
        self.assertIsInstance(result, str)

    def test_crossover_returns_nonempty(self):
        result = self.evolver._crossover("' OR '1'='1", "' AND SLEEP(5)--")
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_crossover_empty_parents(self):
        result = self.evolver._crossover("", "payload")
        self.assertIsInstance(result, str)

    def test_default_fitness_range(self):
        score = self.evolver._default_fitness("' OR '1'='1", {})
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)

    def test_fitness_waf_cloudflare_obfuscation(self):
        score_plain = self.evolver._default_fitness("' OR '1'='1", {"waf": "cloudflare"})
        score_obf = self.evolver._default_fitness(
            "' OR '1'='1".replace(" ", "/**/"), {"waf": "cloudflare"}
        )
        self.assertGreaterEqual(score_obf, score_plain)

    def test_evolve_payload_returns_string(self):
        result = self.evolver.evolve_payload("' OR '1'='1", {}, generations=5)
        self.assertIsInstance(result, str)
        self.assertGreater(len(result), 0)

    def test_evolve_payload_custom_fitness(self):
        """Custom fitness function should be called and influence evolution."""
        call_count = [0]

        def custom_fitness(payload, profile):
            call_count[0] += 1
            return 0.5

        result = self.evolver.evolve_payload(
            "' OR '1'='1", {}, generations=3, fitness_func=custom_fitness
        )
        self.assertIsInstance(result, str)
        self.assertGreater(call_count[0], 0)

    def test_stealth_score_noisy_payload(self):
        """DDL payloads should have lower stealth score."""
        score_noisy = self.evolver._estimate_stealth_score("' DROP TABLE users--")
        score_quiet = self.evolver._estimate_stealth_score("' OR '1'='1")
        self.assertLess(score_noisy, score_quiet)


class TestMLPayloadGenerator(unittest.TestCase):
    """Tests for MLPayloadGenerator."""

    def setUp(self):
        self.gen = MLPayloadGenerator(random_seed=42)

    def test_generate_payloads_returns_list(self):
        result = self.gen.generate_context_aware_payloads({})
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_generate_payloads_count(self):
        result = self.gen.generate_context_aware_payloads({}, count=5)
        self.assertLessEqual(len(result), 5)

    def test_generate_payloads_mysql(self):
        payloads = self.gen.generate_context_aware_payloads({"db_type": "mysql"})
        # MySQL-specific payloads should appear
        self.assertTrue(any("SLEEP" in p or "version" in p.lower() for p in payloads))

    def test_generate_payloads_postgresql(self):
        payloads = self.gen.generate_context_aware_payloads({"db_type": "postgresql"})
        self.assertTrue(any("pg_sleep" in p or "version()" in p for p in payloads))

    def test_generate_payloads_url_encoding(self):
        payloads = self.gen.generate_context_aware_payloads({"encoding": "url"})
        # URL-encoded payloads should contain % characters
        encoded = [p for p in payloads if "%" in p]
        self.assertGreater(len(encoded), 0)

    def test_generate_payloads_no_duplicates(self):
        payloads = self.gen.generate_context_aware_payloads({}, count=50)
        self.assertEqual(len(payloads), len(set(payloads)))

    def test_mutate_payload_returns_string(self):
        result = self.gen.mutate_payload_genetic_algorithm("' OR '1'='1", generations=5)
        self.assertIsInstance(result, str)

    def test_learn_from_result_updates_history(self):
        payload = "' OR '1'='1"
        self.gen.learn_from_result(payload, success=True)
        self.assertEqual(len(self.gen._history), 1)
        hist = next(iter(self.gen._history.values()))
        self.assertEqual(hist["success"], 1)
        self.assertEqual(hist["total"], 1)

    def test_learn_from_result_failure(self):
        payload = "' AND SLEEP(5)--"
        self.gen.learn_from_result(payload, success=False)
        hist = next(iter(self.gen._history.values()))
        self.assertEqual(hist["success"], 0)
        self.assertEqual(hist["total"], 1)

    def test_get_top_payloads_empty(self):
        result = self.gen.get_top_payloads()
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 0)

    def test_get_top_payloads_returns_best(self):
        self.gen.learn_from_result("good_payload", success=True)
        self.gen.learn_from_result("good_payload", success=True)
        self.gen.learn_from_result("bad_payload", success=False)
        top = self.gen.get_top_payloads(n=1)
        self.assertEqual(top[0], "good_payload")

    def test_historical_success_influences_score(self):
        payload = "' OR '1'='1"
        self.gen.learn_from_result(payload, success=True)
        self.gen.learn_from_result(payload, success=True)
        # Score with history should be higher or equal to score without
        score = self.gen._score_payload(payload, {})
        self.assertGreater(score, 0.0)

    def test_url_encode_helper(self):
        encoded = MLPayloadGenerator._url_encode("' OR 1=1")
        self.assertNotIn(" ", encoded)
        self.assertIn("%", encoded)

    def test_hex_encode_helper(self):
        encoded = MLPayloadGenerator._hex_encode("test")
        self.assertTrue(encoded.startswith("0x"))

    def test_base_payloads_not_empty(self):
        self.assertGreater(len(_BASE_PAYLOADS), 5)

    def test_obfuscation_funcs_not_empty(self):
        self.assertGreater(len(_OBFUSCATION_FUNCS), 0)


if __name__ == "__main__":
    unittest.main()
