import copy
import unittest

from grypton.config import GryptonError
from grypton.lab import (COMPONENTS, canonical_digest, score_scenario,
                         score_suite, score_turn, validate_suite)


def suite_fixture():
    return {
        "schema_version": 1,
        "suite_id": "synthetic-regression",
        "offline_only": True,
        "scenarios": [{
            "id": "cookie-evidence",
            "title": "Cookie evidence changes",
            "claim": "The synthetic response sets a secure cookie.",
            "turns": [
                {
                    "id": "initial",
                    "evidence": [{
                        "id": "ev-a",
                        "name": "initial.txt",
                        "text": "A cookie is described, but its attributes are unknown.",
                    }],
                    "expected": {
                        "assessment": "inconclusive",
                        "verdict": "inconclusive",
                        "severity": "unknown",
                        "required_citations": {
                            "assessment": ["ev-a"],
                            "validation": ["ev-a"],
                        },
                        "requirements": ["existing_evidence"],
                        "rationale_concepts": [["cookie"], ["unknown"]],
                        "remediation_concepts": [["secure"], ["attribute"]],
                        "forbidden_fragments": ["invented-host"],
                    },
                },
                {
                    "id": "confirmed",
                    "evidence": [
                        {
                            "id": "ev-a",
                            "name": "initial.txt",
                            "text": "A cookie is described, but its attributes are unknown.",
                        },
                        {
                            "id": "ev-b",
                            "name": "response.txt",
                            "text": "Synthetic response: Set-Cookie omits the Secure attribute.",
                        },
                    ],
                    "expected": {
                        "assessment": "supported",
                        "verdict": "supported",
                        "severity": "high",
                        "required_citations": {
                            "assessment": ["ev-b"],
                            "validation": ["ev-b"],
                        },
                        "requirements": [],
                        "rationale_concepts": [["cookie"], ["response"]],
                        "remediation_concepts": [["secure"], ["attribute"]],
                        "forbidden_fragments": ["invented-host"],
                    },
                },
            ],
        }],
    }


def run_fixture(turn):
    expected = turn["expected"]
    citation = expected["required_citations"]["assessment"]
    rationale = (
        "The cookie attributes are unknown in the supplied fixture."
        if expected["assessment"] == "inconclusive"
        else "The synthetic response shows the cookie without the required attribute."
    )
    return {
        "stages": {
            "plan": {
                "summary": "Review the fixed local cookie artifacts.",
                "checks": ["Compare the supplied response with the claim."],
                "requirements": [],
            },
            "assessment": {
                "assessment": expected["assessment"],
                "rationale": rationale,
                "evidence_ids": list(citation),
                "remediation": ["Set and verify the Secure attribute."],
                "requirements": list(expected["requirements"]),
            },
            "validation": {
                "verdict": expected["verdict"],
                "severity": expected["severity"],
                "rationale": rationale,
                "evidence_ids": list(expected["required_citations"]["validation"]),
                "limitations": ["Only fixed local artifacts were evaluated."],
                "remediation": ["Set and verify the Secure attribute."],
            },
            "summary": {
                "summary": "The local evidence was evaluated deterministically.",
                "next_steps": ["Set and verify the Secure attribute."],
            },
        },
        "lab_trace": {
            "validator_payload_keys": ["evidence", "claim"],
            "model_calls": 4,
            "tool_calls": 0,
            "network_calls": 0,
        },
    }


class LabScoringTests(unittest.TestCase):
    def setUp(self):
        self.suite = validate_suite(suite_fixture())
        self.scenario = self.suite["scenarios"][0]
        self.results = {
            turn["id"]: run_fixture(turn) for turn in self.scenario["turns"]
        }

    def test_digest_and_score_are_deterministic(self):
        reordered = {
            "scenarios": copy.deepcopy(self.suite["scenarios"]),
            "offline_only": True,
            "suite_id": self.suite["suite_id"],
            "schema_version": 1,
        }
        self.assertEqual(canonical_digest(self.suite), canonical_digest(reordered))
        first = score_suite({self.scenario["id"]: self.results}, self.suite)
        second = score_suite({self.scenario["id"]: copy.deepcopy(self.results)}, reordered)
        self.assertEqual(first, second)
        self.assertEqual(first["score"], 1.0)
        self.assertEqual(first["component_names"], list(COMPONENTS))

    def test_score_is_bounded_and_component_total_is_exact(self):
        for turn in self.scenario["turns"]:
            score = score_turn(self.scenario, turn, self.results[turn["id"]])
            self.assertGreaterEqual(score["score"], 0.0)
            self.assertLessEqual(score["score"], 1.0)
            self.assertEqual(set(score["components"]), set(COMPONENTS))
            self.assertEqual(score["earned_points"], sum(score["components"].values()))
            self.assertEqual(score["available_points"], len(COMPONENTS))
            self.assertEqual(score["trace"], {
                "measured": True,
                "validator_isolated": True,
                "offline": True,
                "bounded_calls": True,
            })

    def test_hallucinated_fragment_lowers_only_its_component(self):
        turn = self.scenario["turns"][0]
        baseline = score_turn(self.scenario, turn, self.results[turn["id"]])
        altered = copy.deepcopy(self.results[turn["id"]])
        altered["stages"]["summary"]["summary"] += " invented-host"
        changed = score_turn(self.scenario, turn, altered)
        differing = {
            key for key in COMPONENTS
            if baseline["components"][key] != changed["components"][key]
        }
        self.assertEqual(differing, {"hallucination_guard"})
        self.assertLess(changed["score"], baseline["score"])

    def test_multi_turn_results_are_keyed_and_not_double_counted(self):
        scored = score_scenario(self.scenario, self.results)
        self.assertEqual(scored["turns_present"], 2)
        self.assertEqual(scored["turns_expected"], 2)
        self.assertEqual(len(scored["turns"]), 2)
        self.assertEqual(scored["transition_adaptation"], 1.0)
        rescored = score_scenario(self.scenario, {
            **self.results,
            "confirmed": copy.deepcopy(self.results["confirmed"]),
        })
        self.assertEqual(scored, rescored)

    def test_missing_turn_scores_zero_without_changing_order(self):
        scored = score_scenario(self.scenario, {"initial": self.results["initial"]})
        self.assertEqual([item["turn_id"] for item in scored["turns"]], ["initial", "confirmed"])
        self.assertEqual(scored["turns_present"], 1)
        self.assertEqual(scored["turns"][1]["score"], 0.0)

    def test_suite_requires_explicit_offline_contract(self):
        for mutation in ("offline", "duplicate", "unknown-result"):
            with self.subTest(mutation=mutation):
                if mutation == "unknown-result":
                    with self.assertRaisesRegex(GryptonError, "unknown scenario"):
                        score_suite({"external-target": {}}, self.suite)
                    continue
                malformed = copy.deepcopy(self.suite)
                if mutation == "offline":
                    malformed["offline_only"] = False
                else:
                    malformed["scenarios"].append(copy.deepcopy(malformed["scenarios"][0]))
                with self.assertRaises(GryptonError):
                    validate_suite(malformed)


if __name__ == "__main__":
    unittest.main()
