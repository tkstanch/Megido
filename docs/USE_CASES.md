# Megido Security Research Use Cases

> Use Megido only against systems you own or systems where you have explicit authorization to test.

## 1) Web Application Vulnerability Scanning

**Scenario:** A researcher needs broad coverage of common web application weaknesses.

**How Megido helps:** Provides scanner-driven workflows to probe endpoints, parameters, and response behavior.

**Suggested workflow:**
1. Define authorized scope and targets.
2. Run initial scan with safe defaults.
3. Review findings and confidence signals.
4. Validate high-impact findings manually before reporting.

## 2) API Authentication Testing

**Scenario:** A team wants to assess auth/session robustness in API endpoints.

**How Megido helps:** Supports auth-focused testing workflows and request manipulation to evaluate session handling and access controls.

**Suggested workflow:**
1. Capture baseline authenticated and unauthenticated requests.
2. Run auth-focused checks across relevant endpoints.
3. Compare expected authorization boundaries vs observed behavior.
4. Document reproducible evidence for confirmed gaps.

## 3) Mobile Application Analysis

**Scenario:** A researcher assesses mobile backend/API behavior and hybrid app traffic patterns.

**How Megido helps:** Supports web/mobile-oriented testing components and interception-style workflows in controlled labs.

**Suggested workflow:**
1. Prepare a legal lab environment and test account data.
2. Route mobile/hybrid traffic through authorized test tooling.
3. Evaluate API behavior, auth controls, and error handling.
4. Record confirmed findings with sanitized artifacts.

## 4) Custom Attack Automation

**Scenario:** A security engineer needs repeatable attack sequences for regression testing.

**How Megido helps:** Enables custom attack automation so researchers can encode and replay validated testing strategies.

**Suggested workflow:**
1. Define the attack hypothesis and safety constraints.
2. Build a module/workflow for repeatable execution.
3. Run against staging/lab targets.
4. Iterate based on false positive/negative outcomes.

## 5) Source Code Analysis for Security Signals

**Scenario:** During secure code review, a researcher wants to correlate static clues with runtime behavior.

**How Megido helps:** Supports source-analysis-oriented workflows and documentation-driven triage for suspicious patterns.

**Suggested workflow:**
1. Identify high-risk code paths.
2. Correlate potential weaknesses with runtime probes.
3. Validate exploitability in a controlled environment.
4. Submit actionable findings and fixes.

## 6) Threat Simulation in Lab Environments

**Scenario:** A team wants to validate controls using realistic but safe attack simulations.

**How Megido helps:** Supports controlled threat simulation and evidence-driven testing processes.

**Suggested workflow:**
1. Define simulation objectives and guardrails.
2. Execute targeted scenarios in an isolated environment.
3. Measure detection/response outcomes.
4. Use results to improve defensive controls and secure defaults.
