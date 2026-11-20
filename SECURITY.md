# Security policy

Please report suspected vulnerabilities privately to tech@ernestowendling.ch rather than in a
public issue. Include the affected component, steps to reproduce and the impact you observed.
Reports are acknowledged within five working days.

This repository is a reference implementation operating on synthetic data. It contains no
credentials; the optional AWS Bedrock adapter reads credentials from the standard AWS provider
chain at runtime only.
