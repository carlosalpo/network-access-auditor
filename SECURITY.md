# Security and privacy boundaries

Network Access Auditor is a defensive offline review tool. It does not scan networks, contact ISE, perform authentication, exploit systems, modify devices or generate executable remediation commands. Runtime dependencies are limited to Python's standard library. Installation and CI can access package registries; the example runner launches the installed local CLI.

The parser bounds input size, collections and text fields, and rejects unknown keys, duplicate keys/IDs, broken references, unsupported expressions and non-finite numbers. It does not evaluate templates, Python expressions, YAML objects or native ISE payloads. Risk analysis is bounded to at most 198 modeled states and 128 rules.

The model is not a sandbox for arbitrary network configurations. Group trust, profile classifications, observations, exception ownership and provenance are supplied by the reviewer. Misclassification or omitted conditions can produce misleading conclusions. No findings does not establish security, compliance, successful authentication or enforced segmentation.

Inputs and outputs are **not anonymized**. Labels, evidence references and exception owner/reason fields can disclose sensitive information. Use aliases and public synthetic data in GitHub issues or contributions. Do not include credentials, tokens, client names, real identity inventories or private policy exports. The examples contain no MAC addresses or device credentials.

Outputs have restrictive requested POSIX permissions, fixed filenames and escaped text. Spreadsheet formula prefixes are guarded with a leading apostrophe; use JSON for exact machine-readable values. The tool assumes a trusted local filesystem and does not protect against hostile races replacing output paths. An unsigned hash manifest proves consistency only against a trusted reference, not authenticity.

For sensitive issue reports, use private maintainer contact options on GitHub when available. Public issues should contain only synthetic reproductions.
