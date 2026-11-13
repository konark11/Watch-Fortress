# Product <!-- impeccable:product-schema 1 -->

## Platform
web

## Users
- **Internal Enterprise SecOps & SOC Teams**: Primary users operating in high-security, regulated, or air-gapped enterprise environments. They manage threat exposure, triage multi-scanner findings, track remediation, and monitor authentication anomalies.
- **Security Analysts & Penetration Testers**: Launch targeted scans (Nmap, Nuclei) or import commercial scanner reports (Nessus, OpenVAS), investigate CVE-to-ATT&CK chains, and generate technical remediation workflows.
- **Auditors & Compliance Officers**: Require read-only access to verify security posture, inspect structured audit logs, and export multi-format compliance reports (PDF, HTML, DOCX, JSON).
- **System Administrators**: Manage RBAC permissions, system health, and scheduling without cloud external dependencies.

## Product Purpose
Watch Fortress is an on-premises, unified vulnerability assessment and correlation platform. It consolidates heterogeneous scanner outputs into a single deduplicated risk landscape, maps exposures to standardized MITRE ATT&CK/CWE/CAPEC/KEV taxonomies, correlates security audit events, and provides evidence-backed remediation assistance—operating reliably with or without internet connectivity. Success means eliminating alert fatigue and duplicate findings while enabling fast, traceable triage and verified remediation in air-gapped environments.

## Positioning
A truly air-gapped, zero-cloud vulnerability management console that performs deterministic cross-scanner correlation (merging duplicate findings from Nmap, Nessus, OpenVAS, and Nuclei) and complete offline CVE/CWE/ATT&CK intelligence without external API calls or telemetry dependencies.

## Operating Context
- **Deployment Environments**: Air-gapped networks, private corporate clouds, sovereign infrastructure, or isolated SOC testing labs.
- **Operator Workflows**: Running automated or ad-hoc vulnerability scans, importing third-party `.nessus` and `.xml` scan reports, inspecting correlated vulnerability graphs, analyzing login failure bursts, and exporting audit reports for leadership.
- **Key Artifacts & Protocols**: Nmap XML, Nessus v2 XML, OpenVAS GMP XML, Nuclei JSONL, CISA Known Exploited Vulnerabilities (KEV), MITRE ATT&CK techniques, and structured `auth.login_failed` audit events.

## Capabilities and Constraints
- **Multi-Scanner Ingestion**: Live execution of Nmap and Nuclei; native API clients for OpenVAS (GMP protocol) and Nessus (REST API); generic CSV/JSON import parsers.
- **Correlation & Risk Engine**: Deterministic deduplication across scanners with transparent multi-factor scoring (CVSS, cross-scanner corroboration, exploit availability, CISA KEV presence).
- **Offline Intelligence Engine**: Zero-network mapping from CVEs to CWE, CAPEC, MITRE ATT&CK, OWASP, and CISA KEV.
- **Pluggable Assistant & RAG**: Built-in TF-IDF retrieval + template synthesis (zero dependencies, fully offline), with optional local Ollama, OpenRouter, or OpenAI-compatible backends for connected environments.
- **Reporting & Scheduling**: Multi-format reporting (PDF via ReportLab, HTML via Jinja2, DOCX, JSON) and in-process cron/interval scheduling via APScheduler.
- **RBAC & Auditing**: Strict 4-tier role-based access control (Administrator, Security Analyst, Penetration Tester, Auditor) backed by structured audit logs.
- **Architectural Scope Limits**: Uses SQLite (default) and PostgreSQL; does not use Elasticsearch. Task scheduling is in-process (no Celery/Redis fleet dependencies). Embeddings use offline TF-IDF rather than online HuggingFace/SentenceTransformers models to preserve air-gap portability.

## Brand Commitments
- **Name**: Watch Fortress.
- **Tone & Persona**: Calm, precise, and considered instrument—crafted like a high-grade technical tool (Linear, Grafana) rather than a sci-fi hacker HUD. Professional, quiet, and confident without glowing borders, neon glare, or generic AI dashboard slop.
- **Visual Identity**: Warm neutral graphite canvas (`#121316` / `#18191d`), separated by 1px hairline dividers (`rgba(255, 255, 255, 0.08)`), consistent 5px corner radii, and flat surfaces stepping up by lightness rather than stacked bordered boxes. Off-white typography (`#eceae5`) with clear secondary (`#9c9b96`) and tertiary (`#686763`) tiers meeting WCAG AA.
- **Restrained Single Accent**: A muted sand/amber (`#c49547`) used solely for primary actions, 2px solid active nav indicators, and focus states—never with outer halos, glows, or colored drop shadows.
- **Severity Isolation**: Desaturated severity indicators (Critical: `#c85a54`, High: `#d97736`, Medium: `#c99738`, Low: `#5a949b`, Info: `#787f8a`) used exclusively for real finding states (small 6px dots, tabular counts, hairline left bars), never as decorative pill capsules or general UI accents.
- **Typography**: Single clean UI sans-serif for interface text, reserving monospace strictly for actual data (IPs, ports, CIDRs, hashes, timestamps, and CVE IDs).

## Evidence on Hand
- **Sample Scans**: Real and realistic scan artifacts available in `sample_scans/` (`sample_nmap.xml`, `sample_nessus.nessus`, `sample_openvas.xml`, `sample_nuclei.jsonl`).
- **Offline Intelligence Data**: Curated local vulnerability databases in `backend/knowledge/` covering CVEs, CWEs, CAPEC, MITRE ATT&CK techniques, and CISA KEV.
- **Air-Gap Bundle Script**: `build_portable.sh` generating standalone Docker images, pip wheel cache, and template snapshots.
- **Absences & Non-Claims**: No synthetic scan results; unconfigured integrations (e.g., unset OpenVAS/Nessus credentials) explicitly report as "not configured" rather than simulating output.

## Product Principles
1. **Honesty Over Simulation**: Never fabricate scan output, fake connection success, or simulate AI results; unconfigured services explicitly report unavailable.
2. **Air-Gap as a First-Class Citizen**: Every core capability—from scan parsing and cross-scanner correlation to taxonomy mapping and RAG triage—functions reliably with zero internet connection.
3. **Deterministic, Traceable Risk**: Findings, scores, and correlations are fully reproducible, component-transparent, and tied directly to verified scanner evidence.
4. **Information-Dense, Low-Noise UI**: Designed for operational efficiency with clean visual hierarchy, keyboard friendliness, and zero decorative bloat or condescending helper text.
5. **Evidence-Backed Intelligence**: AI and analytical outputs cite explicit CVE mappings, audit records, or vulnerability evidence without generative hallucinations.

## Accessibility & Inclusion
- High contrast compliant dark theme with distinct luminosity levels between interactive surfaces, typography, and status badges.
- Strict chromatic separation: Severity cues are accompanied by textual labels and icons to ensure legibility across color-vision deficiencies.
