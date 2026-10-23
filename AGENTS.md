# AGENTS.md

## Core Principles

- Inspect the existing repository before changing anything. Preserve working features and architecture.
- Make the best decisions to elevate user experience (UX), developer experience (DX), and agent experience (AX), without breaking anything.
- Prefer simple, modular, production-ready solutions over unnecessary abstraction.
- Cut taglines, helper text, and secondary labels. If a screen needs them to make sense, fix the layout.
- Keep interfaces clean, information-dense, consistent, and functional.
- No fake data, simulated success, fabricated results, or unsupported claims.
- Make security decisions explicit, validate all inputs, and enforce authorization at tool boundaries.
- Keep new integrations configurable and easy to extend.

## Engineering Rules

- Read existing code and conventions before implementing.
- Reuse existing components, services, schemas, and utilities wherever possible.
- Avoid unnecessary rewrites, duplicate logic, breaking API changes, and destructive migrations.
- Keep secrets in environment variables; never commit credentials.
- Handle errors, loading states, empty states, timeouts, and unavailable dependencies properly.
- Add tests for new behavior and run relevant existing tests.
- Update documentation and `.env.example` when configuration changes.
- Never claim a feature or test works without verifying it.

## RAG & Research

- Keep ingestion, chunking, embeddings, retrieval, reranking, generation, tool calling, and evaluation modular.
- Preserve source provenance and enforce evidence-backed answers with citations.
- Keep labelled datasets, development data, and held-out evaluation data separate.
- Make experiments reproducible; record configurations, versions, metrics, and failures.
- Never tune thresholds on held-out test data or fabricate benchmark results.
- Keep security tools scoped, authorized, validated, and auditable.

## Execution

- Implement working code, not just plans or pseudocode.
- Prefer complete vertical slices over disconnected scaffolding.
- Verify backward compatibility and existing workflows after changes.
- Report what changed, what was tested, what failed, and what remains unconfigured.
- When uncertain, inspect the code and available evidence before making assumptions.
