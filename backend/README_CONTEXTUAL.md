Contextual PII filter (local embedding/LLM)

This folder contains additions to enable a local, fast embedding-based contextual
post-filter for the PII detection pipeline in `pii_engine.py`.

Quick start (CPU):

1. Create and activate a virtualenv:

```bash
cd /data01/xcn-pii-new/backend
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -r requirements.txt
```

2. Run the demo script (loads `jhgan/ko-sbert-multitask` and runs the filter):

```bash
python app/test_context_filter.py
```

Using the contextual filter in the pipeline

- In your ruleset (located under `app/rules/<ruleset_name>`), add a `context` document and include the `post_context` step in `steps`.

Example rules (add to your ruleset's ruleset file or `context` doc):

```yaml
# in your rules docs (example file: app/rules/default/context.yaml)
context:
  enabled: true
  method: embed    # eembede for sentence-transformers semantic filter, ekeyworde for simple keywords
  model_name: jhgan/ko-sbert-multitask
  sim_threshold: 0.55
  window_sentences: 2
  target_keys: [SN,SSN,DN,PN,MN,BN,AN,EML]
```

Notes & recommendations

- `jhgan/ko-sbert-multitask` is a Korean SBERT model suitable for local semantic filtering.
- If running at scale, consider batching context snippets and caching indicator embeddings.

