#!/usr/bin/env bash
set -euo pipefail

# Run the contextual LLM demo (assumes virtualenv activated and deps installed)
python app/test_context_filter.py
