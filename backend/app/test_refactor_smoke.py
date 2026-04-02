from app.pii_engine import (
    ContextualLLMPostFilter,
    ContextualPostFilter,
    DetectContext,
    build_pipeline,
)
from app.rules_loader import load_rules


def test_refactor_public_imports():
    assert DetectContext is not None
    assert ContextualPostFilter is not None
    assert ContextualLLMPostFilter is not None


def test_refactor_build_pipeline():
    bundle = load_rules(rules_dir="app/rules", ruleset_name="default")
    pipeline = build_pipeline(bundle)
    assert pipeline
