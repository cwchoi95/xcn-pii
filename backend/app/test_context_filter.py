from app.pii_engine import ContextualLLMPostFilter, DetectContext


def run_demo():
    text = (
        "다음은 예시 텍스트입니다. 주민등록번호: 900101-1234567 은 민감한 정보입니다."
        " 이 예시는 테스트용 샘플 문장입니다. 연락처는 010-1234-5678 입니다."
    )

    # simulate a raw detection hit around the rrn
    rrn_start = text.find("주민등록번호")
    rrn_end = rrn_start + len("주민등록번호: 900101-1234567")

    items = [{"start": rrn_start, "end": rrn_end, "matchString": text[rrn_start:rrn_end]}]

    ctx = DetectContext(text=text, max_results=10, out={"SN": items})

    # create the LLM/embedding-based filter (will lazily load model)
    filt = ContextualLLMPostFilter(enabled=True, target_keys=["SN"], window_sentences=1, sim_threshold=0.4, debug=True)
    filt.run(ctx)

    print("Original items:", items)
    print("Filtered items:", ctx.get("SN"))


if __name__ == "__main__":
    run_demo()
