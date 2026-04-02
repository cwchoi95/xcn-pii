// =========================================================
// Helpers
// =========================================================
function escapeHtml(s) {
  return (s ?? "").toString()
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Map normalized score [-1..1] (or [0..1]) to a color gradient.
function scoreToColor(score) {
  // Expect score in [0,1]. If given [-1,1], convert.
  let v = Number(score);
  if (v < -1) v = -1; if (v > 1) v = 1;
  if (v <= 0) v = (v + 1) / 2; // map [-1,0] -> [0,0.5]
  // now v in [0,1]
  // gradient from red (0) -> yellow (0.5) -> green (1)
  const r1 = [220, 38, 38]; // red
  const r2 = [250, 204, 21]; // yellow
  const r3 = [37, 99, 235]; // blue-ish for high confidence (use blue to stand out)
  if (v < 0.5) {
    const t = v / 0.5;
    const r = Math.round(r1[0] + (r2[0] - r1[0]) * t);
    const g = Math.round(r1[1] + (r2[1] - r1[1]) * t);
    const b = Math.round(r1[2] + (r2[2] - r1[2]) * t);
    return `rgba(${r},${g},${b},0.35)`;
  } else {
    const t = (v - 0.5) / 0.5;
    const r = Math.round(r2[0] + (r3[0] - r2[0]) * t);
    const g = Math.round(r2[1] + (r3[1] - r2[1]) * t);
    const b = Math.round(r2[2] + (r3[2] - r2[2]) * t);
    return `rgba(${r},${g},${b},0.28)`;
  }
}

function show(el) { if (el) el.style.display = "block"; }
function hide(el) { if (el) el.style.display = "none"; }

function setResult(el, ok, html) {
  if (!el) return;
  show(el);
  el.classList.remove("ok", "bad");
  el.classList.add(ok ? "ok" : "bad");
  el.innerHTML = html;
}

/**
 * Highlight text by spans using <mark>.
 * - Preserves original behavior (mark highlight)
 * - Adds class per type (SN/DN/...) and SN valid/invalid
 */
function highlightText(text, spans) {
  if (!spans || spans.length === 0) return escapeHtml(text);

  const sorted = [...spans].sort((a, b) => a.start - b.start || a.end - b.end);
  let out = "";
  let cur = 0;

  for (const s of sorted) {
    const start = Math.max(0, Math.min(text.length, s.start));
    const end = Math.max(0, Math.min(text.length, s.end));
    if (start > cur) out += escapeHtml(text.slice(cur, start));

    const chunk = escapeHtml(text.slice(start, end));

    const tag = (s.tag || s.type || "PII").toString();
    const safeTag = tag.replaceAll(/[^a-zA-Z0-9_-]/g, "");

    let cls = `pii pii-${safeTag}`;

    if (tag === "SN") {
      cls += s.isValid ? " pii-sn-valid" : " pii-sn-invalid";
    }
    if (tag === "SN_INVALID") {
      cls += " pii-sn-invalid";
    }
    if (s.context_pass === false || String(tag).endsWith("_CTX_REJECTED")) {
      cls += " pii-ctx-rejected";
    }

    // include normalized score and snippet in tooltip; apply inline bg color
    const scoreNorm = (s.context_score_norm !== null && s.context_score_norm !== undefined) ? Number(s.context_score_norm) : null;
    const hybridScore = (s.context_hybrid_score !== null && s.context_hybrid_score !== undefined) ? Number(s.context_hybrid_score) : null;
    const scoreText = scoreNorm !== null ? ` score=${scoreNorm.toFixed(2)}` : "";
    const hybridText = hybridScore !== null ? ` hybrid=${hybridScore.toFixed(2)}` : "";
    const methodText = s.context_method ? ` method=${s.context_method}` : "";
    const acceptText = s.context_accept_by ? ` accept=${s.context_accept_by}` : "";
    const detectedByText = s.detected_by ? ` detected_by=${s.detected_by}` : "";
    const snippetText = s.context_snippet ? `\n${s.context_snippet.slice(0,200)}${s.context_snippet.length>200?"...":""}` : "";
    const passText = (typeof s.context_pass === "boolean") ? ` pass=${s.context_pass ? "true" : "false"}` : "";
    const title = `${tag} [${start},${end}]${scoreText}${hybridText}${methodText}${acceptText}${passText}${detectedByText}${snippetText}`;
    let style = "";
    if (hybridScore !== null || scoreNorm !== null) {
      const col = scoreToColor(hybridScore !== null ? hybridScore : scoreNorm);
      style = `style="background:${col};"`;
    }
    out += `<mark class="${cls}" title="${escapeHtml(title)}" ${style}>${chunk}</mark>`;

    cur = end;
  }

  if (cur < text.length) out += escapeHtml(text.slice(cur));
  return out;
}

/**
 * Convert API payload (PiiData) into a flat list of spans.
 * Supports SN_INVALID and maps it to tag="SN_INVALID".
 */
function flattenToSpansAll(apiData) {
  const normType = (t) => {
    if (t === "email" || t === "eml") return "EML";
    if (t === "email_CTX_REJECTED" || t === "eml_CTX_REJECTED") return "EML_CTX_REJECTED";
    return t;
  };

  const types = [
    "SN", "SN_INVALID", "SSN", "DN", "AN", "PN", "MN", "BN", "EML", "IP",
    "email", "eml",
    "SN_CTX_REJECTED", "SN_INVALID_CTX_REJECTED", "SSN_CTX_REJECTED", "DN_CTX_REJECTED", "PN_CTX_REJECTED",
    "MN_CTX_REJECTED", "BN_CTX_REJECTED", "AN_CTX_REJECTED", "EML_CTX_REJECTED", "IP_CTX_REJECTED",
    "email_CTX_REJECTED", "eml_CTX_REJECTED"
  ];
  const spans = [];

  for (const t of types) {
    const arr = apiData?.[t] || [];
    for (const it of arr) {
      const tt = normType(t);
      const isSnInvalid = (tt === "SN_INVALID");
      const isCtxRejected = tt.endsWith("_CTX_REJECTED");
      spans.push({
        type: isSnInvalid ? "SN" : tt,        // type은 SN으로 통일 가능
        tag: isSnInvalid ? "SN_INVALID" : tt, // UI 구분용
        start: it.start,
        end: it.end,
        matchString: it.matchString,
        isValid: isSnInvalid ? false : it.isValid
        ,context_score: typeof it.context_score === 'number' ? it.context_score : null
        ,context_score_norm: typeof it.context_score_norm === 'number' ? it.context_score_norm : null
        ,context_hybrid_score: typeof it.context_hybrid_score === 'number' ? it.context_hybrid_score : null
        ,context_snippet: typeof it.context_snippet === 'string' ? it.context_snippet : null
        ,context_method: typeof it.context_method === 'string' ? it.context_method : null
        ,context_accept_by: typeof it.context_accept_by === 'string' ? it.context_accept_by : null
        ,detected_by: typeof it.detected_by === 'string' ? it.detected_by : null
        ,context_pass: typeof it.context_pass === 'boolean' ? it.context_pass : (isCtxRejected ? false : null)
      });
    }
  }

  return spans;
}

function flattenToSpansNoOverlap(apiData) {
  const spans = flattenToSpansAll(apiData);
  spans.sort((a, b) => a.start - b.start || a.end - b.end);
  const selected = [];
  let lastEnd = -1;
  for (const s of spans) {
    if (typeof s.start !== "number" || typeof s.end !== "number") continue;
    if (s.start >= lastEnd) {
      selected.push(s);
      lastEnd = s.end;
    }
  }
  return selected;
}

function renderTableRows(spans) {
  return spans.map(s => {
    const isValidText =
      ((s.tag === "SN" || s.tag === "SN_INVALID" || s.type === "SN") && typeof s.isValid === "boolean")
        ? (s.isValid ? "valid" : "invalid")
        : "";
    const scoreText = (s.context_score_norm !== null && s.context_score_norm !== undefined)
      ? (s.context_score_norm).toFixed(2)
      : "";
    const hybridText = (s.context_hybrid_score !== null && s.context_hybrid_score !== undefined)
      ? (s.context_hybrid_score).toFixed(2)
      : "";
    const methodText = s.context_method ? escapeHtml(s.context_method) : "";
    const acceptText = s.context_accept_by ? escapeHtml(s.context_accept_by) : "";
    const passText = (typeof s.context_pass === "boolean") ? (s.context_pass ? "pass" : "reject") : "";
    const detectedByText = s.detected_by ? escapeHtml(s.detected_by) : "";
    return `
      <tr>
        <td>${escapeHtml(s.tag || s.type)}</td>
        <td class="mono">${escapeHtml(s.matchString)}</td>
        <td class="mono">[${s.start},${s.end}]</td>
        <td>${escapeHtml(isValidText)}</td>
        <td class="mono">${escapeHtml(scoreText)}</td>
        <td class="mono">${escapeHtml(hybridText)}</td>
        <td>${escapeHtml(methodText)}</td>
        <td>${escapeHtml(passText ? `${acceptText} (${passText})` : acceptText)}</td>
        <td class="mono">${escapeHtml(detectedByText)}</td>
      </tr>
    `;
  }).join("");
}

function renderTable(rowsHtml) {
  return `
    <table class="result-table">
      <thead>
        <tr>
          <th>Type</th>
          <th>Match</th>
          <th>Span</th>
          <th>Valid</th>
          <th>Score</th>
          <th>Hybrid</th>
          <th>Method</th>
          <th>Accept</th>
          <th>Detected</th>
        </tr>
      </thead>
      <tbody>
        ${rowsHtml}
      </tbody>
    </table>`;
}

// =========================================================
// Tabs
// =========================================================
function setActiveTab(name) {
  const tabDetect = document.getElementById("tab-detect");
  const tabRrn = document.getElementById("tab-rrn");
  const pageDetect = document.getElementById("page-detect");
  const pageRrn = document.getElementById("page-rrn");

  if (name === "rrn") {
    tabDetect?.classList.remove("active");
    tabRrn?.classList.add("active");
    if (pageDetect) pageDetect.style.display = "none";
    if (pageRrn) pageRrn.style.display = "block";
  } else {
    tabRrn?.classList.remove("active");
    tabDetect?.classList.add("active");
    if (pageRrn) pageRrn.style.display = "none";
    if (pageDetect) pageDetect.style.display = "block";
  }
}

// =========================================================
// Detect (with timing)
// =========================================================
async function detect() {
  const textEl = document.getElementById("text");
  const maxEl = document.getElementById("maxSpans");
  const outEl = document.getElementById("out");
  const timingEl = document.getElementById("timing");

  const text = (textEl?.value || "");
  const maxResults = parseInt(maxEl?.value || "200", 10);

  if (outEl) outEl.innerHTML = `<div class="card">검출 중...</div>`;
  if (timingEl) {
    timingEl.style.display = "block";
    timingEl.innerHTML = `측정 중...`;
  }

  const t0 = performance.now();

  let res;
  try {
    res = await fetch("/pii/detect", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text, max_results_per_type: maxResults })
    });
  } catch (e) {
    const tErr = performance.now();
    if (timingEl) timingEl.innerHTML = `<b>걸린시간</b> · ${(tErr - t0).toFixed(1)} ms (네트워크 오류)`;
    if (outEl) outEl.innerHTML = `<div class="card">오류: ${escapeHtml(e?.message || String(e))}</div>`;
    return;
  }

  const t1 = performance.now(); // 서버 응답까지

  if (!res.ok) {
    const msg = await res.text();
    const tErr = performance.now();
    if (timingEl) timingEl.innerHTML = `<b>걸린시간</b> · ${(tErr - t0).toFixed(1)} ms (요청 실패)`;
    if (outEl) outEl.innerHTML = `<div class="card">오류: ${escapeHtml(msg)}</div>`;
    return;
  }

  const payload = await res.json();
  const t2 = performance.now(); // JSON 파싱

  // ✅ 현재 API 응답은 { success, status, data: PiiData } 형태
  const data = payload?.data || {};
  const spansAll = flattenToSpansAll(data);
  const spans = flattenToSpansNoOverlap(data);

  const highlighted = highlightText(text, spans);
  const t3 = performance.now(); // 렌더 준비

  const mainRows = renderTableRows(spansAll.filter(s => {
    const tag = String(s.tag || "");
    return !tag.endsWith("_CTX_REJECTED");
  }));
  const ctxRejectedRows = renderTableRows(spansAll.filter(s => String(s.tag || "").endsWith("_CTX_REJECTED")));

  if (outEl) {
    const ctxRejectedCount = spansAll.filter(s => String(s.tag || "").endsWith("_CTX_REJECTED")).length;
    const mainCount = spansAll.length - ctxRejectedCount;
    const emlMain = (data?.EML || data?.email || data?.eml || []).length;
    const emlCtx = (data?.EML_CTX_REJECTED || data?.email_CTX_REJECTED || data?.eml_CTX_REJECTED || []).length;
    outEl.innerHTML = `
      <div class="card">
        <div><b>검출 결과:</b> ${spans.length}건 (length=${text.length})</div>
        <div class="hint">EML 메인 ${emlMain}건 / EML 문맥제외 ${emlCtx}건</div>
        <div style="margin-top:10px; white-space:pre-wrap; line-height:1.7;">${highlighted}</div>
        <div class="list">
          ${ctxRejectedRows ? `<div class="subTitle" style="margin-top:10px;">문맥 제외 항목 (${ctxRejectedCount})</div><div class="tableWrap">${renderTable(ctxRejectedRows)}</div>` : ""}
          <div class="subTitle" style="margin-top:10px;">정규식/기본 항목 (${mainCount})</div>
          <div class="tableWrap">${mainRows ? renderTable(mainRows) : "(없음)"}</div>
        </div>
      </div>
    `;
  }

  const t4 = performance.now(); // DOM 반영 포함 총

  if (timingEl) {
    timingEl.innerHTML =
      `<b>걸린시간</b> · ` +
      `요청(서버응답) ${(t1 - t0).toFixed(1)} ms · ` +
      `JSON파싱 ${(t2 - t1).toFixed(1)} ms · ` +
      `렌더준비 ${(t3 - t2).toFixed(1)} ms · ` +
      `총 ${(t4 - t0).toFixed(1)} ms`;
  }
}

// =========================================================
// RRN checksum (front-only for UI page)
// =========================================================
function rrnChecksumValid(rrn) {
  const s = (rrn ?? "").toString().replaceAll("-", "").trim();
  if (!/^\d{13}$/.test(s)) return false;

  const digits = [...s].map(c => parseInt(c, 10));
  const weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];

  let total = 0;
  for (let i = 0; i < 12; i++) total += digits[i] * weights[i];

  const check = (11 - (total % 11)) % 10;
  return check === digits[12];
}

function extractSnFromText(text) {
  const rx = /(?<!\d)\d{6}-\d{7}(?!\d)/g;
  const out = [];
  let m;
  while ((m = rx.exec(text)) !== null) {
    out.push({ start: m.index, end: m.index + m[0].length, matchString: m[0] });
  }
  return out;
}

// =========================================================
// Init
// =========================================================
document.addEventListener("DOMContentLoaded", () => {
  // Tabs
  document.getElementById("tab-detect")?.addEventListener("click", () => setActiveTab("detect"));
  document.getElementById("tab-rrn")?.addEventListener("click", () => setActiveTab("rrn"));

  // Detect button
  document.getElementById("btnDetect")?.addEventListener("click", detect);

  // RRN elements
  const rrnInput = document.getElementById("rrnInput");
  const rrnResult = document.getElementById("rrnResult");
  const rrnText = document.getElementById("rrnText");
  const rrnBatchResult = document.getElementById("rrnBatchResult");

  document.getElementById("btnRrnCheck")?.addEventListener("click", () => {
    const rrn = (rrnInput?.value || "").trim();
    if (!rrn) {
      setResult(rrnResult, false, "<b>오류:</b> 주민등록번호를 입력하세요.");
      return;
    }
    const ok = rrnChecksumValid(rrn);
    setResult(
      rrnResult,
      ok,
      `<b>입력:</b> ${escapeHtml(rrn)}<br/><b>유효성:</b> ${ok ? "VALID ✅" : "INVALID ❌"}`
    );
  });

  document.getElementById("btnRrnClear")?.addEventListener("click", () => {
    if (rrnInput) rrnInput.value = "";
    if (rrnText) rrnText.value = "";
    if (rrnResult) { rrnResult.innerHTML = ""; hide(rrnResult); rrnResult.classList.remove("ok", "bad"); }
    if (rrnBatchResult) { rrnBatchResult.innerHTML = ""; hide(rrnBatchResult); rrnBatchResult.classList.remove("ok", "bad"); }
  });

  document.getElementById("btnRrnExtract")?.addEventListener("click", () => {
    const text = (rrnText?.value || "").trim();
    if (!text) {
      setResult(rrnBatchResult, false, "<b>오류:</b> 텍스트를 입력하세요.");
      return;
    }

    const t0 = performance.now();

    const snList = extractSnFromText(text);
    if (snList.length === 0) {
      const t1 = performance.now();
      setResult(rrnBatchResult, false, `SN(YYMMDD-XXXXXXX) 형태가 발견되지 않았습니다.\n\n걸린시간: ${(t1 - t0).toFixed(2)} ms`);
      return;
    }

    const validCnt = snList.filter(x => rrnChecksumValid(x.matchString)).length;

    const html = snList.map((it, idx) => {
      const ok = rrnChecksumValid(it.matchString);
      const color = ok ? "#059669" : "#dc2626";
      return `${idx + 1}. <b>${escapeHtml(it.matchString)}</b> (start=${it.start}, end=${it.end}) → <span style="color:${color};">${ok ? "VALID ✅" : "INVALID ❌"}</span>`;
    }).join("<br/>");

    const t1 = performance.now();

    setResult(
      rrnBatchResult,
      validCnt > 0,
      `<b>총 ${snList.length}건</b> (VALID ${validCnt} / INVALID ${snList.length - validCnt})<br/>` +
      `<div class="hint" style="margin-top:6px;">걸린시간: ${(t1 - t0).toFixed(2)} ms</div><br/>` +
      `${html}`
    );
  });

  // Default sample text
  const textArea = document.getElementById("text");
  if (textArea && !textArea.value) {
    textArea.value =
`[고객 문의]
담당자: 홍길동 / 연락처: 010-1234-5678 / 이메일: gil.dong+test@company.co.kr
예비 연락처: 02-345-6789, 031 987 6543

[본인 확인]
주민등록번호: 900101-1234567
미국 SSN: 123-45-6789 / 987654321
추가 샘플: 801231-2345678 / 960229-2234567 / 001231-4567890

[신분증/여권]
운전면허번호(형식): 11-22-333333-44
운전면허번호(연속): 112233333344
여권번호: M12345678 / S98765432 / AB1234567

[배송지]
서울특별시 강남구 테헤란로 123-4 5층
경기도 성남시 분당구 정자동 12-3 번지
부산광역시 해운대구 달맞이길 77

[참고]
이메일 변형: user.name_01@sub.example.com, ADMIN@EXAMPLE.ORG`;
  }

  // Auto-run detect once
  detect();
});
