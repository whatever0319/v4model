# analyzer.py — LangChain + Tools （ 弱白名單 / 工具驅動理由 / 繁體）

import time
import re
from typing import List, Dict
from functools import lru_cache
from urllib.parse import urlparse

from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI

from models import SimplePhishingAnalysis
from tools import (
    check_url_safety,
    analyze_domain_age,
    check_url_patterns,
    extract_contact_info,
    detect_language_anomaly,
    calculate_risk_score,
    generate_page_summary,
    detect_similar_sites,
)

MODEL = "qwen3:8b"
BASE_URL = "http://127.0.0.1:11434/v1"
API_KEY = "ollama"

# ★ 弱白名單（不跳過分析，但限制理由）
SAFE_DOMAINS = [
    "google.com", "google.com.tw", "gstatic.com",
    "facebook.com", "microsoft.com", "github.com",
    "edu.tw", "gov.tw",
    "niu.edu.tw",
]

def is_safe_domain(url):
    host = urlparse(url).netloc.lower()
    return any(sd in host for sd in SAFE_DOMAINS)

# 工具結果 → Evidence Block
def collect_tool_evidence(urls: List[str], visible: str) -> Dict[str, str]:
    evidence = {}

    # --------------------
    # 1. 白名單提示（不直接判安全）
    # --------------------
    if urls and is_safe_domain(urls[0]):
        evidence["白名單檢查"] = "官方安全域名（低風險）"

    # --- URL 安全檢查 ---
    if urls:
        safety = check_url_safety.invoke({"url": urls[0]})
        if safety:
            evidence["URL 安全檢查"] = str(safety)

    # --- 網域年齡（需傳 domain） ---
    if urls:
        domain = urlparse(urls[0]).netloc
        age = analyze_domain_age.invoke({"domain": domain})
        if age:
            evidence["網域年齡檢查"] = str(age)

    # --- URL 結構檢查 ---
    patt = check_url_patterns.invoke({"urls": urls})
    if patt:
        evidence["可疑結構檢查"] = str(patt)

    # --- 聯絡資訊提取 ---
    cinfo = extract_contact_info.invoke({"text": visible})
    if cinfo:
        evidence["聯絡方式檢查"] = str(cinfo)

    # --- 語言異常檢查 ---
    lang = detect_language_anomaly.invoke({"text": visible})
    if lang:
        evidence["語言異常檢查"] = str(lang)

    # --- 相似網站檢測 ---
    if urls:
        similar = detect_similar_sites.invoke({"url": urls[0], "text": visible})
        if similar and "未發現" not in similar:
            evidence["相似網站檢測"] = str(similar)

    return evidence

#  HTML 處理
def _extract_visible_text(html: str) -> str:
    html = re.sub(
        r"<(script|style|meta|link|noscript)[^>]*>.*?</\1>",
        "",
        html,
        flags=re.DOTALL
    )
    blocks = re.findall(r">(.*?)<", html)
    return "\n".join(x.strip() for x in blocks if x.strip())


def _find_urls(text: str) -> List[str]:
    return [m.group(1) for m in re.finditer(
        r"(?i)\b((?:https?://|www\.)\S+)", text
    )]

# LangChain Chain（Evidence → 決定理由）
@lru_cache(maxsize=4)
def _build_chain():

    llm = ChatOpenAI(
        model=MODEL,
        base_url=BASE_URL,
        api_key=API_KEY,
        temperature=0.1,
        max_tokens=512,
    ).bind_tools([
        check_url_safety,
        analyze_domain_age,
        check_url_patterns,
        extract_contact_info,
        detect_language_anomaly,
        calculate_risk_score,
        generate_page_summary,
        detect_similar_sites,
    ])

    prompt = ChatPromptTemplate.from_messages([
        ("system",
         """
你是一個資安分析 AI。
你的任務是依據「Evidence」回傳 SimplePhishingAnalysis JSON。

【explanation 規則】
1. 必須是「短理由」，每點 ≤ 12 字。
2. 用繁體中文。
3. 最多三個理由 → 用 "、" 連接成單行。
4. explanation 只能使用 Evidence 中出現的資訊。
5. Evidence 全部正常 → explanation = 「未發現可疑特徵」。
6. Evidence 含「官方安全域名」→
   禁止使用內容型理由（如：無聯絡資訊、無隱私政策、缺 email）。
7. 不得編造、不得推測。

【額外欄位】
- risk_score: 從 Evidence 中的「風險評分」提取數字（0-100），如果沒有則設為 null
- page_summary: 從 Evidence 中的「頁面摘要」提取，如果沒有則設為 null
- similar_site_detection: 從 Evidence 中的「相似網站檢測」提取，如果沒有則設為 null
"""),

        ("human",
         """
=== 可見文字 ===
{visible_text}

=== URL ===
{urls}

=== 工具檢測結果 (Evidence) ===
{evidence}

請依 Evidence 回傳 SimplePhishingAnalysis JSON。
""")
    ])

    return prompt | llm.with_structured_output(SimplePhishingAnalysis)

# 主分析流程
def analyze_deep(text: str) -> dict:
    start = time.time()

    visible = _extract_visible_text(text)
    urls = _find_urls(text)
    urls_str = "\n".join(urls[:10]) if urls else "（無網址）"

    # Collect Evidence
    evidence_dict = collect_tool_evidence(urls, visible)

    # 計算風險評分
    risk_score_result = None
    if urls:
        evidence_text_for_score = "\n".join(f"{k}: {v}" for k, v in evidence_dict.items())
        risk_score_result = calculate_risk_score.invoke({
            "url": urls[0],
            "evidence": evidence_text_for_score
        })
        evidence_dict["風險評分"] = risk_score_result

    # 生成頁面摘要
    summary_result = generate_page_summary.invoke({"text": text[:2000]})
    if summary_result and "無法" not in summary_result:
        evidence_dict["頁面摘要"] = summary_result

    # Format Evidence → 傳給 LLM
    evidence_text = (
        "\n".join(f"{k}: {v}" for k, v in evidence_dict.items())
        if evidence_dict else
        "（所有工具檢測正常）"
    )

    chain = _build_chain()

    resp = chain.invoke({
        "visible_text": visible[:3000],
        "urls": urls_str,
        "evidence": evidence_text,
    })

    parsed = resp.model_dump() if hasattr(resp, "model_dump") else dict(resp)

    # --- explanation：拆解 → 去雜訊 → 三項 → 以「、」合併 ---
    raw = parsed.get("explanation", "")
    parts = re.split(r"[\n、,，]+", raw)
    parts = [p.strip("- ").strip() for p in parts if p.strip()]
    parts = parts[:3]
    explanation_final = "、".join(parts) if parts else "未發現可疑特徵"

    # 提取風險評分數字
    risk_score_value = None
    if risk_score_result:
        score_match = re.search(r"(\d+)/100", risk_score_result)
        if score_match:
            risk_score_value = int(score_match.group(1))

    # 提取頁面摘要
    page_summary_value = parsed.get("page_summary") or summary_result

    # 提取相似網站檢測
    similar_site_value = parsed.get("similar_site_detection")
    if not similar_site_value and "相似網站檢測" in evidence_dict:
        similar_site_value = evidence_dict["相似網站檢測"]

    elapsed = round(time.time() - start, 2)

    return {
        "is_potential_phishing": parsed.get("is_potential_phishing", False),
        "explanation": explanation_final,
        "elapsed_time": elapsed,
        "risk_score": risk_score_value,
        "page_summary": page_summary_value if page_summary_value and "無法" not in page_summary_value else None,
        "similar_site_detection": similar_site_value if similar_site_value and "未發現" not in similar_site_value else None,
    }
