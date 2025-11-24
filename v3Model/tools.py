# LangChain 工具定義

from langchain_core.tools import tool
from typing import List
import re
from urllib.parse import urlparse
import socket
from datetime import datetime

# 常見第三方託管 host
THIRD_PARTY_HOSTS = ("github.io", "netlify.app", "vercel.app", "pages.dev", "githubusercontent.com", "herokuapp.com")

# 常見可疑域名特徵
SUSPICIOUS_DOMAIN_PATTERNS = [
    r"[\d]{4,}",  # 包含大量數字
    r"[a-z]{1,2}\d+[a-z]{1,2}",  # 短字母+數字組合
    r"bit\.ly|tinyurl|t\.co|goo\.gl",  # 短網址服務
]

@tool
def check_url_safety(url: str) -> str:
    """檢查 URL 的安全性特徵。
    
    分析 URL 的域名、路徑、參數等，判斷是否具有可疑特徵。
    
    Args:
        url: 要檢查的 URL 字串
        
    Returns:
        安全性分析結果（繁體中文）
    """
    if not url:
        return "URL 為空，無法分析。"
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        findings = []
        
        # 檢查第三方託管平台
        for host in THIRD_PARTY_HOSTS:
            if host in domain:
                findings.append(f"使用第三方託管平台：{host}")
        
        # 檢查可疑域名模式
        for pattern in SUSPICIOUS_DOMAIN_PATTERNS:
            if re.search(pattern, domain):
                findings.append(f"域名包含可疑模式：{pattern}")
        
        # 檢查域名長度（過短或過長都可能可疑）
        domain_parts = domain.split('.')
        main_domain = domain_parts[0] if domain_parts else ""
        if len(main_domain) < 3:
            findings.append("主域名過短，可能為可疑網址")
        elif len(main_domain) > 30:
            findings.append("主域名過長，可能為混淆設計")
        
        # 檢查路徑中的可疑關鍵字
        suspicious_paths = ["verify", "confirm", "update", "secure", "login", "account"]
        for keyword in suspicious_paths:
            if keyword in path:
                findings.append(f"路徑包含敏感關鍵字：{keyword}")
        
        # 檢查是否使用 HTTP（非 HTTPS）
        if parsed.scheme == "http":
            findings.append("使用 HTTP 而非 HTTPS，安全性較低")
        
        if not findings:
            return f"URL 基本檢查通過：{domain}\n未發現明顯可疑特徵。"
        else:
            return f"URL 分析結果：{domain}\n" + "\n".join(findings)
            
    except Exception as e:
        return f"URL 解析失敗：{str(e)}"


@tool
def analyze_domain_age(domain: str) -> str:
    """分析域名的註冊時間特徵（簡化版）。
    
    注意：此為簡化版本，實際應用中需要調用 WHOIS API。
    此工具主要檢查域名格式是否合理。
    
    Args:
        domain: 要分析的域名
        
    Returns:
        域名分析結果（繁體中文）
    """
    if not domain:
        return "域名為空，無法分析。"
    
    try:
        domain = domain.lower().strip()
        domain_parts = domain.split('.')
        
        if len(domain_parts) < 2:
            return "域名格式不完整，缺少頂級域名"
        
        main_domain = domain_parts[0]
        tld = domain_parts[-1]
        
        findings = []
        
        # 檢查常見的合法 TLD
        common_tlds = ["com", "org", "net", "edu", "gov", "tw", "cn", "hk", "jp"]
        if tld not in common_tlds:
            findings.append(f"使用不常見的頂級域名：{tld}")
        
        # 檢查主域名是否包含數字（可能是新註冊的可疑域名）
        if re.search(r'\d', main_domain):
            findings.append("主域名包含數字，可能是新註冊的可疑域名")
        
        # 檢查是否為 IP 地址格式
        try:
            socket.inet_aton(domain)
            findings.append("使用 IP 地址而非域名，可能為可疑網站")
        except:
            pass
        
        if not findings:
            return f"域名格式檢查通過：{domain}\n格式看起來正常。"
        else:
            return f"域名分析結果：{domain}\n" + "\n".join(findings)
            
    except Exception as e:
        return f"域名分析失敗：{str(e)}"


@tool
def check_url_patterns(urls: List[str]) -> str:
    """批量檢查多個 URL 的模式特徵。
    
    分析 URL 列表中是否有重複模式、可疑結構等。
    
    Args:
        urls: URL 字串列表
        
    Returns:
        批量分析結果（繁體中文）
    """
    if not urls:
        return "URL 列表為空，無法分析。"
    
    try:
        domains = []
        schemes = []
        
        for url in urls[:20]:  # 最多分析 20 個
            try:
                parsed = urlparse(url)
                domains.append(parsed.netloc.lower())
                schemes.append(parsed.scheme)
            except:
                continue
        
        findings = []
        
        # 檢查是否所有 URL 都使用 HTTP
        if all(s == "http" for s in schemes if s):
            findings.append("所有 URL 都使用 HTTP（非 HTTPS），安全性較低")
        
        # 檢查域名多樣性
        unique_domains = set(domains)
        if len(unique_domains) == 1 and len(urls) > 3:
            findings.append(f"所有 URL 都指向同一個域名：{list(unique_domains)[0]}")
        
        # 檢查是否有第三方託管
        third_party_count = sum(1 for d in domains for host in THIRD_PARTY_HOSTS if host in d)
        if third_party_count > 0:
            findings.append(f"發現 {third_party_count} 個 URL 使用第三方託管平台")
        
        if not findings:
            return f"批量 URL 檢查通過\n分析了 {len(urls)} 個 URL，未發現明顯可疑模式。"
        else:
            return f"批量 URL 分析結果（共 {len(urls)} 個）\n" + "\n".join(findings)
            
    except Exception as e:
        return f"批量 URL 分析失敗：{str(e)}"


@tool
def extract_contact_info(text: str) -> str:
    """從文字中提取聯絡資訊（email、電話）。只要偵測到任一項就算有聯絡方式。"""
    if not text:
        return "文字為空，無法提取聯絡資訊。"

    try:
        findings = []

        # email
        emails = re.findall(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            text
        )

        # 電話
        phones = re.findall(
            r"\d[\d\-\s\(\)]{5,}\d",
            text
        )

        has_contact = False

        if emails:
            has_contact = True
            findings.append(f"找到電子郵件 {len(emails)} 組")

        if phones:
            has_contact = True
            findings.append(f"找到電話號碼 {len(phones)} 組")

        # 只要有任一聯絡方式 → 就算正常
        if has_contact:
            return "聯絡資訊正常：" + "、".join(findings)

        # 皆無 → 才算異常
        return "未找到聯絡資訊"

    except Exception as e:
        return f"聯絡資訊提取失敗：{str(e)}"

@tool
def detect_language_anomaly(text: str) -> str:
    """檢查頁面中的語言異常，包括簡體比例、語法怪異、重複句。
    不使用政治用詞，不偵測國別詞彙，只檢查「語言品質」。
    """
    if not text or len(text) < 20:
        return "文字過少，語言檢查不足"

    findings = []

    # --- 1. 檢查簡體字出現比例 ---
    simplified_chars = "们这对机国观产层战领举办权进体为发过学说语讲"
    simp_count = sum(1 for c in text if c in simplified_chars)
    total_chars = len(text)
    ratio = round(simp_count / max(total_chars, 1), 3)

    if ratio > 0.05:
        findings.append(f"簡體字比例偏高({ratio})")

    # --- 2. 混雜語言檢查（中文 + 英文大量混合） ---
    zh = len(re.findall(r"[\u4e00-\u9fa5]", text))
    en = len(re.findall(r"[A-Za-z]", text))
    if zh > 0 and en > 0 and (en / (zh + 1)) > 0.4:
        findings.append("語言混雜比例異常")

    # --- 3. 偵測是否翻譯腔（重複片段、破碎文法） ---
    if re.search(r"的的|了了|是不|會會|它它", text):
        findings.append("疑似翻譯腔或重複片段")

    if len(findings) == 0:
        return "語言檢查正常"
    return "語言異常：" + "、".join(findings)


@tool
def calculate_risk_score(url: str, evidence: str) -> str:
    """計算網站的風險評分（0-100分）。
    
    根據 URL 特徵和證據分析，給出風險分數。
    分數越高表示風險越大。
    
    Args:
        url: 要評估的 URL
        evidence: 其他工具檢測到的證據（用換行分隔）
        
    Returns:
        風險評分和說明（繁體中文）
    """
    if not url:
        return "風險評分：無法計算（缺少 URL）"
    
    score = 0
    reasons = []
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # URL 特徵評分（0-40分）
        # 使用 HTTP 而非 HTTPS
        if parsed.scheme == "http":
            score += 15
            reasons.append("使用 HTTP（+15分）")
        
        # 第三方託管平台
        for host in THIRD_PARTY_HOSTS:
            if host in domain:
                score += 10
                reasons.append(f"第三方託管平台（+10分）")
                break
        
        # 短網址服務
        if re.search(r"bit\.ly|tinyurl|t\.co|goo\.gl", domain):
            score += 20
            reasons.append("短網址服務（+20分）")
        
        # 域名可疑模式
        if re.search(r"[\d]{4,}", domain):
            score += 12
            reasons.append("域名包含大量數字（+12分）")
        
        # 證據分析評分（0-40分）
        if evidence:
            evidence_lower = evidence.lower()
            
            if "未找到聯絡資訊" in evidence:
                score += 15
                reasons.append("缺少聯絡資訊（+15分）")
            
            if "語言異常" in evidence:
                score += 10
                reasons.append("語言品質異常（+10分）")
            
            if "可疑模式" in evidence or "可疑特徵" in evidence:
                score += 12
                reasons.append("發現可疑模式（+12分）")
            
            if "官方安全域名" in evidence or "白名單檢查" in evidence:
                score -= 20  # 降低風險
                reasons.append("官方安全域名（-20分）")
        
        # 域名長度異常
        domain_parts = domain.split('.')
        main_domain = domain_parts[0] if domain_parts else ""
        if len(main_domain) < 3:
            score += 8
            reasons.append("域名過短（+8分）")
        elif len(main_domain) > 30:
            score += 8
            reasons.append("域名過長（+8分）")
        
        # 確保分數在 0-100 範圍內
        score = max(0, min(100, score))
        
        # 風險等級
        if score < 20:
            level = "低風險"
        elif score < 50:
            level = "中風險"
        elif score < 75:
            level = "高風險"
        else:
            level = "極高風險"
        
        result = f"風險評分：{score}/100（{level}）"
        if reasons:
            result += f"\n評分依據：{'、'.join(reasons[:5])}"  # 最多顯示5個理由
        
        return result
        
    except Exception as e:
        return f"風險評分計算失敗：{str(e)}"


@tool
def generate_page_summary(text: str) -> str:
    """生成頁面內容的智能摘要。
    
    分析頁面文字內容，提取關鍵資訊並生成簡潔摘要。
    
    Args:
        text: 頁面文字內容
        
    Returns:
        頁面摘要（繁體中文，最多150字）
    """
    if not text or len(text) < 50:
        return "內容過少，無法生成摘要"
    
    try:
        # 提取關鍵資訊
        # 1. 標題（通常在開頭或包含關鍵字）
        title_match = re.search(r"<title>(.*?)</title>", text, re.IGNORECASE)
        title = title_match.group(1) if title_match else ""
        
        # 2. 提取前200字作為主要內容
        visible_text = re.sub(r"<[^>]+>", "", text)
        visible_text = visible_text.strip()
        
        # 3. 提取關鍵詞（常見的網站類型關鍵字）
        keywords = []
        if re.search(r"登入|登錄|login|sign in", text, re.IGNORECASE):
            keywords.append("登入頁面")
        if re.search(r"驗證|verify|confirm", text, re.IGNORECASE):
            keywords.append("驗證功能")
        if re.search(r"帳戶|帳號|account", text, re.IGNORECASE):
            keywords.append("帳戶相關")
        if re.search(r"付款|支付|payment|pay", text, re.IGNORECASE):
            keywords.append("付款相關")
        if re.search(r"更新|update|upgrade", text, re.IGNORECASE):
            keywords.append("更新提示")
        
        # 4. 生成摘要
        summary_parts = []
        
        if title:
            summary_parts.append(f"標題：{title[:50]}")
        
        if keywords:
            summary_parts.append(f"功能：{'、'.join(keywords[:3])}")
        
        # 提取主要文字內容（去除 HTML 標籤後的前100字）
        main_content = visible_text[:100].replace("\n", " ").strip()
        if main_content:
            summary_parts.append(f"內容：{main_content}...")
        
        if summary_parts:
            summary = " | ".join(summary_parts)
            # 限制長度
            if len(summary) > 150:
                summary = summary[:147] + "..."
            return summary
        else:
            return "無法提取有效摘要資訊"
            
    except Exception as e:
        return f"摘要生成失敗：{str(e)}"


@tool
def detect_similar_sites(url: str, text: str) -> str:
    """檢測網站是否模仿知名網站。
    
    分析 URL 和頁面內容，判斷是否可能模仿知名品牌或服務。
    
    Args:
        url: 要檢查的 URL
        text: 頁面文字內容
        
    Returns:
        相似網站檢測結果（繁體中文）
    """
    if not url:
        return "無法檢測（缺少 URL）"
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # 知名品牌列表（常見被模仿的網站）
        known_brands = {
            "google": ["google", "gmail", "googledrive", "googlepay"],
            "microsoft": ["microsoft", "outlook", "office", "onedrive", "azure"],
            "apple": ["apple", "icloud", "appleid"],
            "facebook": ["facebook", "fb", "meta"],
            "amazon": ["amazon", "aws"],
            "paypal": ["paypal"],
            "bank": ["bank", "banking", "金融", "銀行"],
            "gov": ["gov", "政府", "官方"],
        }
        
        findings = []
        text_lower = text.lower() if text else ""
        
        # 檢查域名是否包含品牌關鍵字但域名不匹配
        for brand_name, keywords in known_brands.items():
            # 檢查頁面內容是否提到品牌
            content_mentions = any(kw in text_lower for kw in keywords)
            
            # 檢查域名是否類似但不同
            domain_similar = any(kw in domain for kw in keywords)
            
            # 如果內容提到品牌但域名不匹配，可能是模仿
            if content_mentions and not domain_similar:
                # 檢查是否為合法子域名（如 mail.google.com）
                is_legitimate = False
                for kw in keywords:
                    if domain.endswith(f".{kw}.com") or domain.endswith(f".{kw}.com.tw"):
                        is_legitimate = True
                        break
                
                if not is_legitimate:
                    findings.append(f"內容提及「{brand_name}」但域名不匹配")
            
            # 檢查域名是否使用拼寫錯誤或變體（typosquatting）
            if domain_similar:
                # 檢查是否為明顯的拼寫錯誤
                if len(domain) > 5:
                    for kw in keywords:
                        if kw in domain and domain != f"{kw}.com" and domain != f"www.{kw}.com":
                            # 可能是合法子域名，需要進一步檢查
                            if not any(domain.endswith(f".{kw}.com") or domain.endswith(f".{kw}.com.tw") for _ in [1]):
                                # 簡單檢查：如果域名包含品牌但結構可疑
                                if re.search(rf"{kw}[^.]*\.(com|net|org)", domain):
                                    findings.append(f"域名疑似模仿「{brand_name}」")
        
        # 檢查常見的釣魚網站特徵
        suspicious_patterns = [
            (r"secure-[a-z0-9]+\.(com|net)", "使用可疑的 secure- 前綴"),
            (r"[a-z0-9]+-verify\.(com|net)", "使用可疑的 verify 後綴"),
            (r"[a-z0-9]+-update\.(com|net)", "使用可疑的 update 後綴"),
        ]
        
        for pattern, desc in suspicious_patterns:
            if re.search(pattern, domain):
                findings.append(desc)
        
        if not findings:
            return "未發現模仿知名網站的跡象"
        else:
            return "相似網站檢測：" + "、".join(findings[:3])  # 最多顯示3個
            
    except Exception as e:
        return f"相似網站檢測失敗：{str(e)}"



# ------------------------------
# 功能：定義 LangChain 工具，供模型在分析過程中主動調用
# 使用套件：
#   - langchain-core (pip install langchain-core)
#
# 工具列表：
# 1. check_url_safety - 檢查單個 URL 的安全性特徵
# 2. analyze_domain_age - 分析域名格式和特徵
# 3. check_url_patterns - 批量檢查多個 URL 的模式
# 4. extract_contact_info - 從文字中提取聯絡資訊
# 5. detect_language_anomaly - 檢測語言異常（簡體比例、翻譯腔等）
# 6. calculate_risk_score - 計算風險評分（0-100分）⭐ 新增
# 7. generate_page_summary - 生成頁面智能摘要 ⭐ 新增
# 8. detect_similar_sites - 檢測是否模仿知名網站 ⭐ 新增
#
# 這些工具可以讓模型在分析過程中主動調用，獲取更多資訊來做出更準確的判斷。
# 新增的工具讓使用者能明顯感受到 AI 的智能分析能力。

