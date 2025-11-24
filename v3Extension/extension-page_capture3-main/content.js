async function mainCapture() {
    const currentURL = location.href;

    // 1. 檢查是否跳過 (Skip Logic)
    const { skip_once } = await chrome.storage.local.get("skip_once");
    if (skip_once && currentURL.includes(skip_once)) {
        console.log("[EXT] 使用者選擇跳過檢查:", currentURL);
        // 清空 skip_once，避免永久跳過 (安全性考量)
        chrome.storage.local.set({ skip_once: null });
        return; 
    }

    // 2. 開始 UI 狀態更新
    chrome.storage.local.set({ analysis_running: true });
    chrome.runtime.sendMessage({ stage: "開始分析" });
    
    const start = performance.now();
    chrome.storage.local.set({ analysis_start_time: start });
    chrome.runtime.sendMessage({ stage: "資料擷取中…" });

    // 3. 抓取網頁內容
    // 這裡不又fetch一次，直接用渲染好的內容通常更準確
    let html = document.documentElement.outerHTML;
    const doc = document; // 直接使用當前 document

    // 4. 提取主要文字
    const mainSelectors = ["article", "main", "#content", ".content", ".post", ".entry", ".article", ".main"];
    let mainArea = null;
    for (const sel of mainSelectors) {
        mainArea = doc.querySelector(sel);
        if (mainArea) break;
    }

    let contentText = mainArea ? mainArea.innerText : doc.body.innerText;
    // 簡單清洗：去除非文字雜訊
    contentText = contentText
        .replace(/\n\s*\n+/g, "\n\n") // 把多個換行變成兩個
        .replace(/[ \t]{2,}/g, " ")   // 把多個空白變成一個
        .trim();

    // 5. 提取連結 (正規化)
    const normalize = (u) => {
        try {
            const url = new URL(u, location.href);
            // 移除追蹤參數
            ["utm_source", "utm_medium", "utm_campaign", "fbclid"].forEach(p => url.searchParams.delete(p));
            url.hash = "";
            return url.toString();
        } catch { return u; }
    };

    const links = [...doc.querySelectorAll("a[href]")]
        .map(a => a.getAttribute("href"))
        .filter(h => h && !h.startsWith("javascript:") && !h.startsWith("mailto:") && !h.startsWith("#"))
        .map(normalize);

    // 6. 組合資料
    const output = [
        `=== URL ===\n${currentURL}`,
        `=== Timestamp ===\n${Date.now()}`,
        `=== Page Title ===\n${document.title.trim()}`,
        `=== Visible Text (main excerpt) ===\n${contentText.slice(0, 20000)}`, // 限制長度避免 Payload 太大
        `=== Links ===\n${links.slice(0, 500).join("\n")}` // 限制連結數量
    ].join("\n\n");

    // 7. 發送給 Background 處理
    chrome.runtime.sendMessage({
        type: "analyze_request",
        text: output,
        url: currentURL, // 補上 URL 參數方便後端使用
        startTime: start
    });
}

// 初始化與監聽
chrome.storage.local.get({ enabled: true }, (items) => {
    if (items.enabled) mainCapture();
});

chrome.runtime.onMessage.addListener((msg) => {
    if (msg.action === "manual_capture") mainCapture();
});