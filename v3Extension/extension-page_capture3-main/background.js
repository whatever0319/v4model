const API_URL = "http://127.0.0.1:5000/analyze";

// 工具：安全發送訊息 (避免接收端不存在時報錯)
function safeSendMessage(payload) {
    chrome.runtime.sendMessage(payload, () => void chrome.runtime.lastError);
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    
    // 1. 處理「仍要前往」 (使用者在警告頁面點擊放行)
    if (msg.type === "open_original_site" && msg.target) {
        chrome.storage.local.set({ skip_once: msg.target }, () => {
            if (sender?.tab?.id) {
                chrome.tabs.update(sender.tab.id, { url: msg.target });
            } else {
                chrome.tabs.create({ url: msg.target });
            }
        });
        return true;
    }

    // 2. 處理分析請求 (來自 content.js)
    if (msg.type === "analyze_request") {
        const text = msg.text || "";
        safeSendMessage({ stage: "已傳送至後端分析…" });

        // 呼叫 Python 後端
        fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ text })
        })
        .then(resp => {
            safeSendMessage({ stage: "模型正在運算中…" });
            return resp.json();
        })
        .then(data => {
            // 儲存結果供 Popup 顯示
            chrome.storage.local.set({ last_analysis_result: data }, () => {
                safeSendMessage({ type: "analysis_result_done" });
            });

            // ★ 核心阻擋邏輯 ★
            if (data.is_blacklisted === true) {
                console.log("[BLK] 觸發黑名單攔截:", data.blacklist_source);
                
                // 判斷是官方還是使用者黑名單
                const pageName = (data.blacklist_source === "official") ? "block_official.html" : "block_user.html";
                
                // 取得原始網址 (優先用 content.js 傳來的，沒有的話用 tab url)
                const originalUrl = msg.url || sender?.tab?.url;

                // 執行導向
                chrome.tabs.update(sender.tab.id, {
                    url: chrome.runtime.getURL(`${pageName}?target=${encodeURIComponent(originalUrl)}`)
                });
            }
            
            sendResponse({ ok: true });
        })
        .catch(err => {
            console.error("後端分析失敗:", err);
            safeSendMessage({ stage: "連線後端失敗" });
            sendResponse({ ok: false, error: String(err) });
        });

        return true; // 保持 message channel 開啟以進行非同步回應
    }
});