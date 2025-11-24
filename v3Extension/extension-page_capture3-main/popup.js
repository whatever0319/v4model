document.addEventListener("DOMContentLoaded", () => {
    // --- 1. 設定與 DOM 元素選取 ---
    const API_BASE = "http://127.0.0.1:5000";

    const ui = {
        status: document.getElementById("status"),
        toggleBtn: document.getElementById("toggleBtn"),
        manualBtn: document.getElementById("manualBtn"),
        result: document.getElementById("result"),
        statusDetail: document.getElementById("status_detail"),
        // 黑名單區塊
        blAdd: document.getElementById("bl_add"),
        blClearAll: document.getElementById("bl_clear_all"),
        blList: document.getElementById("blacklist_list"),
        blToggle: document.getElementById("bl_toggle"),
        blSection: document.getElementById("bl_section"),
    };

    // --- 2. 工具函式 (Helpers) ---

    /**
     * 通用的後端 API 請求函式
     * @param {string} endpoint - 例如 "/add_blacklist"
     * @param {object} body - (選填) POST 的資料內容
     */
    async function callApi(endpoint, body = null) {
        try {
            const options = {
                headers: { "Content-Type": "application/json" }
            };
            
            if (body) {
                options.method = "POST";
                options.body = JSON.stringify(body);
            }

            const res = await fetch(`${API_BASE}${endpoint}`, options);
            return await res.json();
        } catch (err) {
            console.error(err);
            alert("無法連接後端伺服器");
            return null;
        }
    }

    /**
     * 取得當前分頁網址
     */
    function getCurrentTabUrl() {
        return new Promise((resolve) => {
            chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                resolve(tabs[0] ? tabs[0].url : null);
            });
        });
    }

    // --- 3. 主要功能邏輯 ---

    // 更新開關 UI 狀態
    function updateToggleUI(enabled) {
        ui.status.textContent = enabled ? "Enabled" : "Disabled";
        ui.status.style.color = enabled ? "green" : "red";
        ui.toggleBtn.textContent = enabled ? "關閉功能" : "啟動功能";
    }

    // 顯示分析結果
    function renderAnalysisResult(result) {
        if (!result) {
            ui.result.textContent = "尚未有分析資料。";
            return;
        }
        const elapsed = result.elapsed_time ?? "—";
        
        // 風險評分顯示
        let riskScoreHtml = "";
        if (result.risk_score !== null && result.risk_score !== undefined) {
            const score = result.risk_score;
            let riskClass = "risk-low";
            let riskText = "低風險";
            
            if (score >= 75) {
                riskClass = "risk-very-high";
                riskText = "極高風險";
            } else if (score >= 50) {
                riskClass = "risk-high";
                riskText = "高風險";
            } else if (score >= 20) {
                riskClass = "risk-medium";
                riskText = "中風險";
            }
            
            riskScoreHtml = `<span class="risk-score ${riskClass}">風險評分：${score}/100 (${riskText})</span>`;
        }
        
        // 相似網站檢測顯示
        let similarSiteHtml = "";
        if (result.similar_site_detection) {
            similarSiteHtml = `
                <div class="info-section" style="border-left-color: #dc3545;">
                    <div class="info-title">⚠️ 相似網站檢測</div>
                    <div>${result.similar_site_detection}</div>
                </div>
            `;
        }
        
        ui.result.innerHTML = `
            <div>
                <b>偵測結果：</b> ${result.is_potential_phishing ? "<span style='color: red;'>⚠️ 釣魚網站</span>" : "<span style='color: green;'>✓ 合法網站</span>"}
                ${riskScoreHtml}
            </div>
            <br>
            <div><b>理由：</b><br>${result.explanation}</div>
            ${similarSiteHtml}
            <br>
            <div style="font-size: 11px; color: #666;"><b>耗時：</b> ${elapsed} 秒</div>
        `;
    }

    // 載入並顯示黑名單 (只顯示最近 5 筆)
    async function loadBlacklist() {
        const data = await callApi("/user_blacklist");
        if (!data) return;

        const list = data.list || [];
        
        if (list.length === 0) {
            ui.blList.innerHTML = "<i>目前沒有黑名單項目</i>";
            return;
        }

        ui.blList.innerHTML = "";
        const recentList = list.slice(-5).reverse();

        recentList.forEach(url => {
            const row = document.createElement("div");
            row.className = "bl-item";
            row.innerHTML = `<span>${url}</span><span class="bl-del" style="cursor:pointer;">❌</span>`;

            row.querySelector(".bl-del").addEventListener("click", () => handleBlacklistAction("/delete_blacklist", url));
            
            ui.blList.appendChild(row);
        });
    }

    // 處理黑名單動作 (新增/刪除)
    async function handleBlacklistAction(endpoint, url) {
        if (!url) return alert("無效的網址");
        
        const data = await callApi(endpoint, { url });
        if (data) {
            alert(data.message);
            if (data.success) loadBlacklist();
        }
    }

    // --- 4. 初始化與事件監聽 ---

    // 初始化：讀取開關狀態
    chrome.storage.local.get({ enabled: true, analysis_running: false, last_analysis_result: null }, (items) => {
        updateToggleUI(items.enabled);
        
        if (items.analysis_running) {
            ui.result.innerHTML = `<i style="color:gray;">後端分析中...</i>`;
            ui.statusDetail.textContent = "分析中…";
        } else {
            renderAnalysisResult(items.last_analysis_result);
        }
    });

    // 監聽：開關按鈕
    ui.toggleBtn.addEventListener("click", () => {
        chrome.storage.local.get({ enabled: true }, (items) => {
            const newState = !items.enabled;
            chrome.storage.local.set({ enabled: newState }, () => updateToggleUI(newState));
        });
    });

    // 監聽：手動擷取
    ui.manualBtn.addEventListener("click", async () => {
        const tab = await new Promise(r => chrome.tabs.query({ active: true, currentWindow: true }, tabs => r(tabs[0])));
        if (tab) chrome.tabs.sendMessage(tab.id, { action: "manual_capture" });
    });

    // 監聽：後端訊息推播
    chrome.runtime.onMessage.addListener((msg) => {
        if (msg.stage === "開始分析") {
            chrome.storage.local.set({ analysis_running: true });
            ui.result.innerHTML = `<i style="color:gray;">後端分析中...</i>`;
            return;
        }
        if (msg.stage) ui.statusDetail.textContent = msg.stage;
        
        if (msg.type === "analysis_result_done") {
            chrome.storage.local.set({ analysis_running: false });
            ui.statusDetail.textContent = "";
            // 重新讀取 storage 顯示結果 (或是讓後端直接傳結果過來顯示也可以)
            chrome.storage.local.get("last_analysis_result", (d) => renderAnalysisResult(d.last_analysis_result));
        }
    });

    // 監聽：新增黑名單
    ui.blAdd.addEventListener("click", async () => {
        const url = await getCurrentTabUrl();
        handleBlacklistAction("/add_blacklist", url);
    });

    // 監聽：清空黑名單
    ui.blClearAll.addEventListener("click", async () => {
        if (!confirm("確定要清空「所有」黑名單嗎？此動作無法復原！")) return;
        
        const data = await callApi("/clear_blacklist", {}); // 空物件觸發 POST
        if (data) {
            alert(data.message);
            if (data.success) loadBlacklist();
        }
    });

    // 監聽：黑名單折疊
    ui.blToggle.addEventListener("click", () => {
        const isHidden = ui.blSection.style.display === "none";
        ui.blSection.style.display = isHidden ? "block" : "none";
        ui.blToggle.textContent = isHidden ? "使用者黑名單 ▲" : "使用者黑名單 ▼";
    });

    // 啟動時載入列表
    loadBlacklist();
});