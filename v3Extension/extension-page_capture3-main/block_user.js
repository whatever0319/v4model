document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(location.search);
    const target = params.get("target");

    const targetEl = document.getElementById("targetText");
    if (targetEl) targetEl.textContent = target || "(未知目標)";

    const goBtn = document.getElementById("go");
    if (!goBtn) return;

    goBtn.addEventListener("click", () => {
        chrome.runtime.sendMessage(
            { type: "open_original_site", target },
            () => void chrome.runtime.lastError
        );
    });
});
