document.addEventListener("DOMContentLoaded", () => {
    const params = new URLSearchParams(location.search);
    const target = params.get("target");

    const targetText = document.getElementById("targetText");
    if (targetText) {
        targetText.textContent = target;
    }

    const btn = document.getElementById("go");
    if (btn) {
        btn.addEventListener("click", () => {
            chrome.runtime.sendMessage({
                type: "open_original_site",
                target
            });
        });
    }
});
