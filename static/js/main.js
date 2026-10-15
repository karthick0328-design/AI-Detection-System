/**
 * Client-Side Application Scripts for AI-Based Phishing Detection System
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. Loading Overlay on Form Submission
    const analyzeForms = document.querySelectorAll(".analyze-form");
    const loadingOverlay = document.getElementById("loading-overlay");

    analyzeForms.forEach(form => {
        form.addEventListener("submit", function (e) {
            const input = form.querySelector("input[name='url']");
            if (!input || !input.value.trim()) {
                e.preventDefault();
                alert("Please enter a valid website URL.");
                return;
            }
            if (loadingOverlay) {
                loadingOverlay.style.display = "flex";
            }
        });
    });

    // 2. Sample URL Click Handlers
    const sampleButtons = document.querySelectorAll(".sample-url-btn");
    const mainUrlInput = document.getElementById("main-url-input");

    sampleButtons.forEach(btn => {
        btn.addEventListener("click", function () {
            const sampleUrl = this.getAttribute("data-url");
            if (mainUrlInput && sampleUrl) {
                mainUrlInput.value = sampleUrl;
                mainUrlInput.focus();
                // Smooth scroll to input
                mainUrlInput.scrollIntoView({ behavior: "smooth", block: "center" });
            }
        });
    });

    // 3. Copy to Clipboard Utility
    const copyBtns = document.querySelectorAll(".btn-copy");
    copyBtns.forEach(btn => {
        btn.addEventListener("click", function () {
            const targetText = this.getAttribute("data-copy");
            if (targetText) {
                navigator.clipboard.writeText(targetText).then(() => {
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="bi bi-check2"></i> Copied!';
                    setTimeout(() => {
                        this.innerHTML = originalText;
                    }, 2000);
                });
            }
        });
    });
});
