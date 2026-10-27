"""Generate the human-verification JSON payload used by tests/e2e-real/run.sh.

Usage: python3 report.py {human|headless} <challenge_id> <nonce>
Prints the JSON body for POST /__agentwall_verify.
"""
import json
import sys

HUMAN = {
    "webdriver": False,
    "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/124.0.0.0 Safari/537.36",
    "languages": ["en-US", "en"],
    "plugins": 5,
    "mimeTypes": 2,
    "chrome": True,
    "webglVendor": "Google Inc. (NVIDIA)",
    "webglRenderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
    "hardwareConcurrency": 8,
    "deviceMemory": 8,
    "screenW": 1920,
    "screenH": 1080,
    "outerW": 1920,
    "outerH": 1040,
    "timezoneOffset": -420,
    "notification": "default",
    "pdfViewer": True,
    "touchPoints": 0,
    "cdp": False,
}

# Strix default sandbox browser (containers/Dockerfile):
#   AGENT_BROWSER_USER_AGENT = normal Chrome/131
#   AGENT_BROWSER_ARGS includes --disable-blink-features=AutomationControlled
# so navigator.webdriver is false, but the container headless build still has an
# empty plugin surface, a SwiftShader rasterizer and the PDF viewer disabled.
STRIX = {
    "webdriver": False,
    "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "Chrome/131.0.0.0 Safari/537.36",
    "languages": ["en-US"],
    "plugins": 0,
    "mimeTypes": 0,
    "chrome": True,
    "webglVendor": "Google Inc. (Google)",
    "webglRenderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) "
                     "(0x0000C0DE)), SwiftShader driver)",
    "hardwareConcurrency": 4,
    "deviceMemory": 8,
    "screenW": 800,
    "screenH": 600,
    "outerW": 800,
    "outerH": 600,
    "timezoneOffset": 0,
    "notification": "denied",
    "pdfViewer": False,
    "touchPoints": 0,
    "cdp": False,
}

# Default Playwright/Puppeteer headless Chromium (no stealth patches).
HEADLESS = {
    "webdriver": True,
    "ua": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
          "HeadlessChrome/124.0.0.0 Safari/537.36",
    "languages": [],
    "plugins": 0,
    "mimeTypes": 0,
    "chrome": False,
    "webglVendor": "Google Inc. (Google)",
    "webglRenderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero) "
                     "(0x0000C0DE)), SwiftShader driver)",
    "hardwareConcurrency": 4,
    "deviceMemory": 8,
    "screenW": 800,
    "screenH": 600,
    "outerW": 0,
    "outerH": 0,
    "timezoneOffset": 0,
    "notification": "denied",
    "pdfViewer": False,
    "touchPoints": 0,
    "cdp": True,
}


def main():
    if len(sys.argv) != 4:
        sys.exit("usage: report.py {human|headless|strix} <challenge_id> <nonce>")
    kind, chal_id, nonce = sys.argv[1], sys.argv[2], sys.argv[3]
    report = {"human": HUMAN, "headless": HEADLESS, "strix": STRIX}.get(kind)
    if report is None:
        sys.exit("unknown report kind: " + kind)
    print(json.dumps({"id": chal_id, "nonce": nonce, "report": report}))


if __name__ == "__main__":
    main()
