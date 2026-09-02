import asyncio, sys, base64, os
sys.path.insert(0, "web/tests")
import browser_interaction_test as T
OUT = "/root/Git/github/Fob/docs/screenshots"
async def main():
    chrome = T.Chromium(); chrome.start()
    try:
        # vault-main on fresh page at 1500
        cdp = await chrome.open_page()
        await cdp.send("Emulation.setDeviceMetricsOverride", {"width":1500,"height":950,"deviceScaleFactor":1,"mobile":False})
        await cdp.send("Page.reload", {"ignoreCache":True})
        try: await cdp.wait_for_event("Page.loadEventFired", timeout=6)
        except Exception: pass
        await asyncio.sleep(1.0)
        await T.create_vault(cdp)
        await T.add_password(cdp, "GitHub", "alice@example.com", "s3cure-Passw0rd!")
        await T.add_totp(cdp, "GitHub", "alice@example.com", "JBSWY3DPEHPK3PXP")
        await T.add_password(cdp, "Email", "alice@example.com", "another-pw-123")
        await T.add_password(cdp, "Bank", "alice", "bank-passphrase")
        await asyncio.sleep(0.6)
        r = await cdp.send("Page.captureScreenshot", {"format":"png"})
        with open(os.path.join(OUT,"vault-main.png"),"wb") as f: f.write(base64.b64decode(r["result"]["data"]))
        print("vault-main done")
        await cdp.close()

        # site on fresh page at 1500
        cdp2 = await chrome.open_page()
        await cdp2.send("Emulation.setDeviceMetricsOverride", {"width":1500,"height":950,"deviceScaleFactor":1,"mobile":False})
        await cdp2.send("Page.navigate", {"url":"file:///root/Git/github/Fob/site/index.html"})
        try: await cdp2.wait_for_event("Page.loadEventFired", timeout=6)
        except Exception: pass
        await asyncio.sleep(1.2)
        r = await cdp2.send("Page.captureScreenshot", {"format":"png"})
        with open(os.path.join(OUT,"site-landing.png"),"wb") as f: f.write(base64.b64decode(r["result"]["data"]))
        print("site-landing done")
        await cdp2.close()
    finally:
        chrome.stop()
asyncio.run(main())
