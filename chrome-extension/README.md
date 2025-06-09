# Smart Proxy Manager Chrome Extension

This Chrome extension allows you to easily enable/disable your Smart Proxy (running at 127.0.0.1:8080) and quickly access the proxy dashboard.

## Adding Icons

Before installing the extension, you need to add icon files to the `icons` folder:

1. Create or download three PNG icons of sizes 16x16, 48x48, and 128x128 pixels
2. Save them in the `chrome-extension/icons` folder as:
   - icon16.png (16x16 pixels)
   - icon48.png (48x48 pixels)
   - icon128.png (128x128 pixels)

You can use any proxy or security-related icons you prefer.

## Installing the Extension in Chrome

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" using the toggle in the top-right corner
3. Click "Load unpacked" and select the `chrome-extension` folder
4. The Smart Proxy Manager extension should now appear in your extensions list
5. Click the extension icon in the Chrome toolbar to open the popup interface

## Using the Extension

- Click "Enable Proxy" to configure Chrome to use your Smart Proxy (127.0.0.1:8080)
- Click "Disable Proxy" to return to system proxy settings
- Click "Open Dashboard" to access your proxy's dashboard (if running)

## Important Notes

- For HTTPS interception to work, make sure you've installed the mitmproxy certificate in Chrome
- The proxy must be running (using `mitmdump -s main.py`) for the extension to work properly
- The dashboard link will only work if the dashboard is enabled in your config.yaml
