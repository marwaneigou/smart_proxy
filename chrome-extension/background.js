// Default proxy configuration
const DEFAULT_CONFIG = {
  proxyHost: '127.0.0.1',
  proxyPort: 8080,
  proxyEnabled: false
};

// Initialize extension on install
chrome.runtime.onInstalled.addListener(() => {
  // Set default configuration
  chrome.storage.local.get(Object.keys(DEFAULT_CONFIG), (result) => {
    // Only set values that don't already exist
    const newValues = {};
    for (const [key, defaultValue] of Object.entries(DEFAULT_CONFIG)) {
      if (result[key] === undefined) {
        newValues[key] = defaultValue;
      }
    }
    
    if (Object.keys(newValues).length > 0) {
      chrome.storage.local.set(newValues);
    }
  });
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'updateProxy') {
    updateProxySettings(message.enabled)
      .then(() => sendResponse({ success: true }))
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true; // Keep the message channel open for async response
  }
});

// Function to update proxy settings
async function updateProxySettings(enabled) {
  try {
    if (enabled) {
      // Get proxy configuration from storage
      const config = await new Promise((resolve) => {
        chrome.storage.local.get(['proxyHost', 'proxyPort'], resolve);
      });
      
      const host = config.proxyHost || DEFAULT_CONFIG.proxyHost;
      const port = config.proxyPort || DEFAULT_CONFIG.proxyPort;
      
      // Apply proxy settings
      await chrome.proxy.settings.set({
        value: {
          mode: 'fixed_servers',
          rules: {
            singleProxy: {
              scheme: 'http',
              host: host,
              port: parseInt(port)
            },
            bypassList: ['localhost']
          }
        },
        scope: 'regular'
      });
      
      console.log(`Proxy enabled: ${host}:${port}`);
    } else {
      // Disable proxy by setting to system settings
      await chrome.proxy.settings.set({
        value: { mode: 'system' },
        scope: 'regular'
      });
      
      console.log('Proxy disabled');
    }
    
    // Update storage with new state
    chrome.storage.local.set({ proxyEnabled: enabled });
    
    return true;
  } catch (error) {
    console.error('Error updating proxy settings:', error);
    throw error;
  }
}
