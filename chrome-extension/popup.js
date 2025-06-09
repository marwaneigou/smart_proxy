document.addEventListener('DOMContentLoaded', () => {
  const toggleButton = document.getElementById('toggleProxy');
  const statusContainer = document.getElementById('statusContainer');
  const proxyHost = document.getElementById('proxyHost');
  const proxyPort = document.getElementById('proxyPort');
  
  // Load current proxy settings
  chrome.storage.local.get(['proxyEnabled', 'proxyHost', 'proxyPort'], (result) => {
    // Set default values if not set
    const enabled = result.proxyEnabled || false;
    const host = result.proxyHost || '127.0.0.1';
    const port = result.proxyPort || 8080;
    
    // Update UI
    updateUI(enabled, host, port);
  });
  
  // Toggle proxy button handler
  toggleButton.addEventListener('click', () => {
    chrome.storage.local.get(['proxyEnabled'], (result) => {
      const currentState = result.proxyEnabled || false;
      const newState = !currentState;
      
      // Update storage
      chrome.storage.local.set({ proxyEnabled: newState }, () => {
        // Send message to background script to update proxy
        chrome.runtime.sendMessage({ 
          action: 'updateProxy', 
          enabled: newState 
        }, (response) => {
          if (response && response.success) {
            // Update UI after successful proxy change
            chrome.storage.local.get(['proxyHost', 'proxyPort'], (data) => {
              updateUI(newState, data.proxyHost, data.proxyPort);
            });
          }
        });
      });
    });
  });
  
  // Function to update UI based on proxy state
  function updateUI(enabled, host, port) {
    // Update host and port display
    proxyHost.textContent = host;
    proxyPort.textContent = port;
    
    // Update status display
    if (enabled) {
      statusContainer.className = 'status active';
      statusContainer.textContent = 'Proxy: Active';
      toggleButton.textContent = 'Disable Proxy';
      toggleButton.classList.remove('off');
    } else {
      statusContainer.className = 'status inactive';
      statusContainer.textContent = 'Proxy: Inactive';
      toggleButton.textContent = 'Enable Proxy';
      toggleButton.classList.add('off');
    }
  }
});
