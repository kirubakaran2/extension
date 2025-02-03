document.addEventListener('DOMContentLoaded', function() {
  const toggleSwitch = document.getElementById('toggleSwitch');
  const statusText = document.getElementById('status');
  const notificationContainer = document.getElementById('notificationContainer');

  // Load saved state
  chrome.storage.local.get(['isEnabled'], function(result) {
    toggleSwitch.checked = result.isEnabled || false;
    updateStatus(result.isEnabled);
  });

  toggleSwitch.addEventListener('change', function() {
    const isEnabled = toggleSwitch.checked;
    chrome.storage.local.set({ isEnabled: isEnabled });
    updateStatus(isEnabled);
    
    chrome.runtime.sendMessage({
      type: 'TOGGLE_PROTECTION',
      isEnabled: isEnabled
    });
  });

  // Listen for vulnerability notifications
  chrome.runtime.onMessage.addListener(function(message, sender, sendResponse) {
    if (message.type === 'VULNERABILITY_DETECTED') {
      showVulnerabilityPopup(message.vulnerabilityDetails);
    }
  });

  function updateStatus(isEnabled) {
    statusText.textContent = `Protection is ${isEnabled ? 'ON' : 'OFF'}`;
    statusText.style.color = isEnabled ? '#4CAF50' : '#f44336';
  }

  function showVulnerabilityPopup(details) {
    const popup = document.createElement('div');
    popup.className = 'vulnerability-popup';
    popup.innerHTML = `
      <div class="popup-content">
        <h2>⚠️ Security Alert!</h2>
        <p>${details}</p>
        <button id="closePopup">Close</button>
      </div>
    `;

    notificationContainer.innerHTML = '';
    notificationContainer.appendChild(popup);

    document.getElementById('closePopup').addEventListener('click', function() {
      popup.remove();
    });
  }
});