let isEnabled = false;
let lastCheckedUrl = ''; 

// storage
chrome.storage.local.get(['isEnabled'], function(result) {
    isEnabled = result.isEnabled || false;
    console.log("Extension enabled state:", isEnabled);
});

// checking for common patterns
function isCommonlyBlockedURL(url) {
    const suspiciousPatterns = [
        'about:blank',
        'chrome://',
        'chrome-extension://',
        'file://',
        'view-source:',
        'data:',
        'javascript:'
    ];
    return suspiciousPatterns.some(pattern => url.toLowerCase().startsWith(pattern));
}

// Function to check for security certificate issues
async function checkCertificateStatus(url) {
    try {
        const response = await fetch(url, { method: 'HEAD' });
        return response.ok;
    } catch (error) {
        console.log('Certificate or connection error:', error);
        return false;
    }
}

// Listen for toggle changes
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'TOGGLE_PROTECTION') {
        isEnabled = message.isEnabled;
        chrome.storage.local.set({ isEnabled: message.isEnabled });
        console.log("Protection toggled, new state:", isEnabled);
    }
});

// Listen to web navigation changes including errors
chrome.webNavigation.onErrorOccurred.addListener((details) => {
    if (isEnabled && details.frameId === 0) {
        handleNavigationError(details);
    }
});

function handleNavigationError(details) {
    const errorMessages = {
        'net::ERR_CONNECTION_REFUSED': 'Connection was refused. This could be a malicious site.',
        'net::ERR_CERT_INVALID': 'Invalid SSL certificate detected. Site might be unsafe.',
        'net::ERR_CERT_AUTHORITY_INVALID': 'Invalid certificate authority. Possible security risk.',
        'net::ERR_SSL_PROTOCOL_ERROR': 'SSL protocol error. Connection might be compromised.',
        'net::ERR_CERT_COMMON_NAME_INVALID': 'Domain name mismatch. Possible phishing attempt.',
        'net::ERR_BAD_SSL_CLIENT_AUTH_CERT': 'Invalid client authentication certificate.',
        'net::ERR_CERT_REVOKED': 'Website certificate has been revoked.',
        'net::ERR_BLOCKED_BY_ADMINISTRATOR': 'This site is blocked by your organization.',
        'net::ERR_UNSAFE_PORT': 'The requested port is not secure.'
    };

    const errorMessage = errorMessages[details.error] || 'Security risk detected with this website.';

    showSecurityAlert(details.tabId, errorMessage);
}

// Main navigation listener
chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (!isEnabled || details.frameId !== 0) {
        return;
    }

    const url = details.url;

    // Skip already checked URLs and special protocols
    if (url === lastCheckedUrl || isCommonlyBlockedURL(url)) {
        return;
    }

    lastCheckedUrl = url;

    try {
        // First check if the site has certificate issues
        const isCertValid = await checkCertificateStatus(url);
        if (!isCertValid) {
            showSecurityAlert(details.tabId, 'Invalid security certificate detected. Site might be unsafe.');
            return;
        }

        // Then check with your backend
        const response = await fetch('http://localhost:5000/check', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                url: url,
                timestamp: new Date().toISOString(),
                referrer: details.referrer || '',
            })
        });

        if (!response.ok) {
            throw new Error(`Server error: ${response.status}`);
        }

        const data = await response.json();

        // Check if the response contains a message that requires a redirect
        if (data.message.includes('Vulnerable IP found!') ||
            data.message.includes('Vulnerable domain found!') ||
            data.message.includes('Vulnerable link found!')) {

            showSecurityAlert(details.tabId, data.message);
            // Trigger the redirect after 2 seconds
            setTimeout(() => {
                chrome.tabs.update(details.tabId, { url: 'https://www.google.com' });
            }, 2000);
        } else if (data.message.includes('Vulnerable')) {
            showSecurityAlert(details.tabId, data.message);
        }

    } catch (error) {
        console.error('Error during security check:', error);
        // If we can't reach our security check service, err on the side of caution
        showSecurityAlert(details.tabId, 'Unable to verify site security. Proceed with caution.');
    }
});

function showSecurityAlert(tabId, message) {
    // Show notification
    chrome.notifications.create({
        type: 'basic',
        iconUrl: 'images/icon128.png',
        title: 'Security Alert!',
        message: message,
        priority: 2,
        requireInteraction: true
    });

    // Inject warning banner
    chrome.scripting.executeScript({
        target: { tabId: tabId },
        function: showWarning,
        args: [message]
    }).catch(error => {
        console.error('Failed to inject warning banner:', error);
    });

    // Send message to popup
    chrome.runtime.sendMessage({
        type: 'VULNERABILITY_DETECTED',
        vulnerabilityDetails: message
    });
}

function showWarning(message) {
    if (!document.getElementById('security-warning')) {
        const warningDiv = document.createElement('div');
        warningDiv.id = 'security-warning';
        warningDiv.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            background-color: #ff4444;
            color: white;
            padding: 15px;
            text-align: center;
            z-index: 2147483647;
            font-size: 16px;
            font-family: Arial, sans-serif;
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
            display: flex;
            justify-content: center;
            align-items: center;
        `;

        const textSpan = document.createElement('span');
        textSpan.textContent = message;

        const closeButton = document.createElement('button');
        closeButton.textContent = '×';
        closeButton.style.cssText = `
            margin-left: 15px;
            background: none;
            border: none;
            color: white;
            font-size: 20px;
            cursor: pointer;
            padding: 0 5px;
        `;
        closeButton.onclick = function() {
            warningDiv.remove();
        };

        warningDiv.appendChild(textSpan);
        warningDiv.appendChild(closeButton);
        document.body.prepend(warningDiv);
    }
}
