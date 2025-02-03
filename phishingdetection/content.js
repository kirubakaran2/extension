// Listen for changes or events in the page, then send URL to background.js
const url = window.location.href;

// Send message to background to check if the website is vulnerable
chrome.runtime.sendMessage({ type: "checkVulnerability", url: url }, (response) => {
  if (response.result && response.result.vulnerable) {
    alert('This website is vulnerable! Do not access it.');
  }
});
