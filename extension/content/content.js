// Content script: Detect Microsoft 365 login UI signals in top frame

function isTopFrame() {
  try {
    return window.top === window;
  } catch {
    return false;
  }
}

function detectM365LoginUi(doc) {
  const d = doc || document;
  // Structural selectors resilient to localization
  const emailInput = d.querySelector('input[name="loginfmt"], #i0116');
  const passwordInput = d.querySelector('input[name="passwd"], #i0118');
  const nextButton = d.querySelector('#idSIButton9, input[type="submit"][value]');
  const brandImages = d.querySelector('img[src*="microsoft"], svg[data-icon-name="MicrosoftLogo"]');
  // Heuristic: presence of login email input and primary button is strong
  const strongLoginStruct = !!(emailInput && nextButton);
  const possiblePasswordPhase = !!(passwordInput && nextButton);
  const textHints = /work or school account|pick an account|stay signed in/i.test(d.body ? d.body.textContent || '' : '');
  const m365LoginDetected = strongLoginStruct || possiblePasswordPhase || (strongLoginStruct && textHints) || (brandImages && strongLoginStruct);
  return { m365LoginDetected };
}

function sendDomSignals() {
  const payload = detectM365LoginUi(document);
  if (payload.m365LoginDetected) {
    chrome.runtime.sendMessage({ type: 'domSignals', payload });
  }
}

if (isTopFrame()) {
  // Early try
  if (document.readyState === 'loading') {
    document.addEventListener('readystatechange', () => {
      if (document.readyState === 'interactive') sendDomSignals();
    });
  } else {
    sendDomSignals();
  }
  // Observe dynamic changes
  const observer = new MutationObserver(() => {
    sendDomSignals();
  });
  observer.observe(document.documentElement, { childList: true, subtree: true });
  // Safety: disconnect after some time to reduce overhead
  setTimeout(() => observer.disconnect(), 15000);
}


