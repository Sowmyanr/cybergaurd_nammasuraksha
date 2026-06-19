console.log('Cyber Guardian plugin loaded at', new Date().toISOString());

async function scanLink(link) {
  try {
    console.log('Attempting to scan', link);
    const response = await fetch('http://localhost:3000/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ link })
    });
    if (!response.ok) throw new Error('Scan failed: ' + response.status);
    const result = await response.json();
    console.log('Scan result for', link, ':', result);
    return result;
  } catch (error) {
    console.error('Scan error for', link, ':', error.message);
    return { isPhishing: true, message: 'Error scanning link', platform: 'Web', risk: 'Unknown', source: 'N/A' };
  }
}

async function injectIndicators() {
  console.log('Injecting indicators...');
  const links = document.querySelectorAll('a[href]');
  console.log('Found', links.length, 'links:', Array.from(links).map(l => l.href));

  for (const link of links) {
    const indicator = document.createElement('span');
    indicator.style.marginLeft = '5px';
    indicator.style.display = 'inline-flex';
    indicator.style.alignItems = 'center';
    console.log('Created indicator for', link.href);

    // Add shield SVG
    const shield = document.createElement('span');
    shield.innerHTML = `<svg class="shield" style="width: 16px; height: 16px; margin-right: 4px;" viewBox="0 0 24 24" fill="none" stroke="currentColor"><path d="M12 2L3 7v7c0 5 9 9 9 9s9-4 9-9V7l-9-5z" stroke-width="2"/></svg>`;
    shield.style.color = '#6b7280';
    indicator.appendChild(shield);
    console.log('Added shield SVG for', link.href);

    // Add text
    const text = document.createElement('span');
    text.style.fontSize = '12px';
    text.style.fontWeight = 'bold';
    text.textContent = '(Scanning...)';
    indicator.appendChild(text);

    link.appendChild(indicator);
    console.log('Appended indicator to link', link.href);

    const result = await scanLink(link.href);
    console.log('Updating indicator for', link.href, 'with result:', result);

    // Update shield and text
    shield.style.color = result.isPhishing ? '#ef4444' : '#22c55e';
    text.textContent = result.isPhishing ? '(Phishing)' : '(Safe)';
    text.style.color = result.isPhishing ? '#ef4444' : '#22c55e';

    // Add animation if anime is available
    if (typeof anime !== 'undefined') {
      console.log('Anime.js is available, animating shield for', link.href);
      anime({
        targets: shield.querySelector('.shield'),
        scale: [1, 1.2, 1],
        duration: 1000,
        easing: 'easeInOutQuad'
      });
    } else {
      console.warn('Anime.js not available, skipping animation for', link.href);
    }
  }
}

// Run immediately and on DOM content loaded
injectIndicators().catch(console.error);
document.addEventListener('DOMContentLoaded', () => {
  console.log('DOM content loaded, reinjecting indicators');
  injectIndicators().catch(console.error);
});

// Listen for messages from the extension to trigger rescanning
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg === 'rescan_links') {
      injectIndicators().catch(console.error);
      sendResponse({ status: 'rescanning' });
    }
  });
}