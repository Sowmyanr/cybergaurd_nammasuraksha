function detectPhishing(link) {
    const isPhishing = link.toLowerCase().includes('phish') || Math.random() > 0.8;
    return {
      isPhishing,
      message: isPhishing ? 'Phishing link detected! Do not click.' : 'Link appears safe.',
      platform: 'Web',
      risk: isPhishing ? 'High' : 'Low'
    };
  }
  
  module.exports = { detectPhishing };