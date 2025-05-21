const express = require('express');
const fetch = require('node-fetch');
const dotenv = require('dotenv');
const cors = require('cors');
const { URL } = require('url');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Whitelist of safe domains (add more as you want)
const SAFE_DOMAINS = [
  'youtube.com',
  'www.youtube.com',
  'google.com',
  'www.google.com',
  'facebook.com',
  'www.facebook.com',
  'twitter.com',
  'www.twitter.com',
  'github.com',
  'www.github.com',
];

function extractDomain(inputUrl) {
  try {
    const urlObj = new URL(inputUrl);
    return urlObj.hostname.toLowerCase();
  } catch {
    // If inputUrl is just domain without protocol, add protocol to parse
    try {
      const urlObj = new URL('http://' + inputUrl);
      return urlObj.hostname.toLowerCase();
    } catch {
      return null;
    }
  }
}

app.post('/check-link', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'No URL provided' });

  const domain = extractDomain(url);
  if (!domain) {
    return res.json({ verdict: 'Warning : This URL might be Dangerous' });
  }

  console.log(`🔍 Scanning URL: ${url}, domain: ${domain}`);

  // Check whitelist first
  if (SAFE_DOMAINS.includes(domain)) {
    return res.json({ verdict: 'This URL is Safe' });
  }

  // If domain not in whitelist, proceed with urlscan.io scan
  try {
    const scanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': process.env.URLSCAN_API_KEY,
      },
      body: JSON.stringify({ url }),
    });

    if (!scanResponse.ok) {
      console.log('❌ Scan request failed with status:', scanResponse.status);
      return res.json({ verdict: 'Warning : This URL might be Dangerous' });
    }

    const { uuid } = await scanResponse.json();
    console.log(`✅ Scan started. UUID: ${uuid}`);

    let attempts = 0;
    let resultData;

    while (attempts < 5) {
      const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (!resultResponse.ok) {
        attempts++;
        await new Promise(r => setTimeout(r, 3000));
        continue;
      }

      resultData = await resultResponse.json();
      if (resultData.verdicts) break;

      attempts++;
      await new Promise(r => setTimeout(r, 3000));
    }

    if (!resultData || !resultData.verdicts) {
      return res.json({ verdict: 'Warning : This URL might be Dangerous' });
    }

    const score = resultData.verdicts.overall.score;
    if (score > 0) {
      return res.json({ verdict: 'Warning : This URL might be Dangerous' });
    } else {
      return res.json({ verdict: 'This URL is Safe' });
    }
  } catch (error) {
    console.error('🚨 Unexpected server error:', error.message);
    return res.json({ verdict: 'Warning : This URL might be Dangerous' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
