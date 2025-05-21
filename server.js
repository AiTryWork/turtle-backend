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

// Whitelist of known safe domains
const whitelist = ['youtube.com', 'www.youtube.com', 'google.com', 'www.google.com', 'facebook.com', 'twitter.com'];

app.post('/check-link', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ verdict: 'Warning: This URL might be Dangerous' });

  try {
    // Extract hostname from URL
    const parsedUrl = new URL(url.startsWith('http') ? url : `http://${url}`);
    const hostname = parsedUrl.hostname.toLowerCase();

    // Whitelist check
    if (whitelist.includes(hostname)) {
      return res.json({ verdict: 'This URL is Safe' });
    }

    // Scan with urlscan.io
    const scanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': process.env.URLSCAN_API_KEY,
      },
      body: JSON.stringify({ url }),
    });

    if (!scanResponse.ok) {
      return res.json({ verdict: 'Warning: This URL might be Dangerous' });
    }

    const scanData = await scanResponse.json();
    const uuid = scanData.uuid;

    let attempts = 0;
    let resultData;

    while (attempts < 5) {
      const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (resultResponse.ok) {
        resultData = await resultResponse.json();
        if (resultData.verdicts) break;
      }
      attempts++;
      await new Promise(r => setTimeout(r, 3000));
    }

    if (!resultData || !resultData.verdicts) {
      return res.json({ verdict: 'Warning: This URL might be Dangerous' });
    }

    const score = resultData.verdicts.overall.score;
    if (score > 0) {
      return res.json({ verdict: 'Warning: This URL might be Dangerous' });
    } else {
      return res.json({ verdict: 'This URL is Safe' });
    }

  } catch (error) {
    return res.json({ verdict: 'Warning: This URL might be Dangerous' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server is running on port ${PORT}`);
});
