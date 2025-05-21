// backend/server.js
const express = require('express');
const fetch = require('node-fetch');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();
const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.post('/check-link', async (req, res) => {
  try {
    let { url } = req.body;
    if (!url) {
      return res.status(400).json({ verdict: 'Error: No URL provided' });
    }

    // ─── Normalize the URL ───────────────────────────────────────
    url = url.trim();
    if (!/^https?:\/\//i.test(url)) {
      url = 'http://' + url;
    }
    // Use URL to get a consistently formatted href
    try {
      url = new URL(url).href;
    } catch {
      return res.json({ verdict: 'Warning: Invalid URL format' });
    }
    console.log(`Scanning normalized URL: ${url}`);

    // ─── Kick off the scan ───────────────────────────────────────
    const scanResp = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': process.env.URLSCAN_API_KEY,
      },
      body: JSON.stringify({ url })
    });

    if (!scanResp.ok) {
      console.error('Scan API error:', await scanResp.text());
      return res.json({ verdict: 'Warning: Could not start scan' });
    }
    const { uuid } = await scanResp.json();

    // ─── Poll for the finished result ────────────────────────────
    let resultData = null;
    for (let attempt = 0; attempt < 10; attempt++) {
      const resultResp = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (resultResp.ok) {
        const json = await resultResp.json();
        if (json.status === 'done' && json.verdicts) {
          resultData = json;
          break;
        }
      }
      // wait before retrying
      await new Promise(r => setTimeout(r, 2000));
    }

    if (!resultData || !resultData.verdicts) {
      return res.json({
        verdict: 'Warning: This URL’s domain appears invalid and could be malicious'
      });
    }

    // ─── Interpret the verdict ───────────────────────────────────
    const isMalicious = resultData.verdicts.overall.malicious;
    if (isMalicious) {
      return res.json({
        verdict: 'Warning: This URL’s domain appears invalid and could be malicious'
      });
    } else {
      return res.json({ verdict: 'safe' });
    }

  } catch (err) {
    console.error('Server error in /check-link:', err);
    return res.json({
      verdict: 'Warning: This URL’s domain appears invalid and could be malicious'
    });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
