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
  let { url } = req.body;
  if (!url) {
    return res.status(400).json({ verdict: 'Warning: No URL provided' });
  }

  // Normalize URL
  try {
    url = url.trim();
    if (!/^https?:\/\//i.test(url)) {
      url = 'http://' + url;
    }
    url = new URL(url).href;
  } catch (err) {
    return res.json({ verdict: 'Warning: Invalid URL format' });
  }

  try {
    // Step 1: Submit scan to urlscan.io
    const scanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': process.env.URLSCAN_API_KEY,
      },
      body: JSON.stringify({ url })
    });

    if (!scanResponse.ok) {
      const errorText = await scanResponse.text();
      console.error('Scan API failed:', errorText);
      return res.json({ verdict: 'Warning: Could not start scan' });
    }

    const scanData = await scanResponse.json();
    const uuid = scanData.uuid;
    console.log(`Scan started for ${url}, UUID: ${uuid}`);

    // Step 2: Poll for result
    let resultData = null;
    for (let attempt = 0; attempt < 10; attempt++) {
      const resultResp = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (resultResp.ok) {
        const json = await resultResp.json();
        if (json.verdicts && json.verdicts.overall) {
          resultData = json;
          break;
        }
      }
      await new Promise(r => setTimeout(r, 2000)); // Wait before retrying
    }

    if (!resultData) {
      return res.json({ verdict: 'Warning: Scan timed out or failed' });
    }

    // Step 3: Final verdict logic
    const malicious = resultData.verdicts.overall.malicious;
    if (malicious === true) {
      return res.json({ verdict: 'Warning: This URL’s domain appears invalid and could be malicious' });
    } else {
      return res.json({ verdict: 'safe' });
    }
  } catch (err) {
    console.error('Unexpected server error:', err.message);
    return res.json({ verdict: 'Warning: Something went wrong during scanning' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
