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

  try {
    // Normalize URL
    url = url.trim();
    if (!/^https?:\/\//i.test(url)) {
      url = 'http://' + url;
    }
    url = new URL(url).href;
  } catch (err) {
    return res.json({ verdict: 'Warning: Invalid URL format' });
  }

  try {
    // STEP 1: Submit scan to urlscan.io
    const scanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': process.env.URLSCAN_API_KEY,
        'Referer': 'https://yourdomain.com' // <-- Add your domain or dummy
      },
      body: JSON.stringify({ url })
    });

    if (!scanResponse.ok) {
  const errorData = await scanResponse.json();
  console.log('Scan API error:', errorData.message);
  
  if (errorData.message && errorData.message.includes('resolve')) {
    return res.json({ verdict: 'Error: This domain does not exist or could not be resolved.' });
  }

  return res.json({ verdict: 'Warning: Could not start scan (API error)' });
}


    const scanData = await scanResponse.json();
    const uuid = scanData.uuid;
    console.log(`✅ Scan submitted for ${url}, UUID: ${uuid}`);

    // STEP 2: Poll for result
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
      console.log(`⏳ Waiting for scan result... (${attempt + 1}/10)`);
      await new Promise(r => setTimeout(r, 2000));
    }

    if (!resultData) {
      console.log('❌ Result polling failed or scan not ready.');
      return res.json({ verdict: 'Warning: Scan timed out or failed' });
    }

    // STEP 3: Verdict logic
    const malicious = resultData.verdicts.overall.malicious;
    if (malicious === true) {
      return res.json({ verdict: 'Warning: This URL’s domain appears invalid and could be malicious' });
    } else {
      return res.json({ verdict: 'safe' });
    }

  } catch (err) {
    console.error('❌ Unexpected server error:', err.message);
    return res.json({ verdict: 'Warning: Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
