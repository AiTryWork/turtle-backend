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
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'No URL provided' });

  console.log(`🔍 Scanning URL: ${url}`);

  try {
    // Step 1: Send scan request to urlscan.io
    const scanResponse = await fetch('https://urlscan.io/api/v1/scan/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': process.env.URLSCAN_API_KEY,
      },
      body: JSON.stringify({ url }),
    });

    // Step 2: Handle scan request errors (e.g., DNS issues)
    if (!scanResponse.ok) {
      const errorData = await scanResponse.json();
      console.log('❌ Scan request failed:', errorData.message);

      if (errorData.message && errorData.message.toLowerCase().includes('resolve')) {
        return res.json({ verdict: '❗ Error: This domain does not exist or could not be resolved.' });
      }

      return res.json({ verdict: '⚠️ Warning: Could not start scan (API error)' });
    }

    const { uuid } = await scanResponse.json();
    console.log(`✅ Scan started. UUID: ${uuid}`);

    // Step 3: Poll result up to 5 times
    let resultData;
    let attempts = 0;

    while (attempts < 5) {
      const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (!resultResponse.ok) {
        console.log(`⏳ Waiting for result (attempt ${attempts + 1})...`);
        attempts++;
        await new Promise(r => setTimeout(r, 3000));
        continue;
      }

      resultData = await resultResponse.json();

      if (resultData.verdicts) break;

      attempts++;
      await new Promise(r => setTimeout(r, 3000));
    }

    // Step 4: No verdicts found
    if (!resultData || !resultData.verdicts) {
      return res.json({ verdict: '⚠️ Warning: Could not retrieve scan result.' });
    }

    // Step 5: Check verdict score
    const score = resultData.verdicts.overall.score;
    if (score > 0) {
      return res.json({ verdict: '⚠️ Warning: This URL appears malicious or suspicious.' });
    } else {
      return res.json({ verdict: '✅ The URL is SAFE to use.' });
    }
  } catch (error) {
    console.error('🚨 Unexpected server error:', error.message);
    return res.json({ verdict: '⚠️ Error: Something went wrong while scanning the link.' });
  }
});

app.listen(PORT, () => {
  console.log(`🚀 Server is running on port ${PORT}`);
});
