const express = require('express');
const fetch = require('node-fetch');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();
const app = express();

// Use dynamic port provided by Render, fallback to 3000 for local dev
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

app.post('/check-link', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'No URL provided' });

  console.log(`Received URL to scan: ${url}`);

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
      const errorData = await scanResponse.json();
      console.log('Scan API error:', errorData.message);
      return res.json({ verdict: 'Warning: This URL’s domain appears invalid and could be malicious' });
    }

    const scanData = await scanResponse.json();
    const uuid = scanData.uuid;
    console.log('Scan started, UUID:', uuid);

    let attempts = 0;
    let resultData;

    while (attempts < 5) {
      const resultResponse = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (!resultResponse.ok) {
        console.log('Result API response not ok:', resultResponse.status);
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
      return res.json({ verdict: 'Warning: This URL’s domain appears invalid and could be malicious' });
    }

    const score = resultData.verdicts.overall.score;
    if (score > 0) {
      return res.json({ verdict: 'Warning: This URL’s domain appears invalid and could be malicious' });
    } else {
      return res.json({ verdict: 'safe' });
    }
  } catch (error) {
    console.error('Unexpected server error:', error.message);
    res.json({ verdict: 'Warning: This URL’s domain appears invalid and could be malicious' });
  }
});

// Listen on dynamic port
app.listen(PORT, () => {
  console.log(`✅ Server is running on port ${PORT}`);
});
