const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

const port = process.env.PORT || 3000;

const API_KEY = process.env.API_KEY || 'YOUR_API_KEY';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'YOUR_CLIENT_SECRET';
const SCOPES = process.env.SCOPES || 'PRODUCTS_MANAGE,BOOKINGS_CREATE';
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://your-render-app-url.com/callback';
const BOKUN_HOST = process.env.BOKUN_HOST || 'bokun.io';

// In-memory store for demonstration purposes
const sessions = {};

/**
 * Helper: verifyHmac
 */
function verifyHmac(query, secret) {
  const { hmac: providedHmac, ...params } = query;
  const sortedKeys = Object.keys(params).sort();
  const message = sortedKeys.map(key => `${key}=${params[key]}`).join('&');
  const computedHmac = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');

  console.log('Message for HMAC:', message);
  console.log('Provided HMAC:', providedHmac);
  console.log('Computed HMAC:', computedHmac);

  return computedHmac === providedHmac;
}

/**
 * ROUTE 1: /install
 * Bokun calls this URL with query params (domain, hmac, timestamp, user).
 */
app.get('/install', (req, res) => {
  const query = req.query;
  console.log('Received /install request with query:', query);

  // 1. Verify HMAC
  if (!verifyHmac(query, CLIENT_SECRET)) {
    return res.status(400).send('Invalid HMAC on install request');
  }

  const { domain, user, timestamp } = query;

  // 2. Generate a random nonce and store session data
  const nonce = crypto.randomBytes(16).toString('hex');
  sessions[nonce] = { user, domain, timestamp };

  // 3. Build the Bokun authorization URL
  const authUrl = `https://${domain}.${BOKUN_HOST}/appstore/oauth/authorize?client_id=${API_KEY}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&state=${nonce}`;

  console.log('Redirecting to Bokun authorization URL:', authUrl);

  // 4. Instead of a direct redirect, send an HTML page with a loading screen
  //    and a small script that automatically redirects after a short delay.
  const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <title>Redirecting to Bokun</title>
      <!-- Tailwind CSS via CDN -->
      <link href="https://cdn.jsdelivr.net/npm/tailwindcss@3.2.0/dist/tailwind.min.css" rel="stylesheet">
      <script>
        // Redirect after a brief delay (e.g., 1 second), or set it to 0 for immediate redirect
        setTimeout(function() {
          window.location.href = "${authUrl}";
        }, 1000);
      </script>
    </head>
    <body class="bg-gray-100 h-screen flex items-center justify-center">
      <div class="flex flex-col items-center">
        <!-- Spinner -->
        <div class="animate-spin rounded-full h-16 w-16 border-b-4 border-blue-500"></div>
        <!-- Loading text -->
        <p class="mt-6 text-lg text-gray-600">Preparing to redirect...</p>
      </div>
    </body>
    </html>
  `;

  res.send(html);
});

/**
 * ROUTE 2: /callback
 * Bokun redirects here after the user authorizes your app.
 */
app.get('/callback', async (req, res) => {
  const query = req.query;
  console.log('Received /callback request with query:', query);

  // Bokun sends 'state' instead of 'nonce' in the callback
  const { domain, state, timestamp, hmac, code } = query;

  // Check if the nonce (aka state) exists
  if (!state || !sessions[state]) {
    return res.status(400).send('Invalid or missing nonce/state');
  }

  // Verify the HMAC of the callback request
  if (!verifyHmac(query, CLIENT_SECRET)) {
    return res.status(400).send('Invalid HMAC on callback request');
  }

  // Exchange authorization code for an access token
  const tokenUrl = `https://${domain}.${BOKUN_HOST}/appstore/oauth/access_token`;

  try {
    const tokenResponse = await axios.post(tokenUrl, {
      client_id: API_KEY,
      client_secret: CLIENT_SECRET,
      code: code
    });

    const tokenData = tokenResponse.data;
    console.log('Received access token data:', tokenData);

    // Retrieve stored session info
    const sessionData = sessions[state];

    // Prepare data to "store"
    const storeData = {
      user: sessionData.user,
      domain: sessionData.domain,
      nonce: state,
      access_token: tokenData.access_token,
      scope: tokenData.scope,
      vendor_id: tokenData.vendor_id
    };

    console.log('Storing data to webhook (simulated DB):', storeData);
    await axios.post('https://webhook.site/054f59c1-a4f2-493b-b21c-c2c95527df19', storeData);

    delete sessions[state];
    res.send('App successfully installed and data stored!');
  } catch (error) {
    console.error('Error exchanging authorization code for access token:', error.message);
    res.status(500).send('Error exchanging authorization code for access token');
  }
});

// Start server
app.listen(port, () => {
  console.log(`Bokun OAuth app listening on port ${port}`);
});
