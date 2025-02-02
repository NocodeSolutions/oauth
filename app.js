// app.js
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

const port = process.env.PORT || 3000;

// ====== CONFIGURATION ======
// These values should be set as environment variables in Render.
// For local testing, you can create a .env file (and use a package like dotenv) or set them manually.
const API_KEY = process.env.API_KEY || 'YOUR_API_KEY';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'YOUR_CLIENT_SECRET';
const SCOPES = process.env.SCOPES || 'PRODUCTS_MANAGE,BOOKINGS_CREATE';
// IMPORTANT: For local testing, you might use http://localhost:3000/callback,
// but when deployed on Render, update REDIRECT_URI to your Render app URL.
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://your-render-app-url.com/callback';

// In-memory session store (for demonstration only – use a proper persistent store in production)
const sessions = {};

/**
 * Helper: Verify HMAC signature.
 * - Removes the hmac parameter from the query.
 * - Sorts the remaining keys.
 * - Joins them as key=value pairs separated by &.
 * - Computes a SHA256 HMAC digest using the provided secret.
 * Returns true if the computed HMAC matches the provided one.
 */
function verifyHmac(query, secret) {
  // Remove the provided hmac from the query parameters
  const { hmac: providedHmac, ...params } = query;

  // Sort the remaining keys alphabetically
  const sortedKeys = Object.keys(params).sort();

  // Build the message string as: key1=value1&key2=value2...
  const message = sortedKeys.map(key => `${key}=${params[key]}`).join('&');

  // Compute the HMAC using SHA256 and the provided secret
  const computedHmac = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');

  console.log('Message for HMAC:', message);
  console.log('Provided HMAC:', providedHmac);
  console.log('Computed HMAC:', computedHmac);

  // Return true if the computed HMAC exactly matches the provided one
  return computedHmac === providedHmac;
}

// ====== ROUTE 1: Initial Endpoint Called by Bokun ======
// This route is called by Bokun (e.g., when a vendor starts installing your app).
// Example: GET /install?domain=nocodesolutionsltd&hmac=...&timestamp=...&user=3413
app.get('/install', (req, res) => {
  const query = req.query;
  console.log('Received /install request with query:', query);

  // Verify the HMAC of the incoming request.
  if (!verifyHmac(query, CLIENT_SECRET)) {
    return res.status(400).send('Invalid HMAC on install request');
  }

  const { domain, user, timestamp } = query;

  // Generate a random nonce to be used as the state parameter.
  const nonce = crypto.randomBytes(16).toString('hex');

  // Save the session data (in production, use a proper session or database storage).
  sessions[nonce] = { user, domain, timestamp };

  // Construct the Bokun authorisation URL.
  const authUrl = `https://${domain}.bokun.io/appstore/oauth/authorize?client_id=${API_KEY}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&state=${nonce}`;

  console.log('Redirecting vendor to Bokun authorisation URL:', authUrl);
  res.redirect(authUrl);
});

// ====== ROUTE 2: Callback Endpoint ======
// After the vendor authorises your app, Bokun redirects to your callback URL.
// Example: GET /callback?domain=nocodesolutionsltd&nonce=...&timestamp=...&hmac=...&authorization_code=...
app.get('/callback', async (req, res) => {
  const query = req.query;
  console.log('Received /callback request with query:', query);

  const { domain, nonce, timestamp, hmac, authorization_code } = query;

  // Check that the nonce exists in our sessions store.
  if (!nonce || !sessions[nonce]) {
    return res.status(400).send('Invalid or missing nonce');
  }

  // Verify the HMAC for the callback request.
  if (!verifyHmac(query, CLIENT_SECRET)) {
    return res.status(400).send('Invalid HMAC on callback request');
  }

  // Exchange the authorization code for an access token.
  const tokenUrl = `https://${domain}.bokun.io/appstore/oauth/access_token`;

  try {
    const tokenResponse = await axios.post(tokenUrl, {
      client_id: API_KEY,
      client_secret: CLIENT_SECRET,
      code: authorization_code
    });
    const tokenData = tokenResponse.data;
    console.log('Received access token data:', tokenData);

    // Retrieve saved session data.
    const sessionData = sessions[nonce];

    // Prepare data to store (simulated database).
    const storeData = {
      user: sessionData.user,
      domain: sessionData.domain,
      nonce,
      access_token: tokenData.access_token,
      scope: tokenData.scope,
      vendor_id: tokenData.vendor_id
    };

    console.log('Storing data to webhook (simulated DB):', storeData);

    // POST the data to a webhook (simulate database storage).
    await axios.post('https://webhook.site/054f59c1-a4f2-493b-b21c-c2c95527df19', storeData);

    // Clean up the session.
    delete sessions[nonce];

    res.send('App successfully installed and data stored!');
  } catch (error) {
    console.error('Error exchanging authorization code for access token:', error.message);
    res.status(500).send('Error exchanging authorization code for access token');
  }
});

// ====== START THE SERVER ======
app.listen(port, () => {
  console.log(`Bokun OAuth app listening on port ${port}`);
});
