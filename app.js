// app.js
const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const app = express();

const port = process.env.PORT || 3000;

// ====== CONFIGURATION ======
// Set these values in your environment (or via a .env file with dotenv)
const API_KEY = process.env.API_KEY || 'YOUR_API_KEY';
const CLIENT_SECRET = process.env.CLIENT_SECRET || 'YOUR_CLIENT_SECRET';
const SCOPES = process.env.SCOPES || 'PRODUCTS_MANAGE,BOOKINGS_CREATE';
const REDIRECT_URI = process.env.REDIRECT_URI || 'https://your-render-app-url.com/callback';
// Use this variable to switch between bokun.io and bokuntest.com (or any other host)
const BOKUN_HOST = process.env.BOKUN_HOST || 'bokun.io';

// In-memory session store (for demonstration purposes only)
const sessions = {};

/**
 * Helper: Verify HMAC signature.
 * 1. Removes the 'hmac' parameter.
 * 2. Sorts the remaining keys alphabetically.
 * 3. Joins them as key=value pairs separated by '&'.
 * 4. Computes a SHA256 HMAC digest using the provided secret.
 * Returns true if the computed HMAC matches the provided one.
 */
function verifyHmac(query, secret) {
  // Extract and remove the 'hmac' parameter from the query object.
  const { hmac: providedHmac, ...params } = query;

  // Sort the keys alphabetically.
  const sortedKeys = Object.keys(params).sort();

  // Build the message string in the format key1=value1&key2=value2...
  const message = sortedKeys.map(key => `${key}=${params[key]}`).join('&');

  // Compute the HMAC using SHA256 with the provided secret.
  const computedHmac = crypto
    .createHmac('sha256', secret)
    .update(message)
    .digest('hex');

  console.log('Message for HMAC:', message);
  console.log('Provided HMAC:', providedHmac);
  console.log('Computed HMAC:', computedHmac);

  return computedHmac === providedHmac;
}

// ====== ROUTE 1: /install ======
// This route is called by Bokun when a vendor begins installing your app.
// Example: /install?domain=nocodesolutionsltd&hmac=...&timestamp=...&user=3413
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

  // Store session data keyed by the nonce.
  sessions[nonce] = { user, domain, timestamp };

  // Construct the Bokun authorization URL.
  const authUrl = `https://${domain}.${BOKUN_HOST}/appstore/oauth/authorize?client_id=${API_KEY}` +
    `&scope=${encodeURIComponent(SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}` +
    `&state=${nonce}`;

  console.log('Redirecting vendor to Bokun authorization URL:', authUrl);
  res.redirect(authUrl);
});

// ====== ROUTE 2: /callback ======
// Bokun redirects here after the vendor authorizes your app.
// Note: Bokun sends the nonce back as 'state' and the authorization code as 'code'.
app.get('/callback', async (req, res) => {
  const query = req.query;
  console.log('Received /callback request with query:', query);

  // Extract parameters from the callback query.
  // Note: We use 'state' instead of 'nonce'.
  const { domain, state, timestamp, hmac, code } = query;

  // Check that the state (our original nonce) exists in our session store.
  if (!state || !sessions[state]) {
    return res.status(400).send('Invalid or missing nonce/state');
  }

  // Verify the HMAC for the callback request.
  if (!verifyHmac(query, CLIENT_SECRET)) {
    return res.status(400).send('Invalid HMAC on callback request');
  }

  // Construct the URL for exchanging the code for an access token.
  const tokenUrl = `https://${domain}.${BOKUN_HOST}/appstore/oauth/access_token`;

  try {
    const tokenResponse = await axios.post(tokenUrl, {
      client_id: API_KEY,
      client_secret: CLIENT_SECRET,
      code: code
    });
    const tokenData = tokenResponse.data;
    console.log('Received access token data:', tokenData);

    // Retrieve the stored session data.
    const sessionData = sessions[state];

    // Prepare the data to "store" (simulate saving to a database).
    const storeData = {
      user: sessionData.user,
      domain: sessionData.domain,
      nonce: state,
      access_token: tokenData.access_token,
      scope: tokenData.scope,
      vendor_id: tokenData.vendor_id
    };

    console.log('Storing data to webhook (simulated DB):', storeData);

    // Post the data to a webhook (simulated database storage).
    await axios.post('https://webhook.site/054f59c1-a4f2-493b-b21c-c2c95527df19', storeData);

    // Clean up the session.
    delete sessions[state];

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
