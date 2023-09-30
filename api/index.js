const express = require('express');
const jose = require('jose');
const NodeCache = require('node-cache');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;
const cache = new NodeCache();

// Configure body-parser middleware
app.use(bodyParser.json());

// Function to retrieve the JWKS from the cache or fetch it remotely
async function getJwks() {
  const cachedJwks = cache.get('jwks');

  if (cachedJwks) {
    return cachedJwks;
  } else {
    try {
      const remoteJwks = jose.createRemoteJWKSet(new URL("https://api-auth.web3auth.io/jwks"));

      // Cache the JWKS for a specified duration (e.g., 1 hour)
      cache.set('jwks', remoteJwks, 3600);

      return remoteJwks;
    } catch (error) {
      throw error;
    }
  }
}

// Define the route that performs JWT verification
app.post('/verify-jwt', async (req, res) => {
  try {
    // Retrieve idToken and app_pub_key from the request body
    const { idToken, app_pub_key } = req.body;

    // Get the JWKS from the cache or fetch it remotely
    const jwks = await getJwks();

    // Verify the JWT using Web3Auth's JWKS
    const jwtDecoded = await jose.jwtVerify(idToken, jwks, { algorithms: ["ES256"] });

    // Checking `app_pub_key` against the decoded JWT wallet's public_key
    if (jwtDecoded.payload.wallets[0].public_key === app_pub_key) {
      // Verification Successful
      res.status(200).json({ message: 'Verification Successful', decodedJWT: jwtDecoded });
    } else {
      // Verification Failed
      res.status(400).json({ message: 'Verification Failed', decodedJWT: jwtDecoded });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Internal Server Error', error: error });
  }
});

app.listen(port, () => {
  console.log(`Server is listening on port ${port}`);
});
