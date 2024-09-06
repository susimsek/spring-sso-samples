// Function to generate a random string (used for state, nonce, and code verifier)
function generateRandomString(length) {
  const array = new Uint32Array(length);
  window.crypto.getRandomValues(array);
  return Array.from(array, dec => ('0' + dec.toString(36)).slice(-2)).join('');
}

// Function to generate Code Challenge from Code Verifier (for PKCE)
async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const hash = await window.crypto.subtle.digest('SHA-256', data);
  const base64Hash = btoa(String.fromCharCode.apply(null, new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return base64Hash;
}

// authorize function, with PKCE and Client ID support
async function authorize(pkceEnabled = false, clientId) {
  // Generate state and nonce (CSRF protection and replay protection)
  const state = generateRandomString(16);
  const nonce = generateRandomString(16);

  // Create the base OAuth 2.0 authorization URL
  const url = new URL('/oauth2/authorize', window.location.origin);
  url.searchParams.set('redirect_uri', 'http://127.0.0.1:8080/login/oauth2/code/oidc-client');
  url.searchParams.set('scope', 'openid profile');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('state', state);
  url.searchParams.set('nonce', nonce);

  // If PKCE is enabled, generate code verifier and code challenge, and add them to the request
  if (pkceEnabled) {
    const codeVerifier = generateRandomString(64); // PKCE code verifier
    const codeChallenge = await generateCodeChallenge(codeVerifier); // PKCE code challenge

    // Store code verifier in sessionStorage (needed for the token request later)
    sessionStorage.setItem('codeVerifier', codeVerifier);

    // Add PKCE parameters to the URL
    url.searchParams.set('code_challenge_method', 'S256');
    url.searchParams.set('code_challenge', codeChallenge);
  } else {
    sessionStorage.removeItem('codeVerifier');
  }

  // Redirect the user to the constructed authorization URL
  window.location.href = url.toString();
}
