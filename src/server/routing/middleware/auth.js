const express = require('express');
const app = express();
const jwt = require('express-jwt');
const jwtAuthz = require('express-jwt-authz');
const jwksRsa = require('jwks-rsa');

// Authentication middleware. When used, the
// access token must exist and be verified against
// the Auth0 JSON Web Key Set
module.exports = jwt({
	  // Dynamically provide a signing key
	  // based on the kid in the header and 
	  // the signing keys provided by the JWKS endpoint.
	  secret: jwksRsa.expressJwtSecret({
	    cache: true,
	    rateLimit: true,
	    jwksRequestsPerMinute: 5,
	    jwksUri: `https://budgie.auth0.com/.well-known/jwks.json`
	  }),

	  // Validate the audience and the issuer.
	  audience: 'https://www.budgie.com/api',
	  issuer: `https://budgie.auth0.com/`,
	  algorithms: ['RS256']
	});