const fastify = require('fastify');
const axios = require("axios");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");

// ---------------------------------------------------------------------------------
// COGNITO JWT verification and alternate implementation of USERINFO endpoing.
//
// https://docs.aws.amazon.com/cognito/latest/developerguide/userinfo-endpoint.html
//
// The Cognito provided implementation requires providing an ACCESS_TOKEN rather
// than an ID_TOKEN. If an ACCESS_TOKEN is shared with another service (e.g. QuebicJS)
// then a security risk is introduced as the ACCESS_TOKEN returned by Cognito is
// typically scoped for the user to perform actions such as calling other AWS endpoints,
// triggering AWS Lambda functions via AWS API Gateway, calling methods of custom APIs
// built by an AWS customer for their service and deployed via API GATEWAY, etc.
//
// If an ID_TOKEN was provided the scope would be limited solely to obtaining the
// information that is included in the decoded ID_TOKEN.
//
// A 3rd party service like QuebicJS will not depend on the ID_TOKEN presented.
// ACCESS, ID and REFRESH tokens created by Cognito IDP are stored by default in
// the browser's localStorage. A compromise of the browser (e.g. via an browser extension)
// can leak these tokens. Tokens could be used in replay attacks and cause information
// leakage. Because of this, QuebicJS will make a real-time call to an integrated
// provider's userInfo endpoint to obtain the OAUTH2/OPENID subscriber information
// when an integration attempts to authenticate and authorize the user to obtain
// a QuebicJS refresh and access tokens.
//
// This implementation provides a mechanism to address this concern over use of
// ACCESS_TOKEN. It is an alternative implementation of the Cognito provided USERINFO
// endpoint that utilizes the ID_TOKEN rather than the ACCESS_TOKEN. The call is
// identical accept ID_TOKEN is provided in the Authorization header. The token
// is decoded, validated as an ID token that hasn't expired and the public key
// used to sign ID_TOKENs is used to verify the signature and confirm that the
// token hasn't been created by any party other than Cogito IDP (which controls the
// private key that was used to sign the token during the user's authorization
// flow.
//
// AWS Cognito DOES NOT rotate public keys. But they do caveat (since 2016) that they
// may in the future. OAUTH2 providers like OKTA do perform key rotation.
//
// Given that these keys are used in things like AWS LAMBDA, AMPLIFY, etc ... a sudden
// change to AWS Cognito policy of NOT rotating keys would break hundreds of thousands
// of running integrations. This alone is reason to expect AWS Cognito to NEVER change
// their current behavior.
//
// https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-2
// https://forums.aws.amazon.com/thread.jspa?threadID=241570
// https://medium.com/@victor.leong.17/decoding-aws-cognito-jwt-in-rails-f88c1c4db9ec
// https://stackoverflow.com/questions/43978673/why-does-aws-cognito-use-multiple-public-keys-for-jwts
//
// This implementation requires two values: REGION and POOLID.
//
// Testing has shown that the REGION is embedded in the POOLID but I'm not depending
// on that. Treating POOLID as opaque id.
//
// getCognitoIdpKeys - called once at initialization to obtain the public key(s) used
//                     that Cognito uses to sign the access and id tokens.
//
// validateToken     - called for each ID_TOKEN provided to the oauth2/userInfo
//                     api method. Decodes the token.
//
//                     Use the keyid in the token header to determine which
//                     public key to use. Create PEM version of public key.
// 
//                     Verify the signature of the token and that it hasn't expired.
//
// userInfo          - Extract the ID_TOKEN from request header.
//                     Decode & Verify that it's got the necessary fields.
//                     call validateToken to ensure not expired and signature is valid
//                     If not valid or expired, 401.
//                     Otherwise 200 with typical OPENID fields returned:
//                     {sub, email, email_verified, username, iat, exp}
//
// Note that with Cognito, if Federation is enabled and the user authenticates via
// Google for example, the sub and username will be different than if the user
// validates via username/password or email/password.
//
// ---------------------------------------------------------------------------------

let   COGNITO_POOL_KEYS        = [];

const getCognitoIdpKeys = (region, poolId) => {
    return new Promise((resolve, reject) => {
	const cognito_key_url = `https://cognito-idp.${region}.amazonaws.com/${poolId}/.well-known/jwks.json`;
	axios.get(cognito_key_url)
	    .then(result => {
		if (result.status===200) {
		    resolve(result.data);
		} else {
		    reject(null);
		}
	    })
	    .catch(e => {
		console.log(e);
		reject(null);
	    });
    });
}

const validateToken = (token) => {

    const getJsonWebKeyWithKID = (kid) => {
	for (let jwk of COGNITO_POOL_KEYS) {
            if (jwk.kid === kid) {
		return jwk;
            }
	}
	return null;
    }

    const decodeTokenHeader = (token) => {
	const [headerEncoded] = token.split('.');
	const buff = Buffer.from(headerEncoded, 'base64');
	const text = buff.toString('ascii');
	return JSON.parse(text);
    }
    
    const verifyJsonWebTokenSignature = (token, jsonWebKey, clbk) => {
	const pem = jwkToPem(jsonWebKey);
	jwt.verify(token, pem, {algorithms: ['RS256']}, (err, decodedToken) => clbk(err, decodedToken))
    }

    return new Promise((resolve) => {

	const header = decodeTokenHeader(token);
	const jsonWebKey = getJsonWebKeyWithKID(header.kid);
	const decoded = jwt.decode(token);
	// should have email, token_use=='id', sub
	if (decoded.token_use==='id' && decoded.hasOwnProperty("email") && decoded.hasOwnProperty("sub")) {
	    
	    verifyJsonWebTokenSignature(token, jsonWebKey, (err, decodedToken) => {
		if (err) {
		    LOG(`${err.message} ${decoded.sub} ${decoded.email}`);
		    resolve(null);
		} else {
		    LOG(`AUTH ${decodedToken.sub}`);
		    resolve(decodedToken);
		}
	    })
	} else {
	    console.error(`TokenInvalid: ID_TOKEN missing required fields`);
	    resolve(null);
	}
    });
}

const LOG = function (line) {
    var now = new Date();
    var time = [('0' + now.getHours()).slice(-2), ('0' + now.getMinutes()).slice(-2),
		('0' + now.getSeconds()).slice(-2)];
    var timestamp = '[' + time.join(':') + '] ';
    console.log(timestamp + line);
};

const userInfo = (req, res) => {
    const auth = req.headers["authorization"];
    if (auth !== undefined) {
	const parts = auth.trim().split(" ");
	if (parts[0]==="Bearer" && parts.length===2) {
	    const encoded_token = parts[1];
	    validateToken(encoded_token)
		.then(tkn => {
		    if (tkn===null) {
			res.code(401).send();
		    } else {
			const {sub, email, email_verified, iat, exp} = tkn;
			res.send({
			    sub,
			    email,
			    email_verified,
			    username: tkn["cognito:username"],
			    iat,
			    exp
			});
		    }
		})
		.catch(e => {
		    console.log(e);
		    res.code(401).send();
		})

	} else {
	    res.code(401).send();
	}
    } else {
	// Always 401 if not handled above
	res.code(401).send();
    }
}

// ---------------------------------------------------------------------------------
// API SERVICE
// ---------------------------------------------------------------------------------

const app = fastify().get('/oauth2/userInfo', userInfo);

// ---------------------------------------------------------------------------------
// Init System
//
// For CLI usage. Obtain the REGION and POOLID as arguments (could be environment, etc)
// PORT is optional param as well. Defaults to 6003.
// If requires params not provided, exit.
// Otherwise obtain latest public keys and start server.
// Deployment (behind LB, NGINX, etc) not provided here.
// ---------------------------------------------------------------------------------

let PORT = 6003;
let REGION, POOLID;

const usage = () => {
    console.log(`Usage: node oauth2-userinfo --region=REGION --pool=POOLID [--port=${PORT}]`);
}

// Determine what params have been provided...
for (let i = 2; i < process.argv.length; i++) {
    const arg = process.argv[i];
    if (arg.startsWith("--port")) {
        PORT = parseInt(arg.split("=")[1]);
	if (isNaN(PORT)) {
	    usage();
	    process.exit();
	}
    } else if (arg.startsWith("--region=")) {
        REGION = arg.split("=")[1];
    } else if (arg.startsWith("--pool=")) {
        POOLID = arg.split("=")[1];
    } else {
	usage();
	process.exit();
    }
}

// If no params, exit
if (REGION===undefined || POOLID===undefined) {
    usage();
    process.exit();
}

// Get cognito user pool public keys
getCognitoIdpKeys(REGION, POOLID)
    .then(result => {
	COGNITO_POOL_KEYS = result.keys;
	app.listen(PORT, () => {
	    LOG(`INIT port=${PORT}`);
	    // Heartbeat (primarily for healthcheck, reporting stats to log
	    intervalObj = setInterval(() => {
		LOG(`HEARTBEAT -- TODO SOME LEVEL OF STATS about usage`);
	    }, 60000);
	    
	});
    })
    .catch(e => {
	console.log(e);
	process.exit();
    });
