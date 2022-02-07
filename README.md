# cognito-userinfo

---------------------------------------------------------------------------------
COGNITO JWT verification and alternate implementation of USERINFO endpoing.

https://docs.aws.amazon.com/cognito/latest/developerguide/userinfo-endpoint.html

The Cognito provided implementation requires providing an ACCESS_TOKEN rather
than an **ID_TOKEN**. If an **ACCESS_TOKEN** is shared with another service 
then a security risk is introduced as the **ACCESS_TOKEN** returned by Cognito is
typically scoped for the user to perform actions such as calling other AWS endpoints,
triggering AWS Lambda functions via AWS API Gateway, calling methods of custom APIs
built by an AWS customer for their service and deployed via API GATEWAY, etc.

If an **ID_TOKEN** was provided the scope would be limited solely to obtaining the
information that is included in the verified and decoded **ID_TOKEN**.

ACCESS, ID and REFRESH tokens created by Cognito IDP are stored by default in
the browser's localStorage. A compromise of the browser (e.g. via an browser extension)
can leak these tokens. Tokens could be used in replay attacks and cause information
leakage. Because of this, an integrated API service should make a real-time call to an integrated
provider's userInfo endpoint to obtain the OAUTH2/OPENID subscriber information
when an integration attempts to authenticate and authorize the user to obtain
a refresh and access tokens for the service.

This implementation provides a mechanism to address this concern over use of
**ACCESS_TOKEN**. It is an alternative implementation of the Cognito provided **USERINFO**
endpoint that utilizes the ID_TOKEN rather than the ACCESS_TOKEN. 

- https://docs.aws.amazon.com/cognito/latest/developerguide/userinfo-endpoint.html

The call is identical accept ID_TOKEN is provided in the Authorization header. The token
is decoded, validated as an ID token that hasn't expired and the public key
used to sign ID_TOKENs is used to verify the signature and confirm that the
token hasn't been created by any party other than Cogito IDP (which controls the
private key that was used to sign the token during the user's authorization
flow.

> AWS Cognito DOES NOT rotate public keys. But they do caveat (since 2016) that they
> may in the future. OAUTH2 providers like OKTA do perform key rotation.

Given that these keys are used in things like AWS LAMBDA, AMPLIFY, etc ... a sudden
change to AWS Cognito policy of NOT rotating keys would break hundreds of thousands
of running integrations. This alone is reason to expect AWS Cognito to NEVER change
their current behavior.

- https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html#amazon-cognito-user-pools-using-tokens-step-2
- https://forums.aws.amazon.com/thread.jspa?threadID=241570
- https://medium.com/@victor.leong.17/decoding-aws-cognito-jwt-in-rails-f88c1c4db9ec
- https://stackoverflow.com/questions/43978673/why-does-aws-cognito-use-multiple-public-keys-for-jwts

This implementation requires two values: **REGION** and **POOLID**.

> Testing has shown that the REGION is embedded in the POOLID but I'm not depending on that. Treating POOLID as opaque id.

| Method | Description |
| ------ | ----------- |
| getCognitoIdpKeys| called once at initialization to obtain the public key(s) used that Cognito uses to sign the access and id tokens.|
| validateToken | called for each ID_TOKEN provided to the oauth2/userInfo api method. Decodes the token. Use the keyid in the token header to determine which public key to use. Create PEM version of public key. Verify the signature of the token and that it hasn't expired.|
| userInfo | Extract the ID_TOKEN from request header. Decode & Verify that it's got the necessary fields. Call validateToken to ensure not expired and signature is valid. If not valid or expired, 401. Otherwise 200 with typical OPENID fields returned: {sub, email, email_verified, username, iat, exp}|
                    

> Note that with Cognito, if Federation is enabled and the user authenticates via Google for example, the sub and username will be different than if the user validates via username/password or email/password.
