# vhjwt

My own implementation of Javascript WebTokens in PHP

## Installation

clone the repository and move the contents of the `src` folder into your project

## Usage

`$jwtHandler = new VhJwt($secret,$algorithm = 'HS256');` constructs a new helper class.

`$jwtHandler->generateToken($payload,$expiry = 3600);` returns a new JWT with the specified payload and expiry set.

`$jwtHandler->validateToken($jwt);` returns true if our signature matches the one provided

`$jwtHandler->getPayload($jwt);` returns the payload, regardless if it passes validation or not.

## Todo

Would love to support other algorithms but at this time this suits our needs.
