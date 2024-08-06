<?php

// vhjwt.php

/*

Version 1.0

Basic class to handle JWTs

*/

class VhJwt
{
    private $secretKey;
    private $algorithm;

    public function __construct($secretKey, $algorithm = 'HS256')
    {
        $this->secretKey = $secretKey;
        $this->algorithm = $algorithm;
    }

    // Base64Url encode
    private function base64UrlEncode($data)
    {
        return str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode($data)
        );
    }

    // Base64Url decode
    private function base64UrlDecode($data)
    {
        $base64 = str_replace(
            ['-', '_'],
            ['+', '/'],
            $data
        );
        return base64_decode($base64);
    }

    // Generate a JWT
    public function generateToken($payload, $expiry = 3600)
    {
        $header = json_encode([
            'typ' => 'JWT',
            'alg' => $this->algorithm
        ]);
        $issuedAt = time();
        $expirationTime = $issuedAt + $expiry;

        $payload['iat'] = $issuedAt;
        $payload['exp'] = $expirationTime;

        $base64UrlHeader = $this->base64UrlEncode($header);
        $base64UrlPayload = $this->base64UrlEncode(json_encode($payload));

        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $this->secretKey, true);
        $base64UrlSignature = $this->base64UrlEncode($signature);

        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }

    // Validate a JWT
    public function validateToken($jwt)
    {
        $tokenParts = explode('.', $jwt);
        if (count($tokenParts) !== 3) {
            return false;
        }

        $header = $this->base64UrlDecode($tokenParts[0]);
        $payload = $this->base64UrlDecode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];

        // Check the expiration time
        $payloadArray = json_decode($payload, true);
        if ($payloadArray['exp'] < time()) {
            return false;
        }

        // Build a signature based on the header and payload using the secret
        $base64UrlHeader = $this->base64UrlEncode($header);
        $base64UrlPayload = $this->base64UrlEncode($payload);
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $this->secretKey, true);
        $base64UrlSignature = $this->base64UrlEncode($signature);

        return $base64UrlSignature === $signatureProvided;
    }

    // Get the payload of a JWT without validating
    public function getPayload($jwt)
    {
        $tokenParts = explode('.', $jwt);
        if (count($tokenParts) !== 3) {
            return false;
        }

        $payload = $this->base64UrlDecode($tokenParts[1]);
        return json_decode($payload, true);
    }
}
