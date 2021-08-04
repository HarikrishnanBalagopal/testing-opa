# Testing Open Policy Agent

Testing authorization using Open Policy Agent

## Prerequisites

- Golang
- Clone this repo and run `go get`
- An ECDSA key pair

### Generate ECDSA keys in DER format

https://stackoverflow.com/questions/50235113/generate-ecdsa-key-pair-in-der-format

```
mkdir secrets
openssl ecparam -name prime256v1 -outform der -genkey -out secrets/privkey.der
openssl ec -inform der -in privkey.der -pubout -outform der -out secrets/pubkey.der
```

## Usage

To generate an access token for user `john`:
```
go run signer/signer.go -u john
```

To run the demo API server:
```
go run main.go
```

## Authorization

When calling the REST API, each request contains an HTTP header:
```
Authorization: Bearer <access token>
```
The access token is a JSON Web Token (JWT) signed using a private key.  
The Move2Kube API server will verify the access token using the public key.

The public key can either be configured on the API server during startup,  
or it can be provided as a certificate with each request (client certificate).  
The API server can verify that the certificate was issued by a trusted Certificate Authority (CA).  
The public keys/certificates of the trusted CAs will be configured during startup.  
The header in which to provide the certificate can be configured on startup (similar to K8s).

## Access token

Schema:
```json
{
    "$schema": "http://json-schema.org/draft-06/schema#",
    "type": "object",
    "properties": {
        "idp_type": {
            "type": "string",
            "description": "The type of identity provider (OAuth2, SAML, etc.)"
        },
        "idp_id": {
            "type": "string",
            "description": "A unique ID for the identity provider"
        },
        "idp_user_id": {
            "type": "string",
            "description": "The ID given to the user by the identity provider"
        },
        "exp": {
            "type": "number",
            "description": "time at which this token will expire (number of seconcds since Unix epoch)"
        },
        "iss": {
            "type": "string",
            "description": "who issued this token"
        },
        "aud": {
            "type": "string",
            "description": "who this token is intended for"
        }
    },
    "required": [
        "idp_id",
        "idp_type",
        "idp_user_id"
    ]
}
```

Example:
```json
{
    "idp_type": "oauth2",
    "idp_id": "my-idp",
    "idp_user_id": "john"
}
```
