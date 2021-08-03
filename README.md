# Testing Open Policy Agent

Testing authorization using Open Policy Agent

## Generate ECDSA keys in DER format

https://stackoverflow.com/questions/50235113/generate-ecdsa-key-pair-in-der-format

```
openssl ecparam -name prime256v1 -outform der -genkey -out privkey.der
openssl ec -inform der -in privkey.der -pubout -outform der -out pubkey.der
```
