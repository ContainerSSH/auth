# Changelog

## 0.9.2: Fixed YAML and JSON serialization

This release fixes how the client configuration structure is serialized and unserialized. Previously, we missed to add the `inline` option to the embedded option to the HTTP client config which lead to a substructure being created. This is now fixed. 

## 0.9.1: Changed public key to authorized key format (December 5, 2020)

This release changes the `publicKeyBase64` field to `publicKey` and the format from the OpenSSH wire format to the authorized_keys format.

This also means that the internal API format changes from `[]byte` to `string`.

Transitioning to the authorized_keys format should make it easier for auth server implementers to authenticate against SSH keys.  

## 0.9.0: Initial release (December 5, 2020)

This is the initial release of this library and port from ContainerSSH 0.3.0.