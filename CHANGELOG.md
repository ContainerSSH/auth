# Changelog

## 1.0.1: Fixing ignored authentication config

This release fixes [ContainerSSH/ContainerSSH#167](https://github.com/ContainerSSH/ContainerSSH/issues/167) where both the `password` and the `pubkey` options are ignored in the configuration.

## 1.0.0: First stable release

This release tags the first stable version for ContainerSSH 0.4.0.

## 0.9.6: Server ready message

This release adds a message when the authentication server is ready.

## 0.9.5: Direct metrics support

This release adds metrics support directly in the auth library.

## 0.9.4: Authentication retry

This release adds retries to the authentication process. This allows ContainerSSH to retry requests that lead to a non-200 status code.

## 0.9.3: Bumped HTTP dependency

Bumped [http](https://github.com/containerssh/http) dependency to 0.9.2.

## 0.9.2: Fixed YAML and JSON serialization

This release fixes how the client configuration structure is serialized and unserialized. Previously, we missed to add the `inline` option to the embedded option to the HTTP client config which lead to a substructure being created. This is now fixed. 

## 0.9.1: Changed public key to authorized key format (December 5, 2020)

This release changes the `publicKeyBase64` field to `publicKey` and the format from the OpenSSH wire format to the authorized_keys format.

This also means that the internal API format changes from `[]byte` to `string`.

Transitioning to the authorized_keys format should make it easier for auth server implementers to authenticate against SSH keys.  

## 0.9.0: Initial release (December 5, 2020)

This is the initial release of this library and port from ContainerSSH 0.3.0.
