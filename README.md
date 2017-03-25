# ruby-netpgp

ruby-netpgp is a Ruby wrapper for libnetpgp/rnp.

# Overview
The code is split in to two main modules.
The low-level binding code is in the module `LibNetPGP` (`lib/netpgp/lowlevel/`).
The high-level wrapper is in the module `NetPGP` (`lib/netpgp/highlevel/`).

# Documentation
Run "yardoc" to generate documentation in the `doc/` directory.
```sh
$ yardoc
```

# Tests
Run "rake" or "rspec" to run all tests in the `spec/` directory.
```sh
$ rake
```

# Examples
There are examples demonstrating the use of both the low-level and high-level interfaces in `examples/`.

# Usage

## Loading Keys

```ruby
require 'netpgp'
keyring = NetPGP::Keyring.load(File.read('spec/keys/seckey_sign_only.asc'))
# load some more keys in to this keyring
keyring.add(File.read('spec/keys/pubkey_sign_only.asc'))
# access public keys
keyring.public_keys
# access secret keys
keyring.secret_keys
```

## Unlocking Secret Keys
Most secret keys are encrypted and require a passphrase for certain operations. This can be provided during keyring loading by providing a block, like so:
```ruby
keyring = NetPGP::Keyring.load(File.read('spec/keys/seckey_sign_only.asc')) {|seckey|
    # This block will be called for each encrypted key that is found during parsing.
    # An instance of SecretKey is passed.
    print "Enter passphrase for key #{seckey.key_id_hex}: "
    $stdin.gets.chomp
}
```
The above method will result in fully unlocked SecretKey instances that have @passphrase set correctly (and have decrypted key material in @mpi).

Alternatively, you can manually set @passphrase on a secret key to enable operations that require a passphrase. In this case, the key material in @mpi will have nil values, but the encrypted key material will be available in @raw_subpackets and used for operations requiring it.
```ruby
secret_key = keyring.secret_keys[0]
secret_key.passphrase = 'password'
# decrypt, sign, etc.
```

## Encryption and Decryption
Encryption is done with a PublicKey.
```ruby
public_key = keyring.public_keys[0]
encrypted_message = public_key.encrypt('Test')
```
Decryption is done with the corresponding SecretKey.
```ruby
# find the secret key that corresponds with the above public key
secret_key = keyring.secret_keys.find {|key| key.key_id_hex == public_key.key_id_hex}
# decrypt (note that secret_key.passphrase must be correctly set, if required)
secret_key.decrypt(encrypted_message)
```

## Signing and Verifying
Signing is done with a SecretKey, like so:
```ruby
signed_message = secret_key.sign('My Data')
```
Verification is done with a Keyring.
```ruby
# returns true or false
keyring.verify(signed_message)
```

## Exporting
Keys can be exported by using the Keyring::export function.
```ruby
# this will output an ASCII-armored private key
puts keyring.export(secret_key)
# a secret key also has a public key inside
puts keyring.export(secret_key.public_key)
```

