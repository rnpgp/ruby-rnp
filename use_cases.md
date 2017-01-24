1. Generate or import a secret key, and read its properties:

```
key = NetPGP::SecretKey.new
key.generate(
  key_length: Integer,
  public_key_algorithm: PublicKeyAlgorithm::RSA,
  algorithm_params: { e: Integer }, # content is public_key_algorithm specific
  userid: String || Userid,
  hash_algorithm: HashAlgorithm,
  symmetric_key_algorithm: SymmetricKeyAlgorithm
)

key.version # must be 4
key.userids # => [] with its User ID packets
key.userid_signatures # => [] of Signature Packets of its User ID packets
key.passphrase # sets the passphrase if non-blank
key.key_id # => key id of key
key.fingerprint # => fingerprint of key
key.key_length # length of key
```


2. (Generate and) Add a Subkey to a secret key:

```
subkey = SecretSubkeyPacketV4.new
subkey.generate(
  key_length: Integer,
  public_key_algorithm: PublicKeyAlgorithm,
  algorithm_params: { e: Integer }, # content is public_key_algorithm specific
  userid: String || Userid,
  hash_algorithm: HashAlgorithm,
  symmetric_key_algorithm: SymmetricKeyAlgorithm
)

# Adds subkey to key
key.add_subkey(subkey)

# Or
subkey_self_sig = Signature.new
subkey_self_sig.type = SignatureType::SubkeyBinding
subkey_self_sig.userid = userid
subkey_self_sig.key_flags = [:encrypt_data, :encrypt_comm, :cert]
subkey_self_sig.key_expiration_time = DateTime
subkey_self_sig.creation_time = DateTime

```

3. Sign and verify a PGP message

```
# Plaintext OpenPGP message
plaintext_data = File.read("plaintext.txt")
literal_message = LiteralMessage.new(plaintext_data) # automatically creates a LiteralDataPacket inside

# Signed OpenPGP message
message = SignedMessage.new(literal_message)
message.content = literal_message # alternative to above
message.key = SecretKey
message.sign # => SignedMessage [SignaturePacket, LiteralMessage]

# Or
message = OnePassSignedMessage.new(
  signature_type: PositiveCertification,
  hash_algorithm: HashAlgorithm,
  public_key_algorithm: PublicKeyAlgorithm,
  key: SecretKey || PublicKey,
  content: literal_message
) # => OnePassSignedMessage is an OpenPgpMessage

message.to_s # ASCII armored message

# Verifying a PGP message
public_key.verify(message.signature, message.content)
secret_key.verify(message.signature, message.content)
```

4. Encrypt and decrypt a PGP message

```
# Encrypted OpenPGP message
message = EncryptedMessage.new
message.key = YourPublicKey
message.public_key_algorithm = PublicKeyAlgorithm
message.content = plaintext_data

# Decrypt OpenPGP message
message = NetPGP::OpenPgpMessage.new

# Importing from ASCII armored PGP message
message.import_ascii(File.read("ascii_armored_pgp_message.txt"))

# Importing unarmored content
message.import_raw(File.read("base64_portion_of_multipart_email.eml"))

message.signature # => signature of message in NetPGP::Signature
message.signer_userid # => signer in NetPGP::Userid
message.signed? # => is message signed?
message.encrypted? # => is message encrypted?
message.decrypt(key) # => decrypt content of message
message.content # => decrypted content of message
```

5. Packet and Keychain functionalities.

While these are not crucial, the Packet stuff will aid a higher level
implementation.

The 'netpgp_*' functions do support signing/verifying/encrypting/decrypting, but for generate key (Case 1)
especially for subkeys we need to implement the remaining stuff in Ruby.
