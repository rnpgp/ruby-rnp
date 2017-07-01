# Example usage of Rnp Ruby binding

module Rnp

  # https://tools.ietf.org/html/rfc4880#section-4.1
  # An OpenPGP message is constructed from a number of records that are
  # traditionally called packets.
  #
  # https://tools.ietf.org/html/rfc4880#section-11
  # OpenPGP packets are assembled into sequences in order to create
  # messages and to transfer keys.  Not all possible packet sequences are
  # meaningful and correct.
  class Message; end

  # RFC 4880 11.1. Transferable Public Keys
  # OpenPGP users may transfer public keys.  The essential elements of a
  # transferable public key are as follows:
  #  - One Public-Key packet
  #  - Zero or more revocation signatures
  #  - One or more User ID packets
  #  - After each User ID packet, zero or more Signature packets (certifications)
  #  - Zero or more User Attribute packets
  #  - After each User Attribute packet, zero or more Signature packets (certifications)
  #  - Zero or more Subkey packets
  #  - After each Subkey packet, one Signature packet, plus optionally a revocation
  class PublicKeyMessage; end
  # message.public_key_packet => PublicKeyPacketV(3 or 4)
  # message.revocation_signatures => [] of Signatures

  # RFC 4880 11.2.  Transferable Secret Keys
  # OpenPGP users may transfer secret keys.  The format of a transferable
  # secret key is the same as a transferable public key except that secret-key
  # and secret-subkey packets are used instead of the public key and
  # public-subkey packets.  Implementations SHOULD include self- signatures on
  # any user IDs and subkeys, as this allows for a complete public key to be
  # automatically extracted from the transferable secret key.  Implementations
  # MAY choose to omit the self-signatures, especially if a transferable public
  # key accompanies the transferable secret key.
  class SecretKeyMessage; end

  # RFC 4880 11.3.  OpenPGP Messages
  # An OpenPGP message is a packet or sequence of packets that corresponds to the
  # following grammatical rules (comma represents sequential composition, and
  # vertical bar separates alternatives):
  #
  # OpenPGP Message :- Encrypted Message | Signed Message | Compressed Message | Literal Message.
  # Compressed Message :- Compressed Data Packet.
  # Literal Message :- Literal Data Packet.
  # ESK :- Public-Key Encrypted Session Key Packet | Symmetric-Key Encrypted Session Key Packet.
  # ESK Sequence :- ESK | ESK Sequence, ESK.
  # Encrypted Data :- Symmetrically Encrypted Data Packet | Symmetrically Encrypted Integrity Protected Data Packet
  # Encrypted Message :- Encrypted Data | ESK Sequence, Encrypted Data.
  # One-Pass Signed Message :- One-Pass Signature Packet, OpenPGP Message, Corresponding Signature Packet.
  # Signed Message :- Signature Packet, OpenPGP Message | One-Pass Signed Message.
  class OpenPgpMessage < Message; end

  # The user only needs to know about these
  class LiteralMessage < OpenPgpMessage; end
  class CompressedMessage < OpenPgpMessage; end
  class EncryptedMessage < OpenPgpMessage; end
  class SignedMessage < OpenPgpMessage; end

  class OnePassSignedMessage < OpenPgpMessage; end
  class EncryptedData; end
  class EncryptedSessionKeySequence; end
  class EncryptedSessionKey; end

  # RFC 4880 11.4. Detached Signatures
  # Some OpenPGP applications use so-called "detached signatures".  For
  # example, a program bundle may contain a file, and with it a second file
  # that is a detached signature of the first file.  These detached signatures
  # are simply a Signature packet stored separately from the data for which
  # they are a signature.
  class Signature < Packet; end # a "Signature Packet"

  # https://tools.ietf.org/html/rfc4880#section-4.1
  # RFC 4880 Section 4-5
  # A packet is a chunk of data that has a tag specifying its meaning.  An
  # OpenPGP message, keyring, certificate, and so forth consists of a number of
  # packets.  Some of those packets may contain other OpenPGP packets (for
  # example, a compressed data packet, when uncompressed, contains OpenPGP
  # packets).
  class Packet; end
  packet.type # RFC 4880 section 5
  packet.version # version 3 or 4
  packet.subpackets # sub-packets in Rnp::Packet format
  packet.certify(key) # adds a certification signature after the packet
  packet.parent # The parent packet if it is a subpacket

  # 5.1. Public-Key Encrypted Session Key Packets (Tag 1)
  class PublicKeyEncryptedSessionKeyPacket; end
  # - A one-octet number giving the version number of the packet type.  The
  #   currently defined value for packet version is 3.
  packet.version # => 3 only

  # - An eight-octet number that gives the Key ID of the public key to
  #   which the session key is encrypted.  If the session key is
  #   encrypted to a subkey, then the Key ID of this subkey is used
  #   here instead of the Key ID of the primary key.
  packet.public_key_id # => String Key ID

  # - A one-octet number giving the public-key algorithm used.
  packet.public_key_algorithm # => PublicKeyAlgorithm

  # - A string of octets that is the encrypted session key.  This string takes
  #   up the remainder of the packet, and its contents are dependent on the
  #   public-key algorithm used.
  packet.encrypted_session_key # => String ciphertext
  packet.decrypted_session_key # => String plaintext

  # - Algorithm specific fields
  # If RSA:
  # - Multiprecision integer (MPI) of RSA encrypted value m**e mod n.
  # { mpi: m**e mod n }
  # If Elgamal:
  # - MPI of Elgamal (Diffie-Hellman) value g**k mod p.
  # - MPI of Elgamal (Diffie-Hellman) value m * y**k mod p.
  # { first: g**k mod p, second: m* y**k mod p }
  packet.algorithm_specific_fields

  # 5.2. Signature Packet (Tag 2)
  SignaturePacket = Signature # as defined above
  # RFC 4880 5.2.2 (3 or 4)
  signature.version
  # RFC 4880 5.2.1 Signature Type
  signature.type = [ # one of
    SignatureType::GenericCertification,
    SignatureType::PersonaCertification,
    SignatureType::CasualCertification,
    SignatureType::PositiveCertification,
    SignatureType::SubkeyBinding,
    SignatureType::PrimaryKeyBinding,
    SignatureType::DirectKey,
    SignatureType::KeyRevocation,
    SignatureType::SubkeyRevocation,
    SignatureType::CertificationRevocation,
    SignatureType::Timestamp,
    SignatureType::ThirdPartyConfirmation
  ]
  signature.public_key_algorithm # PublicKeyAlgorithm
  signature.hash_algorithm # HashAlgorithm
  signature.to_s # ASCII armored signature

  # SIGNATURE ATTRIBUTES (Subpackets of the Signature Packet)
  # 5.2.3 Returns array of Subpackets
  signature.hashed_subpackets
  signature.unhashed_subpackets
  # 5.2.3.4. Signature Creation Time
  # DateTime
  signature.creation_time
  # 5.2.3.5. Issuer: The OpenPGP Key ID of the key issuing the signature.
  signature.issuer
  # 5.2.3.6. Key Expiration Time
  # DateTime
  signature.key_expiration_time
  # 5.2.3.7. Preferred Symmetric Algorithms
  # Ordered [] of preferred symmetric algorithms
  signature.preferred_symmetric_algorithms
  # 5.2.3.8. Preferred Hash Algorithms
  # Ordered [] of preferred hash algorithms
  signature.preferred_hash_algorithms
  # 5.2.3.9. Preferred Compression Algorithms
  # Ordered [] of preferred compression algorithms, :zip by default
  signature.preferred_compression_algorithms
  # 5.2.3.10. Signature Expiration Time
  # DateTime
  signature.signature_expiration_time
  # 5.2.3.11. Exportable Certification
  # Boolean
  signature.exportable_certification
  # 5.2.3.12. Revocable
  # Boolean
  signature.revocable
  # 5.2.3.13. Trust Signature
  # Integer 0-255
  signature.trust_signature
  # 5.2.3.14. Regular Expression
  # RegExp
  signature.regex
  # 5.2.3.15. Revocation Key
  signature.revocation_key # String of Key ID
  signature.revocation_key_sensitive # Boolean
  signature.revocation_key_algorithm # Key Algorithm
  # 5.2.3.16. Notation Data
  class NotationData; end
  # Each NotationData has a :name (email address), :value (UTF8 string), a flag
  # :human_readable
  signature.notation_data.first.human_readable # Boolean, "human-readable"
  # [] of NotationData, each is a { name (email) => value (UTF8 string) }
  signature.notation_data
  # 5.2.3.17. Key Server Preferences
  signature.key_server_preferences_no_modify # Boolean
  # 5.2.3.18. Preferred Key Server
  signature.preferred_key_server # a URI String
  # 5.2.3.19. Primary User ID
  signature.primary_userid # Boolean
  # 5.2.3.20. Policy URI
  signature.policy_uri # a URI String
  # 5.2.3.21. Key Flags
  # The "split key" (0x10) and "group key" (0x80) flags are placed on a
  # self-signature only; they are meaningless on a certification signature.  They
  # SHOULD be placed only on a direct-key signature (type 0x1F) or a subkey
  # signature (type 0x18), one that refers to the key the flag applies to.
  signature.key_flags # Can be combination of the following, :cert is always required.
   [
     :cert, # First octet 0x01, This key may be used to certify other keys.
     :sign, # First octet 0x02, This key may be used to sign data.
     :encrypt_comm, # First octet 0x04, This key may be used to encrypt communications.
     :encrypt_data, # First octet 0x08, This key may be used to encrypt storage.
     :auth, # First octet 0x20, This key may be used for authentication.
     :split, # 0x10 - The private component of this key may have been split by a secret-sharing mechanism
     :group, # 0x80 - The private component of this key may be in the possession of more than one person.
  ]
  # 5.2.3.22. Signer's User ID
  signature.userid # Userid object
  # 5.2.3.23. Reason for Revocation
  signature.revocation_code # one of :no_reason, :superseded, :compromised, :retired, :invalid
  signature.revocation_reason # String
  # 5.2.3.24. Features
  signature.features # Not needed now
  # 5.2.3.25. Signature Target
  signature.target_public_key_algorithm # PublicKeyAlgorithm
  signature.target_hash_algorithm # HashAlgorithm
  signature.target_hash # String
  # 5.2.3.26. Embedded Signature
  signature.embedded_signature # => SignaturePacket


  # 5.3. Symmetric-Key Encrypted Session Key Packets (Tag 3)
  class SymmetricKeyEncryptedSessionKeyPacket; end
  p.version # => 4
  p.symmetric_algorithm # => SymmetricKeyAlgorithm
  p.string_to_key # (S2K)
  p.session_key

  # 5.4. One-Pass Signature Packets (Tag 4)
  class OnePassSignaturePacket; end
  p.version # => 4
  p.signature_type # => SignatureType
  p.hash_algorithm # => HashAlgorithm
  p.public_key_algorithm # => PublicKeyAlgorithm
  p.key_id # => String
  p.nested # => Boolean

  # 5.5. Key Material Packet
  # 5.5.1. Key Packet Variants
  #   5.5.1.1. Public-Key Packet (Tag 6)
  #   5.5.1.2. Public-Subkey Packet (Tag 14)
  #   5.5.1.3. Secret-Key Packet (Tag 5)
  #   5.5.1.4. Secret-Subkey Packet (Tag 7)
  class KeyMaterialPacket; end

  # 5.5.2. Public-Key Packet Formats
  class PublicKeyPacketV3 < KeyMaterialPacket; end
  class PublicSubkeyPacketV3 < PublicKeyPacketV3; end
  # Methods
  packet.version # => 3
  packet.creation_time # => DateTime
  packet.expiration_time # => Integer in days
  packet.public_key_algorithm # => PublicKeyAlgorithm
  packet.mpi # =>
  # {
  #  n: "RSA MPI modulus n",
  #  e: "RSA MPI encryption exponent e"
  # }

  class PublicKeyPacketV4 < KeyMaterialPacket; end
  class PublicSubkeyPacketV4 < PublicKeyPacketV4; end
  # Methods
  packet.version # => 4
  packet.creation_time # => DateTime
  packet.expiration_time # => Integer in days
  packet.public_key_algorithm # => PublicKeyAlgorithm
  # If RSA:
  packet.mpi # => {
  #   n: RSA MPI modulus n
  #   e: RSA MPI encryption exponent e
  # }
  # If DSA:
  packet.mpi # => {
  #   p: DSA prime p
  #   q: DSA group order q
  #   g: DSA group generator g
  #   y: DSA public key value y
  # }
  # If Elgamal:
  packet.mpi # => {
  #   p: Elgamal prime p
  #   g: Elgamal group generator g
  #   y: Elgamal public key value y
  # }

  # 5.5.3. Secret-Key Packet Formats
  class SecretKeyPacketV3 < PublicKeyPacketV3; end
  class SecretSubkeyPacketV3 < SecretKeyPacketV3; end
  class SecretKeyPacketV4 < PublicKeyPacketV4; end
  class SecretSubkeyPacketV4 < SecretKeyPacketV4; end
  # Methods (in addition to PublicKey methods above)
  packet.public_key_packet # => PublicKeyPacketV3 || PublicSubkeyPacketV3
  packet.string_to_key_usage # => 0-255
  packet.symmetric_key_algorithm # (optional if usage is 255 or 254)
  packet.string_to_key_specifier # (optional if usage is 255 or 254)
  packet.iv # (optional, if secret key is encrypted)
  packet.secret_key_data # => String

  # If the string-to-key usage octet is zero or 255, then a two-octet checksum
  # of the plaintext of the algorithm-specific portion (sum of all octets, mod
  # 65536).  If the string-to-key usage octet was 254, then a 20-octet SHA-1
  # hash of the plaintext of the algorithm-specific portion.  This checksum or
  # hash is encrypted together with the algorithm-specific fields (if
  # string-to-key usage octet is not zero).  Note that for all other values, a
  # two-octet checksum is required.
  packet.checksum # => String

  # If RSA secret key:
  # {
  #   d: multiprecision integer (MPI) of RSA secret exponent d.
  #   p: MPI of RSA secret prime value p.
  #   q: MPI of RSA secret prime value q (p < q).
  #   u: MPI of u, the multiplicative inverse of p, mod q.
  # }
  # If DSA secret key:
  # { x: MPI of DSA secret exponent x. }
  # If Elgamal secret key:
  # { x: MPI of Elgamal secret exponent x. }
  packet.algorithm_specific_fields # => Hash

  # 5.6. Compressed Data Packet (Tag 8)
  class CompressedDataPacket; end
  packet.algorithm # => CompressionAlgorithm
  packet.data # => a valid decompressed Rnp::OpenPgpMessage
  packet.to_s # => an armored compressed data packet

  # 5.7. Symmetrically Encrypted Data Packet (Tag 9)
  class SymmetricallyEncryptedDataPacket; end
  packet.data # => [] of valid Rnp::Packet(s)

  # 5.8. Marker Packet (Obsolete Literal Packet) (Tag 10)
  class MarkerPacket; end
  # The body of this packet consists of:
  # - The three octets 0x50, 0x47, 0x50 (which spell "PGP" in UTF-8).
  # Such a packet MUST be ignored when received.
  packet.text # => "PGP"

  # 5.9. Literal Data Packet (Tag 11)
  class LiteralDataPacket; end
  # A Literal Data packet contains the body of a message; data that is not to
  # be further interpreted.
  #  - A one-octet field that describes how the data is formatted.
  packet.format # => one of "b" (Binary), "t" (Text), "u" (UTF-8 text), "l" or
                #    "1" (Local) is deprecated.
  packet.binary?
  packet.text?
  packet.utf8?

  # - File name as a string (one-octet length, followed by a file name).
  packet.filename # => String. Name of encrypted file or "_CONSOLE" (for your eyes only)

  # - A four-octet number that indicates a date associated with the literal
  # data.
  packet.date # => DateTime, modification date of a file or the time packet was
              #    created, or 0 for no time

  # - The remainder of the packet is literal data.
  packet.data # => IO stream
  packet.text # => If packet.text? then return text data with normalized <CR><LF> to local

  # 5.10. Trust Packet (Tag 12)
  class TrustPacket; end
  # Only used in Keyrings

  # 5.11. User ID Packet (Tag 13)
  class UserIdPacket; end
  # A RFC 2822 mail-addr.
  # Same as class Rnp::Userid

  # 5.12. User Attribute Packet (Tag 17)
  class UserAttributePacket < UserIdPacket; end
  packet.subpackets # => [] of Subpackets

  class UserAttributeSubpacket; end
  subpacket.type # => Only "1" is allowed as ImageAttributeSubpacket
  subpacket.body # => Body of subpacket

  # 5.12.1. The Image Attribute Subpacket
  class ImageAttributeSubpacket < UserAttributeSubpacket; end
  imagesubpacket.version # => 1 (only 1 allowed)
  imagesubpacket.encoding # => 1 (only 1 allowed, means "JPEG")
  imagesubpacket.body # => JPEG file IO

  # 5.13. Sym. Encrypted Integrity Protected Data Packet (Tag 18) ..49
  class SymmetricallyEncryptedIntegrityProtectedDataPacket < SymmetricallyEncryptedDataPacket; end
  # - A one-octet version number.  The only currently defined value is 1.
  packet.version # => 1 (only 1 allowed)

  # - Encrypted data, the output of the selected symmetric-key cipher operating
  # in Cipher Feedback mode with shift amount equal to the block size of the
  # cipher (CFB-n where n is the block size).
  packet.data # => [decrypted Packet(s) (last one must be a ModificationDetectionCodePacket)]
  packet.plaintext_data # => [decrypted Packet(s) without the last one (the ModificationDetectionCodePacket)]

  # The symmetric cipher used MUST be specified in a Public-Key or
  # Symmetric-Key Encrypted Session Key packet that precedes the Symmetrically
  # Encrypted Data packet.
  packet.cipher_packet # => a preceding PublicKeyEncryptedSessionKeyPacket or
                       #    SymmetricKeyEncryptedSessionKeyPacket

  # packet.mdc_packet => the ModificationDetectionCodePacket at the end of its packet.data

  # 5.14. Modification Detection Code Packet (Tag 19)
  class ModificationDetectionCodePacket; end
  # - A 20-octet SHA-1 hash of the preceding plaintext data of the
  # Symmetrically Encrypted Integrity Protected Data packet, including prefix
  # data, the tag octet, and length octet of the Modification Detection Code
  # packet.
  #
  packet.hash # => SHA1 hash
  packet.hash_algorithm # => SHA1 allowed only

  # These provide easier user access to the Packet(s)
  Userid = UserIdPacket;
  PublicKey = PublicKeyMessage
  SecretKey = SecretKeyMessage

  # These are the algorithms, for user read-only
  class PublicKeyAlgorithm; end
  class SymmetricKeyAlgorithm; end
  class HashAlgorithm; end
  class CompressionAlgorithm; end
  # Not required yet
  # class Keyring; end
end

# READING AN EXISTING SECRET KEY
key = Rnp::SecretKey.import(File.read("privatekey.key"))
key.passphrase = "xxx" # => non-interactive method of providing passphrase
key.to_s # => ASCII armored PGP secret key
key.public_key # => Rnp::PublicKey object

# GENERATING A NEW KEY
key = Rnp::SecretKey.new
key.generate(
  key_length: Integer,
  public_key_algorithm: PublicKeyAlgorithm::RSA,
  algorithm_params: { e: Integer }, # content is public_key_algorithm specific
  userid: String || Userid,
  hash_algorithm: HashAlgorithm,
  symmetric_key_algorithm: SymmetricKeyAlgorithm
)
# => calls Rnp's
# pgp_rsa_new_selfsign_key(
#    const int numbits,
#    const unsigned long e,
#    uint8_t *userid,
#    const char *hashalg,
#    const char *cipher
# )
#
# Generates the following structure for the SecretKeyMessage:
# (Note: a User ID certification signature packet is called a self-signature in
# RFC 4880)
# [
#    (a Secret-Key packet) SecretKeyPacketV4 (contains a PublicKeyPacketV4),
#    (a User ID packet) UserIdPacket with primary_userid set to true,
#    (a User ID certification signature) SignaturePacket(subpackets: [
#      type = PositiveCertification
#      primary_userid = true
#    ])
# ]
#
# RFC 4880 5.5.2
# OpenPGP implementations MUST create keys with version 4 format.  V3 keys are
# deprecated; an implementation MUST NOT generate a V3 key, but MAY accept it.
key.version # must be 4
key.secret_key_packet # => its Secret-Key packet
key.userids # => [] with its User ID packets
key.userid_signatures # => [] of Signature Packets of its User ID packets
key.passphrase # sets the passphrase if non-blank
key.key_id # => key id of key
key.fingerprint # => fingerprint of key

key.key_length # length of key
# :rsa
# https://tools.ietf.org/html/rfc4880#section-13.5
# An implementation SHOULD NOT implement RSA keys of size less than 1024 bits.
#
# :dsa
# https://tools.ietf.org/html/rfc4880#section-13.6
# An implementation SHOULD NOT implement DSA keys of size less than 1024 bits.
# It MUST NOT implement a DSA key with a q size of less than 160 bits.  DSA
# keys MUST also be a multiple of 64 bits, and the q size MUST be a multiple of
# 8 bits.  The Digital Signature Standard (DSS) [FIPS186] specifies that DSA be
# used in one of the following ways:
#  * 1024-bit key, 160-bit q, SHA-1, SHA-224, SHA-256, SHA-384, or SHA-512 hash
#  * 2048-bit key, 224-bit q, SHA-224, SHA-256, SHA-384, or SHA-512 hash
#  * 2048-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
#  * 3072-bit key, 256-bit q, SHA-256, SHA-384, or SHA-512 hash
#
# :elgamal # Unsupported in Rnp
# https://tools.ietf.org/html/rfc4880#section-13.7
# An implementation SHOULD NOT implement Elgamal keys of size less than 1024
# bits.

# The "self-signatures": adding requrirements to the key
userid = key.userids.first
self_sig = key.userid_signature(userid) # retrieve SignaturePacket for a given Userid
self_sig.key_flags = [:sign, :cert] # adds to a self-signature packet
self_sig.preferred_symmetric_algorithms = [
  SymmetricKeyAlgorithm::Aes256,
  SymmetricKeyAlgorithm::Aes192,
  SymmetricKeyAlgorithm::Aes,
  SymmetricKeyAlgorithm::Cast5
]
self_sig.preferred_hash_algorithms = [
  HashAlgorithm::Sha512,
  HashAlgorithm::Sha384,
  HashAlgorithm::Sha256,
  HashAlgorithm::Sha224
]
self_sig.preferred_compression_algorithms = [
  CompressionAlgorithm::Zlib,
  CompressionAlgorithm::Bzip2,
  CompressionAlgorithm::Zip,
  CompressionAlgorithm::Uncompressed
]


# Adding a subkey
#

subkey = SecretSubkeyPacketV4.new
subkey.generate(
  key_length: Integer,
  public_key_algorithm: PublicKeyAlgorithm,
  algorithm_params: { e: Integer }, # content is public_key_algorithm specific
  userid: String || Userid,
  hash_algorithm: HashAlgorithm,
  symmetric_key_algorithm: SymmetricKeyAlgorithm
)
subkey_self_sig = Signature.new
subkey_self_sig.type = SignatureType::SubkeyBinding
subkey_self_sig.userid = userid
subkey_self_sig.key_flags = [:encrypt_data, :encrypt_comm, :cert]
subkey_self_sig.key_expiration_time = DateTime
subkey_self_sig.creation_time = DateTime

# Adds subkey to key
key.add_subkey(subkey)

key.subkeys # => [] of SecretSubkeyPacketV4
key.subkey_signature(subkey) # => SignaturePacket of subkey

# Delegate to self-signature
key.expiration_time # => time in seconds after key creation time
key.creation_time # => key generation date in DateTime of key
key.flags # => [] of key flags

# key is now:
# [
#    (a Secret-Key packet) SecretKeyPacketV4 (contains a PublicKeyPacketV4),
#    (a User ID packet) UserIdPacket with primary_userid set to true,
#    (a User ID certification signature) SignaturePacket(subpackets: [
#      type = PositiveCertification
#      primary_userid = true
#      key_flags = [:sign, :cert]
#      preferred_symmetric_algorithms = [
#        SymmetricKeyAlgorithm::Aes256,
#        SymmetricKeyAlgorithm::Aes192,
#        SymmetricKeyAlgorithm::Aes,
#        SymmetricKeyAlgorithm::Cast5
#      ]
#      preferred_hash_algorithms = [
#        HashAlgorithm::Sha512,
#        HashAlgorithm::Sha384,
#        HashAlgorithm::Sha256,
#        HashAlgorithm::Sha224
#      ]
#      preferred_compression_algorithms = [
#        CompressionAlgorithm::Zlib,
#        CompressionAlgorithm::Bzip2,
#        CompressionAlgorithm::Zip,
#        CompressionAlgorithm::Uncompressed
#      ]
#    ])
#    (a Subkey packet) SecretSubkeyPacketV4 (contains a PublicSubkeyPacketV4),
#    (a subkey binding signature) SignaturePacket(subpackets: [
#      type = SubkeyBindingSignature
#      userid = userid
#      key_flags = [:encrypt_data, :encrypt_comm, :cert]
#      key_expiration_time = DateTime
#      creation_time = DateTime
#    ]),
# ]

# Public Key Algorithms
# https://tools.ietf.org/html/rfc4880#section-9.1
# https://tools.ietf.org/html/rfc6637#section-5
# NOTE: Rnp only supports generation of RSA keys (see rsa_generate_keypair()
# in openssl_crypto.c)
PublicKeyAlgorithms = [
  PublicKeyAlgorithm::Rsa, # RFC4880, ID 1, RSA Encrypt or Sign [HAC]
  PublicKeyAlgorithm::RsaEncryptOnly, # RFC4880, ID 2, RSA Encrypt-Only [HAC]
  PublicKeyAlgorithm::RsaSignOnly, # RFC4880, ID 3, RSA Sign-Only [HAC]
  PublicKeyAlgorithm::Elgamal, # RFC4880, ID 16, Elgamal (Encrypt-Only) [ELGAMAL] [HAC]
  PublicKeyAlgorithm::Dsa, # RFC4880, ID 17, DSA (Digital Signature Algorithm) [FIPS186] [HAC]
  PublicKeyAlgorithm::Ecdh, # RFC6637, ID 18, ECDH public key algorithm
  PublicKeyAlgorithm::Ecdsa # RFC6637, ID 19, ECDSA public key algorithm
]
# https://tools.ietf.org/html/rfc4880#section-13.5
# There are algorithm types for RSA Sign-Only, and RSA Encrypt-Only keys.
# These types are deprecated.  The "key flags" subpacket in a signature is a
# much better way to express the same idea, and generalizes it to all
# algorithms.  An implementation SHOULD NOT create such a key, but MAY
# interpret it.
# => Do not allow generation of :rsa_e or :rsa_s keys

# Symmetric Key Algorithms
# https://tools.ietf.org/html/rfc4880#section-9.2
# https://tools.ietf.org/html/rfc5581#section-3
# NOTE: Rnp only supports:
#	{	"cast5",		PGP_SA_CAST5		},
#	{	"idea",			PGP_SA_IDEA		},
#	{	"aes128",		PGP_SA_AES_128		},
#	{	"aes256",		PGP_SA_AES_256		},
#	{	"camellia128",		PGP_SA_CAMELLIA_128	},
#	{	"camellia256",		PGP_SA_CAMELLIA_256	},
#	{	"tripledes",		PGP_SA_TRIPLEDES	},
#	{	NULL,			0			}
SymmetricKeyAlgorithms = [
  SymmetricKeyAlgorithm::None, #RFC4880, ID 0, Plaintext or unencrypted data
  SymmetricKeyAlgorithm::Idea, #RFC4880, ID 1, IDEA [IDEA]
  SymmetricKeyAlgorithm::Tripledes, #RFC4880, ID 2, TripleDES (DES-EDE, [SCHNEIER] [HAC], 168 bit key derived from 192)
  SymmetricKeyAlgorithm::Cast5, #RFC4880, ID 3, CAST5 (128 bit key, as per [RFC2144])
  SymmetricKeyAlgorithm::Blowfish, #RFC4880, ID 4, Blowfish (128 bit key, 16 rounds) [BLOWFISH]
  SymmetricKeyAlgorithm::Aes128, #RFC4880, ID 7, AES with 128-bit key [AES]
  SymmetricKeyAlgorithm::Aes192, #RFC4880, ID 8, AES with 192-bit key
  SymmetricKeyAlgorithm::Aes256, #RFC4880, ID 9, AES with 256-bit key
  SymmetricKeyAlgorithm::Blowfish256, #RFC4880, ID 10, Twofish with 256-bit key [TWOFISH]
  SymmetricKeyAlgorithm::Camellia128, #RFC4880, ID 11, Camellia with 128-bit key
  SymmetricKeyAlgorithm::Camellia192, #RFC4880, ID 12, Camellia with 192-bit key
  SymmetricKeyAlgorithm::Camellia256 #RFC4880, ID 13, Camellia with 256-bit key
]

# Hash Algorithms
# https://tools.ietf.org/html/rfc4880#section-9
# NOTE: Rnp only supports
# case PGP_HASH_MD5:
# case PGP_HASH_SHA1:
# case PGP_HASH_SHA256:
# case PGP_HASH_SHA384:
# case PGP_HASH_SHA512:
# case PGP_HASH_SHA224:
HashAlgorithms = [
  HashAlgorithms::Md5, # RFC4880, ID 1, MD5 [HAC] Text: "MD5",
  HashAlgorithms::Sha1, # RFC4880, ID 2, SHA-1 [FIPS180] Text: "SHA1"
  HashAlgorithms::Ripemd160, # RFC4880, ID 3, RIPE-MD/160 [HAC] Text: "RIPEMD160"
  HashAlgorithms::Sha256, # RFC4880, ID 8, SHA256 [FIPS180] Text: "SHA256"
  HashAlgorithms::Sha384, # RFC4880, ID 9, SHA384 [FIPS180] Text: "SHA384"
  HashAlgorithms::Sha512, # RFC4880, ID 10, SHA512 [FIPS180] Text: "SHA512"
  HashAlgorithms::Sha224 # RFC4880, ID 11, SHA224 [FIPS180] Text: "SHA224"
]

# Compression Algorithms
# https://tools.ietf.org/html/rfc4880#section-9.3
# NOTE: Rnp supports all three
# case PGP_C_ZIP:
# case PGP_C_ZLIB:
# case PGP_C_BZIP2:
CompressionAlgorithms = [
  CompressionAlgorithm::Uncompressed || :nil, # RFC4880, ID 0, Uncompressed
  CompressionAlgorithm::Zip, # RFC4880, ID 1, ZIP [RFC1951]
  CompressionAlgorithm::Zlib, # RFC4880, ID 2, ZLIB [RFC1950]
  CompressionAlgorithm::Bzip2 # RFC4880, ID 3, BZip2 [BZ2]
]


# Verifying a PGP message
public_key.verify(message.signature, message.content)
secret_key.verify(message.signature, message.content)

# USER ID methods
# A User ID is the 'name-addr' specified in RFC 2822 3.4
# https://tools.ietf.org/html/rfc2822#section-3.4
userid = key.userids.first
# Note: Rnp pgp_get_userid
userid = Rnp::Userid.new(address: "joshuac@mail.net", name: "Josiah Carberry")
userid.address # => address of user id
userid.name # => name of user id
userid.to_s # => "Josiah Carberry <joshuac@mail.net>"
userid.primary_userid # => RFC 4880 5.2.3.19 is this the Primary User ID of a key? Only when userid is associated with key.

key.userids << userid # adds Rnp::Userid packet to a Message
# Note: Rnp pgp_add_userid

# SIGNATURE METHODS
signature = Rnp::Signature.import("detached_ascii_pgp_signature")
signature.verify(key, data)

# MESSAGE METHODS
message = Rnp::OpenPgpMessage.new
# Importing from ASCII armored PGP message
message.import_ascii(File.read("ascii_armored_pgp_message.txt"))
# Importing unarmored content
message.import_raw(File.read("base64_portion_of_multipart_email.eml"))
message.packets # => [] of Rnp::Packet objects
message.signature # => signature of message in Rnp::Signature
message.signer_userid # => signer in Rnp::Userid
message.signed? # => is message signed?
message.encrypted? # => is message encrypted?
message.decrypt(key) # => decrypt content of message
message.content # => decrypted content of message

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

# Or
message = SignedMessage.new
# Automatically creates a LiteralMessage, which contains a Literal Data Packet
message.content = plaintext_data
message.key = SecretKey
message.signature_type = PositiveCertification
message.hash_algorithm = HashAlgorithm
message.public_key_algorithm = PublicKeyAlgorithm

# Encrypted OpenPGP message
message = EncryptedMessage.new
message.key = YourPublicKey
message.public_key_algorithm = PublicKeyAlgorithm
# Automatically creates this:
# EncryptedMessage (
#   EncryptedSessionKeySequence (
#     EncryptedSessionKey (
#       PublicKeyEncryptedSessionKeyPacket
#     ),
#     EncryptedData (
#       SymmetricallyEncryptedIntegrityProtectedDataPacket (
#         LiteralPacket(plaintext_data)
#       )
#     )
#   )
# )
message.content = plaintext_data


# ALGORITHM METHODS
algo = message.public_key_algorithm # => public key algorithm in Rnp::PublicKeyAlgorithm format
algo.name # => name of algo, e.g., RSA
algo.parameters # => parameters of algo used, e.g., RSA parameters (RFC 4880 Algorithm Specific Fields)

