module NetPGP

class PublicKeyAlgorithm
  NONE = 0
  RSA = 1
  RSA_ENCRYPT_ONLY = 2
  RSA_SIGN_ONLY = 3
  ELGAMAL = 16
  DSA = 17
  ECDH = 18
  ECDSA = 19
  FORMERLY_ELGAMAL = 20

  def self.from_native(alg)
    raise if alg.class != Symbol
    LibNetPGP::PGP_PUBKEY_ALG_T[alg]
  end

  def self.to_native(alg)
    raise if alg.class != Fixnum
    LibNetPGP::PGP_PUBKEY_ALG_T[alg]
  end

end

class HashAlgorithm
  MD5 = 1
  SHA1 = 2
  RIPEMD = 3
  SHA256 = 8
  SHA384 = 9
  SHA512 = 10
  SHA224 = 11

  # see pgp_str_to_hash_alg
  STRING_MAPPING = {
    MD5 => 'md5',
    SHA1 => 'sha1',
    SHA256 => 'sha256',
    SHA384 => 'sha384',
    SHA512 => 'sha512'
  }

  def self.to_s(alg)
    STRING_MAPPING[alg]
  end

end

class SymmetricKeyAlgorithm
  PLAINTEXT = 0
  IDEA = 1
  TRIPLEDES = 2
  CAST5 = 3
  BLOWFISH = 4
  AES128 = 7
  AES192 = 8
  AES256 = 9
  TWOFISH256 = 10

  # see pgp_str_to_cipher
  STRING_MAPPING = {
    IDEA => 'idea',
    TRIPLEDES => 'tripledes',
    CAST5 => 'cast5',
    AES128 => 'aes128',
    AES256 => 'aes256'
  }

  def self.to_s(alg)
    STRING_MAPPING[alg]
  end

end

class StringToKeyUsage
  NONE = 0
  ENCRYPTED_AND_HASHED = 254
  ENCRYPTED = 255
end

class StringToKeySpecifier
  SIMPLE = 0
  SALTED = 1
  ITERATED_AND_SALTED = 3
end

end

