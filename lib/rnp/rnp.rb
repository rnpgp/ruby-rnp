# frozen_string_literal: true

# (c) 2018,2019 Ribose Inc.

require 'English'
require 'json'

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'
require 'rnp/key'
require 'rnp/op/sign'
require 'rnp/op/verify'
require 'rnp/op/encrypt'
require "rnp/op/generate"

# Class used for interacting with RNP.
class Rnp
  # @api private
  attr_reader :ptr

  # Create a new interface to RNP.
  #
  # @param pubfmt [String] the public keyring format
  # @param secfmt [String] the secret keyring format
  def initialize(pubfmt = 'GPG', secfmt = 'GPG')
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_ffi_create, pptr, pubfmt, secfmt)
    @ptr = FFI::AutoPointer.new(pptr.read_pointer, self.class.method(:destroy))
    @key_provider = nil
    @password_provider = nil
  end

  # @api private
  def self.destroy(ptr)
    LibRnp.rnp_ffi_destroy(ptr)
  end

  def inspect
    Rnp.inspect_ptr(self)
  end

  # Set a logging destination.
  #
  # @param fd [Integer, IO] the file descriptor to log to. This will be closed
  #   when this object is destroyed.
  def log=(fd)
    fd = fd.to_i if fd.is_a(::IO)
    Rnp.call_ffi(:rnp_ffi_set_log_fd, @ptr, fd)
  end

  # Set a key provider.
  #
  # The key provider is useful if, for example, you have a database of keys and
  # you do not want to load all of them, and you don't know which will be needed
  # for a given operation.
  #
  # The key provider will be called to request that a key be loaded, and the
  # key provider is responsible for loading the appropriate key (if available)
  # using {#load_keys}.
  #
  # The provider may be called multiple times for the same key, but with
  # different identifiers. For example, it may first be called with
  # a fingerprint, then (if the key was not loaded), it may be called with a
  # keyid.
  #
  # == Examples
  # === examples/key_provider.rb
  # {include:file:examples/key_provider.rb}
  #
  # @param provider [Proc, #call] a callable object
  def key_provider=(provider)
    @key_provider = provider
    @key_provider = KEY_PROVIDER.curry[provider] if provider
    Rnp.call_ffi(:rnp_ffi_set_key_provider, @ptr, @key_provider, nil)
  end

  # Set a password provider.
  #
  # The password provider is used for retrieving passwords for various
  # operations, including:
  # * Signing data
  # * Decrypting data (public-key or symmetric)
  # * Adding a userid to a key
  # * Unlocking a key
  # * Unprotecting a key
  #
  # == Examples
  # === examples/password_provider.rb
  # {include:file:examples/password_provider.rb}
  #
  # @param provider [Proc, #call, String] a callable object, or a password
  def password_provider=(provider)
    @password_provider = provider
    @password_provider = PASS_PROVIDER.curry[provider] if provider
    Rnp.call_ffi(:rnp_ffi_set_pass_provider, @ptr, @password_provider, nil)
  end

  # Generate a new key or pair of keys.
  #
  # @note The generated key(s) will be unprotected and unlocked.
  #   The application should protect and lock the keys with
  #   {Key#protect} and {Key#lock}.
  #
  # == Examples
  # === examples/key_generation.rb
  # {include:file:examples/key_generation.rb}
  #
  # @param description [String, Hash]
  # @return [Hash<Symbol, Key>] a hash containing the generated key(s)
  def generate_key(description)
    description = JSON.generate(description) unless description.is_a?(String)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_generate_key_json, @ptr, description, pptr)
    begin
      presults = pptr.read_pointer
      return nil if presults.null?
      results = JSON.parse(presults.read_string)
      generated = {}
      results.each do |k, v|
        key = find_key(v.keys[0].to_sym => v.values[0])
        generated[k.to_sym] = key
      end
      generated
    ensure
      LibRnp.rnp_buffer_destroy(presults)
    end
  end

  # Generate an RSA key (w/optional subkey).
  #
  # @param userid [String] the userid for the key
  # @param bits [Integer] the bit length for the primary key
  # @param subbits [Integer] the bit length for the subkey
  #   (0 if no subkey should be generated)
  # @param password [String] the password to protect the key(s)
  #   (nil for no protection)
  def generate_rsa(userid:, bits:, subbits: 0, password:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_generate_key_rsa, @ptr, bits, subbits, userid, password,
                 pptr)
    pkey = pptr.read_pointer
    Key.new(pkey) unless pkey.null?
  end

  # Generate a DSA (w/optional ElGamal subkey) key.
  #
  # @param userid [String] the userid for the key
  # @param bits [Integer] the bit length for the primary key
  # @param subbits [Integer] the bit length for the subkey
  #   (0 if no subkey should be generated)
  # @param password [String] the password to protect the key(s)
  #   (nil for no protection)
  def generate_dsa_elgamal(userid:, bits:, subbits: 0, password:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_generate_key_dsa_eg, @ptr, bits, subbits, userid,
                 password, pptr)
    pkey = pptr.read_pointer
    Key.new(pkey) unless pkey.null?
  end

  # Generate an ECDSA+ECDH key pair.
  #
  # @param userid [String] the userid for the key
  # @param curve [String] the name of the curve
  # @param password [String] the password to protect the key(s)
  #   (nil for no protection)
  def generate_ecdsa_ecdh(userid:, curve:, password:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_generate_key_ec, @ptr, curve, userid, password, pptr)
    pkey = pptr.read_pointer
    Key.new(pkey) unless pkey.null?
  end

  # Generate an EdDSA+x25519 key pair.
  #
  # @param userid [String] the userid for the key
  # @param password [String] the password to protect the key(s)
  #   (nil for no protection)
  def generate_eddsa_25519(userid:, password:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_generate_key_25519, @ptr, userid, password, pptr)
    pkey = pptr.read_pointer
    Key.new(pkey) unless pkey.null?
  end

  # Generate an SM2 key pair.
  #
  # @param userid [String] the userid for the key
  # @param password [String] the password to protect the key(s)
  #   (nil for no protection)
  def generate_sm2(userid:, password:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_generate_key_sm2, @ptr, userid, password, pptr)
    pkey = pptr.read_pointer
    Key.new(pkey) unless pkey.null?
  end

  # Generate a key and optional subkey.
  #
  # @param userid [String] the userid for the key
  # @param password [String] the password to protect the key(s)
  #   (nil for no protection)
  def generate(type:, userid:, bits:, curve: nil, password:,
               subtype: nil, subbits: 0, subcurve: nil)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_generate_key_ex, @ptr, type, subtype, bits, subbits,
                 curve, subcurve, userid, password, pptr)
    pkey = pptr.read_pointer
    Key.new(pkey) unless pkey.null?
  end

  # Load keys.
  #
  # @param format [String] the format of the keys to load (GPG, KBX, G10).
  # @param input [Input] the input to read the keys from
  # @param public_keys [Boolean] whether to load public keys
  # @param secret_keys [Boolean] whether to load secret keys
  # @return [void]
  def load_keys(input:, format:, public_keys: true, secret_keys: true)
    raise ArgumentError, 'At least one of public_keys or secret_keys must be true' if !public_keys && !secret_keys
    flags = load_save_flags(public_keys: public_keys, secret_keys: secret_keys)
    Rnp.call_ffi(:rnp_load_keys, @ptr, format, input.ptr, flags)
  end

  def unload_keys(public_keys: true, secret_keys: true)
    raise ArgumentError, "At least one of public_keys or secret_keys must be true" \
      if !public_keys && !secret_keys
    flags = unload_keys_flags(public_keys: public_keys, secret_keys: secret_keys)
    Rnp.call_ffi(:rnp_unload_keys, @ptr, flags)
  end

  # Save keys.
  #
  # @param format [String] the format to save the keys in (GPG, KBX, G10).
  # @param output [Output] the output to write the keys to
  # @param public_keys [Boolean] whether to load public keys
  # @param secret_keys [Boolean] whether to load secret keys
  # @return [void]
  def save_keys(output:, format:, public_keys: false, secret_keys: false)
    raise ArgumentError, 'At least one of public_keys or secret_keys must be true' if !public_keys && !secret_keys
    flags = load_save_flags(public_keys: public_keys, secret_keys: secret_keys)
    Rnp.call_ffi(:rnp_save_keys, @ptr, format, output.ptr, flags)
  end

  # Find a key.
  #
  # @param criteria [Hash] the search criteria. Some examples would be:
  #   * !{keyid: '2FCADF05FFA501BB'}
  #   * !{'userid': 'user0'}
  #   * !{fingerprint: 'BE1C4AB951F4C2F6B604'}
  #   Only *one* criteria can be specified.
  # @return [Key, nil]
  def find_key(criteria)
    raise Rnp::Error, 'Invalid search criteria' if !criteria.is_a?(::Hash) ||
                                                   criteria.size != 1
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_locate_key, @ptr, criteria.keys[0].to_s,
                 criteria.values[0], pptr)
    pkey = pptr.read_pointer
    Rnp::Key.new(pkey) unless pkey.null?
  end

  # @!method userids
  # Get a list of all userids.
  #
  # @return [Array<String>]

  # @!method each_userid(&block)
  # Enumerate all userids.
  #
  # @return [self, Enumerator]

  # @!method keyids
  # Get a list of all keyids.
  #
  # @return [Array<String>]

  # @!method each_keyid(&block)
  # Enumerate all keyids.
  #
  # @return [self, Enumerator]

  # @!method fingerprints
  # Get a list of all fingerprints.
  #
  # @return [Array<String>]

  # @!method each_fingerprint(&block)
  # Enumerate all fingerprints.
  #
  # @return [self, Enumerator]

  # @!method grips
  # Get a list of all grips.
  #
  # @return [Array<String>]

  # @!method each_grip(&block)
  # Enumerate all grips.
  #
  # @return [self, Enumerator]

  %w[userid keyid fingerprint grip].each do |identifier_type|
    define_method("each_#{identifier_type}".to_sym) do |&block|
      each_identifier(identifier_type, &block)
    end

    define_method("#{identifier_type}s".to_sym) do
      each_identifier(identifier_type).to_a
    end
  end

  def public_key_count
    pcount = FFI::MemoryPointer.new(:size_t)
    Rnp.call_ffi(:rnp_get_public_key_count, @ptr, pcount)
    pcount.read(:size_t)
  end

  def secret_key_count
    pcount = FFI::MemoryPointer.new(:size_t)
    Rnp.call_ffi(:rnp_get_secret_key_count, @ptr, pcount)
    pcount.read(:size_t)
  end

  # Create a signature.
  #
  # @param input [Input] the input to read the data to be signed
  # @param output [Output] the output to write the signatures.
  #   If nil, the result will be returned directly as a String.
  # @param signers [Key, Array<Key>] the keys to sign with
  # @param armored (see Sign#armored=)
  # @param compression (see Sign#compression=)
  # @param creation_time (see Sign#creation_time=)
  # @param expiration_time (see Sign#expiration_time=)
  # @param hash (see Sign#hash=)
  # @return [nil, String]
  def sign(input:, output: nil, signers:,
           armored: nil,
           compression: nil,
           creation_time: nil,
           expiration_time: nil,
           hash: nil)
    Output.default(output) do |output_|
      sign = start_sign(input: input, output: output_)
      sign.options = {
        armored: armored,
        compression: compression,
        creation_time: creation_time,
        expiration_time: expiration_time,
        hash: hash
      }
      simple_sign(sign, signers)
    end
  end

  # Create a cleartext signature.
  #
  # @param input (see #sign)
  # @param output (see #sign)
  # @param signers [Key, Array<Key>] the keys to sign with
  # @param compression (see Sign#compression=)
  # @param creation_time (see Sign#creation_time=)
  # @param expiration_time (see Sign#expiration_time=)
  # @param hash (see Sign#hash=)
  # @return [nil, String]
  def cleartext_sign(input:, output: nil, signers:,
                     compression: nil,
                     creation_time: nil,
                     expiration_time: nil,
                     hash: nil)
    Output.default(output) do |output_|
      sign = start_cleartext_sign(input: input, output: output_)
      sign.options = {
        compression: compression,
        creation_time: creation_time,
        expiration_time: expiration_time,
        hash: hash
      }
      simple_sign(sign, signers)
    end
  end

  # Create a detached signature.
  #
  # @param input (see #sign)
  # @param output (see #sign)
  # @param signers [Key, Array<Key>] the keys to sign with
  # @param armored (see Sign#armored=)
  # @param compression (see Sign#compression=)
  # @param creation_time (see Sign#creation_time=)
  # @param expiration_time (see Sign#expiration_time=)
  # @param hash (see Sign#hash=)
  # @return [nil, String]
  def detached_sign(input:, output: nil, signers:,
                    armored: nil,
                    compression: nil,
                    creation_time: nil,
                    expiration_time: nil,
                    hash: nil)
    Output.default(output) do |output_|
      sign = start_detached_sign(input: input, output: output_)
      sign.options = {
        armored: armored,
        compression: compression,
        creation_time: creation_time,
        expiration_time: expiration_time,
        hash: hash
      }
      simple_sign(sign, signers)
    end
  end

  # Verify a signature.
  #
  # @param input [Input] the input to read the signatures
  # @param output [Output] the output (if any) to write the verified data
  def verify(input:, output: nil)
    verify = start_verify(input: input, output: output)
    verify.execute
  end

  # Verify a detached signature.
  #
  # @param data [Input] the input to read the data
  # @param signature [Input] the input to read the signatures
  def detached_verify(data:, signature:)
    verify = start_detached_verify(data: data, signature: signature)
    verify.execute
  end

  # Encrypt data with a public key.
  #
  # @param input [Input] the input to read the plaintext
  # @param output [Output] the output to write the encrypted data.
  #   If nil, the result will be returned directly as a String.
  # @param recipients [Key, Array<Key>] list of recipients keys
  # @param armored (see Encrypt#armored=)
  # @param compression (see Encrypt#compression=)
  # @param cipher (see Encrypt#cipher=)
  # @param aead (see Encrypt#aead=)
  def encrypt(input:, output: nil, recipients:,
              armored: nil,
              compression: nil,
              cipher: nil,
              aead: nil)
    Output.default(output) do |output_|
      enc = start_encrypt(input: input, output: output_)
      enc.options = {
        armored: armored,
        compression: compression,
        cipher: cipher,
        aead: aead,
      }
      simple_encrypt(enc, recipients: recipients)
    end
  end

  # Encrypt and sign data with a public key.
  #
  # @param input (see #encrypt)
  # @param output (see #encrypt)
  # @param recipients (see #encrypt)
  # @param signers [Key, Array<Key>] list of keys to sign with
  # @param armored (see Encrypt#armored=)
  # @param compression (see Encrypt#compression=)
  # @param cipher (see Encrypt#cipher=)
  # @param aead (see Encrypt#aead=)
  # @param hash (see Encrypt#hash=)
  # @param creation_time (see Encrypt#creation_time=)
  # @param expiration_time (see Encrypt#expiration_time=)
  def encrypt_and_sign(input:, output: nil, recipients:, signers:,
                       armored: nil,
                       compression: nil,
                       cipher: nil,
                       aead: nil,
                       hash: nil,
                       creation_time: nil,
                       expiration_time: nil)
    Output.default(output) do |output_|
      enc = start_encrypt(input: input, output: output_)
      enc.options = {
        armored: armored,
        compression: compression,
        cipher: cipher,
        aead: aead,
        hash: hash,
        creation_time: creation_time,
        expiration_time: expiration_time
      }
      simple_encrypt(enc, recipients: recipients, signers: signers)
    end
  end

  # Encrypt with a password only.
  #
  # @param input (see #encrypt)
  # @param output (see #encrypt)
  # @param passwords [String, Array<String>] list of passwords to encrypt with.
  #        Any (single) one of the passwords can be used to decrypt.
  # @param armored (see Encrypt#armored=)
  # @param compression (see Encrypt#compression=)
  # @param cipher (see Encrypt#cipher=)
  # @param aead (see Encrypt#aead=)
  # @param s2k_hash (see Encrypt#add_password)
  # @param s2k_iterations (see Encrypt#add_password)
  # @param s2k_cipher (see Encrypt#add_password)
  # @return [void]
  def symmetric_encrypt(input:, output: nil, passwords:,
                        armored: nil,
                        compression: nil,
                        cipher: nil,
                        aead: nil,
                        s2k_hash: nil,
                        s2k_iterations: 0,
                        s2k_cipher: nil)
    Output.default(output) do |output_|
      enc = start_encrypt(input: input, output: output_)
      enc.options = {
        armored: armored,
        compression: compression,
        cipher: cipher,
        aead: aead,
      }
      passwords = [passwords] if passwords.is_a?(String)
      passwords.each do |password|
        enc.add_password(password,
                         s2k_hash: s2k_hash,
                         s2k_iterations: s2k_iterations,
                         s2k_cipher: s2k_cipher)
      end
      enc.execute
    end
  end

  # Decrypt encrypted data.
  #
  # @param input [Input] the input to read the encrypted data
  # @param output [Output] the output to write the decrypted data.
  #   If nil, the result will be returned directly as a String.
  # @return [nil, String]
  def decrypt(input:, output: nil)
    Output.default(output) do |output_|
      Rnp.call_ffi(:rnp_decrypt, @ptr, input.ptr, output_.ptr)
    end
  end

  # Start a {Generate} operation.
  #
  # @param type [String, Symbol] the key type to generate (RSA, DSA, etc)
  # @return [Generate]
  def start_generate(type:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_op_generate_create, pptr, @ptr, type.to_s)
    pgen = pptr.read_pointer
    Generate.new(pgen) unless pgen.null?
  end

  # Start a {Generate} operation.
  #
  # @param primary [Key] the primary key for which to generate a subkey
  # @param type [String, Symbol] the key type to generate (RSA, DSA, etc)
  # @return [Generate]
  def start_generate_subkey(primary:, type:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_op_generate_subkey_create, pptr, @ptr, primary.ptr,
                 type.to_s)
    pgen = pptr.read_pointer
    Generate.new(pgen) unless pgen.null?
  end

  # Create a {Sign} operation.
  #
  # @param input [Input] the input to read the data to be signed
  # @param output [Output] the output to write the signatures
  def start_sign(input:, output:)
    _start_sign(:rnp_op_sign_create, input, output)
  end

  # Create a cleartext {Sign} operation.
  #
  # @param input (see #start_sign)
  # @param output (see #start_sign)
  def start_cleartext_sign(input:, output:)
    _start_sign(:rnp_op_sign_cleartext_create, input, output)
  end

  # Create a detached {Sign} operation.
  #
  # @param input (see #start_sign)
  # @param output (see #start_sign)
  def start_detached_sign(input:, output:)
    _start_sign(:rnp_op_sign_detached_create, input, output)
  end

  # Create a {Verify} operation.
  #
  # @param input [Input] the input to read the signatures
  # @param output [Output] the output (if any) to write the verified data
  def start_verify(input:, output: nil)
    output = Output.to_null unless output
    _start_verify(:rnp_op_verify_create, input, output)
  end

  # Create a detached {Verify} operation.
  #
  # @param data [Input] the input to read the signed data
  # @param signature [Input] the input to read the signatures
  def start_detached_verify(data:, signature:)
    _start_verify(:rnp_op_verify_detached_create, data, signature)
  end

  # Create an {Encrypt} operation.
  #
  # @param input [Input] the input to read the plaintext
  # @param output [Output] the output to write the encrypted data
  def start_encrypt(input:, output:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_op_encrypt_create, pptr, @ptr, input.ptr, output.ptr)
    pencrypt = pptr.read_pointer
    Encrypt.new(pencrypt) unless pencrypt.null?
  end

  # Import keys
  #
  # @param input [Input] the input to read the (OpenPGP-format) keys from
  # @param public_keys [Boolean] whether to load public keys
  # @param secret_keys [Boolean] whether to load secret keys
  # @return [Hash] information on the imported keys
  def import_keys(input:, public_keys: true, secret_keys: true)
    flags = 0
    flags |= LibRnp::RNP_LOAD_SAVE_PUBLIC_KEYS if public_keys
    flags |= LibRnp::RNP_LOAD_SAVE_SECRET_KEYS if secret_keys
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_import_keys, @ptr, input.ptr, flags, pptr)
    begin
      presults = pptr.read_pointer
      JSON.parse(presults.read_string) unless pptr.null?
    ensure
      LibRnp.rnp_buffer_destroy(presults)
    end
  end

  # Import signatures
  #
  # @param input [Input] the input to read the (OpenPGP-format) keys from
  # @return [Hash] information on the imported keys
  def import_signatures(input:)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_import_signatures, @ptr, input.ptr, 0, pptr)
    begin
      presults = pptr.read_pointer
      JSON.parse(presults.read_string) unless pptr.null?
    ensure
      LibRnp.rnp_buffer_destroy(presults)
    end
  end

  private

  KEY_PROVIDER = lambda do |provider, _rnp, _ctx, identifier_type, identifier, secret|
    provider.call(identifier_type, identifier, secret)
  end

  PASS_PROVIDER = lambda do |provider, _rnp, _ctx, pkey, reason, buf, buf_len|
    begin
      if provider.is_a?(String)
        # we were provided a a literal password
        password = provider
      else
        key = Key.new(pkey, false) unless pkey.null?
        password = provider.call(key, reason)
      end
      return false unless password && password.size < buf_len
      buf.write_string(password)
      return true
    rescue
      puts $ERROR_INFO
      return false
    end
  end

  def simple_sign(sign, signers)
    signers = [signers] if signers.is_a?(Key)
    signers.each do |signer|
      sign.add_signer(signer)
    end
    sign.execute
  end

  def _start_sign(func, input, output)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(func, pptr, @ptr, input.ptr, output.ptr)
    psign = pptr.read_pointer
    Rnp::Sign.new(psign) unless psign.null?
  end

  def _start_verify(func, io1, io2)
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(func, pptr, @ptr, io1.ptr, io2.ptr)
    pverify = pptr.read_pointer
    Verify.new(pverify) unless pverify.null?
  end

  def simple_encrypt(enc, recipients: nil, signers: nil)
    recipients = [recipients] if recipients.is_a?(Key)
    recipients&.each do |recipient|
      enc.add_recipient(recipient)
    end
    signers = [signers] if signers.is_a?(Key)
    signers&.each do |signer|
      enc.add_signer(signer)
    end
    enc.execute
  end

  def each_identifier(type, &block)
    block or return enum_for(:identifier_iterator, type)
    identifier_iterator(type, &block)
    self
  end

  def identifier_iterator(identifier_type)
    pptr = FFI::MemoryPointer.new(:pointer)
    piterator = nil
    Rnp.call_ffi(:rnp_identifier_iterator_create, @ptr, pptr, identifier_type)
    piterator = pptr.read_pointer
    loop do
      Rnp.call_ffi(:rnp_identifier_iterator_next, piterator, pptr)
      pidentifier = pptr.read_pointer
      break if pidentifier.null?
      yield pidentifier.read_string
    end
  ensure
    LibRnp.rnp_identifier_iterator_destroy(piterator) if piterator
  end

  def load_save_flags(public_keys:, secret_keys:)
    flags = 0
    flags |= LibRnp::RNP_LOAD_SAVE_PUBLIC_KEYS if public_keys
    flags |= LibRnp::RNP_LOAD_SAVE_SECRET_KEYS if secret_keys
    flags
  end

  def unload_keys_flags(public_keys:, secret_keys:)
    flags = 0
    flags |= LibRnp::RNP_KEY_UNLOAD_PUBLIC if public_keys
    flags |= LibRnp::RNP_KEY_UNLOAD_SECRET if secret_keys
    flags
  end
end # class

