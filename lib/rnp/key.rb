# frozen_string_literal: true

# (c) 2018-2020 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'
require 'rnp/userid'

class Rnp
  # Class that represents a PGP key (potentially encompassing both the public
  # and private portions).
  class Key
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr, free = true)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      if free
        @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      else
        @ptr = ptr
      end
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_key_handle_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    def to_s
      "#<#{self.class}:#{keyid}>"
    end

    # Get the fingerprint of the key
    #
    # @return [String]
    def fingerprint
      string_property(:rnp_key_get_fprint)
    end

    # Get the keyid of the key
    #
    # @return [String]
    def keyid
      string_property(:rnp_key_get_keyid)
    end

    # Get the grip of the key
    #
    # @return [String]
    def grip
      string_property(:rnp_key_get_grip)
    end

    # Get the primary grip of the key (for subkeys)
    #
    # @return [String]
    def primary_grip
      string_property(:rnp_key_get_primary_grip)
    end

    # Get the primary userid of the key
    #
    # @return [String]
    def primary_userid
      string_property(:rnp_key_get_primary_uid)
    end

    # Enumerate each userid for this key.
    #
    # @return [self, Enumerator]
    def each_userid(&block)
      block or return enum_for(:userid_iterator)
      userid_iterator(&block)
      self
    end

    # Get a list of all userids for this key.
    #
    # @return [Array<String>]
    def userids
      each_userid.to_a
    end

    # Enumerate each {UserID} for this key.
    #
    # @return [self, Enumerator]
    def each_uid(&block)
      block or return enum_for(:uid_iterator)
      uid_iterator(&block)
      self
    end

    # Get a list of {UserID}s for this key.
    #
    # @return [Array<UserID>]
    def uids
      each_uid.to_a
    end

    # Enumerate each {Signature} for this key.
    #
    # @return [self, Enumerator]
    def each_signature(&block)
      block or return enum_for(:signature_iterator)
      signature_iterator(&block)
      self
    end

    # Get a list of {Signature}s for this key.
    #
    # @return [Array<Signature>]
    def signatures
      each_signature.to_a
    end

    # Add a userid to a key.
    #
    # @param userid [String] the userid to add
    # @param hash (see Sign#hash=)
    # @param expiration_time (see Sign#expiration_time=)
    # @param key_flags [Integer]
    # @param primary [Boolean] if true then this userid will be marked as the
    #   primary userid
    # @return [void]
    def add_userid(userid, hash: nil, expiration_time: 0, key_flags: 0,
                   primary: false)
      Rnp.call_ffi(:rnp_key_add_uid, @ptr, userid, hash, expiration_time,
                   key_flags, primary)
    end

    # Returns true if the key is currently locked.
    #
    # @return [Boolean]
    def locked?
      bool_property(:rnp_key_is_locked)
    end

    # Lock the key.
    #
    # @return [self]
    def lock
      Rnp.call_ffi(:rnp_key_lock, @ptr)
      self
    end

    # Unlock the key.
    #
    # @param password [String, nil] the password to unlock the key. If nil, the
    #   current password provider will be used (see {Rnp#password_provider=}).
    # @return [self]
    def unlock(password = nil)
      Rnp.call_ffi(:rnp_key_unlock, @ptr, password)
      self
    end

    # Returns true if the key is currently protected.
    #
    # @return [Boolean]
    def protected?
      bool_property(:rnp_key_is_protected)
    end

    # Protect or re-protect the key.
    #
    # @param password [String] the password with which to encrypt the key.
    # @param cipher [String] the cipher algorithm to encrypt with
    # @param cipher_mode [String] the cipher mode
    # @param s2k_hash (see Encrypt#add_password)
    # @param s2k_iterations (see Encrypt#add_password)
    # @return [self]
    def protect(password, cipher: nil, cipher_mode: nil, s2k_hash: nil,
                s2k_iterations: 0)
      Rnp.call_ffi(:rnp_key_protect, @ptr, password, cipher, cipher_mode,
                   s2k_hash, s2k_iterations)
      self
    end

    # Unprotect the key.
    #
    # @param password [String, nil] the password to unlock the key. If nil,
    #   the current password provider will be used (see {Rnp#password_provider=}).
    # @return [self]
    def unprotect(password = nil)
      Rnp.call_ffi(:rnp_key_unprotect, @ptr, password)
      self
    end

    # Returns true if the key is a primary key.
    #
    # @return [Boolean]
    def primary?
      bool_property(:rnp_key_is_primary)
    end

    # Returns true if the key is a subkey.
    #
    # @return [Boolean]
    def sub?
      bool_property(:rnp_key_is_sub)
    end

    # Returns true if the public key packet is available.
    #
    # @return [Boolean]
    def public_key_present?
      bool_property(:rnp_key_have_public)
    end

    # Returns true if the secret key packet is available.
    #
    # @return [Boolean]
    def secret_key_present?
      bool_property(:rnp_key_have_secret)
    end

    # Export a public key.
    #
    # By default, when exporting a primary key, only the primary key
    # will be exported. When exporting a subkey, the primary key and
    # subkey will both be exported.
    #
    # @param output [Output] the output to write the exported key.
    #   If nil, the result will be returned directly as a String.
    # @param armored (see Sign#armored=)
    # @param with_subkeys [Boolean] when exporting a primary key,
    #   this controls whether all subkeys should also be exported.
    #   When true, the primary key and all subkeys will be exported.
    #   When false, only the primary key will be exported.
    #   This parameter is not valid when the key is a subkey.
    # @return [nil, String]
    def export_public(armored: true, with_subkeys: false, output: nil)
      Output.default(output) do |output_|
        export(public_key: true, with_subkeys: with_subkeys, armored: armored, output: output_)
      end
    end

    # Export a secret key.
    #
    # By default, when exporting a primary key, only the primary key
    # will be exported. When exporting a subkey, the primary key and
    # subkey will both be exported.
    #
    # @param output [Output] the output to write the exported key.
    #   If nil, the result will be returned directly as a String.
    # @param armored (see Sign#armored=)
    # @param with_subkeys [Boolean] when exporting a primary key,
    #   this controls whether all subkeys should also be exported.
    #   When true, the primary key and all subkeys will be exported.
    #   When false, only the primary key will be exported.
    #   This parameter is not valid when the key is a subkey.
    # @return [nil, String]
    def export_secret(armored: true, with_subkeys: false, output: nil)
      Output.default(output) do |output_|
        export(secret_key: true, with_subkeys: with_subkeys, armored: armored, output: output_)
      end
    end

    # Returns the raw public key data as PGP packets.
    #
    # @return [String]
    def public_key_data
      buf_property(:rnp_get_public_key_data)
    end

    # Returns the raw secret key data.
    #
    # The format may be either PGP packets or an s-expr/G10.
    #
    # @return [String]
    def secret_key_data
      buf_property(:rnp_get_secret_key_data)
    end

    # Return a JSON representation of this key (as a Hash).
    #
    # @param public_mpis [Boolean] if true then public MPIs will be included
    # @param secret_mpis [Boolean] if true then secret MPIs will be included
    # @param signatures [Boolean] if true then signatures will be included
    # @param signature_mpis [Boolean] if true then signature MPIs will be
    #   included
    # @return [Hash]
    def json(public_mpis: false, secret_mpis: false, signatures: true,
             signature_mpis: false)
      flags = 0
      flags |= LibRnp::RNP_JSON_PUBLIC_MPIS if public_mpis
      flags |= LibRnp::RNP_JSON_SECRET_MPIS if secret_mpis
      flags |= LibRnp::RNP_JSON_SIGNATURES if signatures
      flags |= LibRnp::RNP_JSON_SIGNATURE_MPIS if signature_mpis
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_key_to_json, @ptr, flags, pptr)
      begin
        presult = pptr.read_pointer
        JSON.parse(presult.read_string) unless presult.null?
      ensure
        LibRnp.rnp_buffer_destroy(presult)
      end
    end

    # Unload this key.
    #
    # @note When both the public and secret portions of this key have been
    # unloaded, you should no longer interact with this object.
    #
    # @param unload_public [Boolean] if true then the public key will be
    #   unloaded
    # @param unload_secret [Boolean] if true then the secret  key will be
    #   unloaded
    # @return [void]
    def unload(unload_public: true, unload_secret: true)
      flags = 0
      flags |= LibRnp::RNP_KEY_REMOVE_PUBLIC if unload_public
      flags |= LibRnp::RNP_KEY_REMOVE_SECRET if unload_secret
      Rnp.call_ffi(:rnp_key_remove, @ptr, flags)
    end

    # Enumerate each subkey for this key.
    #
    # @return [self, Enumerator]
    def each_subkey(&block)
      block or return enum_for(:subkey_iterator)
      subkey_iterator(&block)
      self
    end

    # Get a list of all subkeys for this key.
    #
    # @return [Array<Key>]
    def subkeys
      each_subkey.to_a
    end

    # Get the type of this key (RSA, etc).
    #
    # @return [String]
    def type
      string_property(:rnp_key_get_alg)
    end

    # Get the bit length for this key.
    #
    # @return [Integer]
    def bits
      pbits = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_key_get_bits, @ptr, pbits)
      pbits.read(:uint32)
    end

    # Get the bit length for the q parameter of this DSA key.
    #
    # @return [Integer]
    def qbits
      pbits = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_key_get_dsa_qbits, @ptr, pbits)
      pbits.read(:uint32)
    end

    # Get the curve of this EC key.
    #
    # @return [String]
    def curve
      string_property(:rnp_key_get_curve)
    end

    # Query whether this key can be used to perform a certain operation.
    #
    # @param op [String,Symbol] the operation to query (sign, etc)
    # @return [Boolean]
    def can?(op)
      pvalue = FFI::MemoryPointer.new(:bool)
      Rnp.call_ffi(:rnp_key_allows_usage, @ptr, op.to_s, pvalue)
      pvalue.read(:bool)
    end

    # Check if this has been revoked.
    #
    # @return [Boolean]
    def revoked?
      bool_property(:rnp_key_is_revoked)
    end

    # Check if this revoked key's material was compromised.
    #
    # @return [Boolean]
    def compromised?
      bool_property(:rnp_key_is_compromised)
    end

    # Check if this revoked key was retired.
    #
    # @return [Boolean]
    def retired?
      bool_property(:rnp_key_is_retired)
    end

    # Check if this revoked key was superseded by another key.
    #
    # @return [Boolean]
    def superseded?
      bool_property(:rnp_key_is_superseded)
    end

    # Retrieve the reason for revoking this key, if any.
    #
    # @return [String]
    def revocation_reason
      string_property(:rnp_key_get_revocation_reason)
    end

    # Retrieve the creation time of the key
    #
    # @return [Time]
    def creation_time
      ptime = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_key_get_creation, @ptr, ptime)
      Time.at(ptime.read(:uint32))
    end

    # Retrieve the expiration time of the key
    #
    # @return [Time]
    def expiration_time
      ptime = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_key_get_expiration, @ptr, ptime)
      Time.at(ptime.read(:uint32))
    end

    # Get the OpenPGP version of the key.
    #
    # @return [Integer]
    def version
      pversion = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_key_get_version, @ptr, pversion)
      pversion.read(:uint32)
    end

    # Check whether the key is expired.
    #
    # @note While an expired key cannot be used to generate new signatures
    #   or encrypt to, it can still be used to verify older signatures and
    #   decrypt previously encrypted data.
    #
    # @return [Boolean]
    def expired?
      bool_property(:rnp_key_is_expired)
    end

    # Check whether the public key is valid. This includes checks of the
    # self-signatures, expiration times, revocations, etc.
    #
    # @return [Boolean]
    def valid?
      bool_property(:rnp_key_is_valid)
    end

    # Get the time till which the key can be considered valid. This takes
    # into account not only the key's expiration, but revocations as well
    # (and, for a subkey, the primary key's validity time).
    #
    # @return [Time, nil] nil if the key never expires
    def valid_till
      ptime = FFI::MemoryPointer.new(:uint64)
      Rnp.call_ffi(:rnp_key_valid_till64, @ptr, ptime)
      time = ptime.read(:uint64)
      time == (1 << 64) - 1 ? nil : Time.at(time)
    end

    # Get the fingerprint of the primary key.
    #
    # @note This is only valid for subkeys and raises an error for a
    #   primary key.
    #
    # @return [String]
    def primary_fingerprint
      string_property(:rnp_key_get_primary_fprint)
    end

    # Get a list of the designated revokers of the key (keys which are
    # allowed to revoke this key).
    #
    # @return [Array<String>] a list of revoker key fingerprints
    def revokers
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_key_get_revoker_count, @ptr, pcount)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...pcount.read(:size_t)).map do |idx|
        Rnp.call_ffi(:rnp_key_get_revoker_at, @ptr, idx, pptr)
        begin
          prevoker = pptr.read_pointer
          prevoker.read_string unless prevoker.null?
        ensure
          LibRnp.rnp_buffer_destroy(prevoker)
        end
      end
    end

    # Get the key's revocation signature, if any.
    #
    # @return [Signature, nil] nil if there is no valid revocation
    #   signature
    def revocation_signature
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_key_get_revocation_signature, @ptr, pptr)
      psig = pptr.read_pointer
      Signature.new(psig) unless psig.null?
    end

    # Get the type of protection used for the secret key data.
    #
    # @return [String] one of 'None', 'Encrypted', 'Encrypted-Hashed',
    #   'GPG-None', 'GPG-Smartcard' or 'Unknown'
    def protection_type
      string_property(:rnp_key_get_protection_type)
    end

    # Get the mode in which the secret key data is encrypted.
    #
    # @return [String] one of 'None', 'Unknown', 'CFB', 'CBC' or 'OCB'
    def protection_mode
      string_property(:rnp_key_get_protection_mode)
    end

    # Get the cipher used to encrypt the secret key data.
    #
    # @note This raises an error if the secret key data is not available
    #   or not encrypted.
    #
    # @return [String]
    def protection_cipher
      string_property(:rnp_key_get_protection_cipher)
    end

    # Get the hash used to derive the secret-key-data encrypting key from
    # the password.
    #
    # @note This raises an error if the secret key data is not available
    #   or not encrypted.
    #
    # @return [String]
    def protection_hash
      string_property(:rnp_key_get_protection_hash)
    end

    # Get the number of iterations used to derive the encrypting key from
    # the password.
    #
    # @note This raises an error if the secret key data is not available
    #   or not encrypted.
    #
    # @return [Integer]
    def protection_iterations
      piterations = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_key_get_protection_iterations, @ptr, piterations)
      piterations.read(:size_t)
    end

    # Start building a certification signature over a userid, issued by
    # this key. Customize the returned {KeySignature} and call
    # {KeySignature#sign} to finalize it.
    #
    # @note This key (the signer) must be secret.
    #
    # @param uid [UserID] the userid to certify. It may belong to this key
    #   (a self-certification) or to another key.
    # @param type [String, nil] the certification type ('generic',
    #   'persona', 'casual' or 'positive'). If nil, the default is used
    #   ('positive' for a self-certification, 'generic' otherwise).
    # @return [KeySignature]
    def start_certification(uid, type: nil)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_key_certification_create, @ptr, uid.ptr, type, pptr)
      psig = pptr.read_pointer
      KeySignature.new(psig) unless psig.null?
    end

    # Start building a direct-key signature, issued by this key. Customize
    # the returned {KeySignature} and call {KeySignature#sign} to finalize
    # it.
    #
    # @note This key (the signer) must be secret.
    #
    # @param target [Key, nil] the key to sign. If nil, the signature is
    #   made over this key itself (a self-signature).
    # @return [KeySignature]
    def start_direct_signature(target = nil)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_key_direct_signature_create, @ptr, target&.ptr,
                   pptr)
      psig = pptr.read_pointer
      KeySignature.new(psig) unless psig.null?
    end

    # Start building a key or subkey revocation signature, issued by this
    # key. Customize the returned {KeySignature} and call
    # {KeySignature#sign} to finalize it.
    #
    # @note This key (the revoker) must be secret.
    #
    # @param target [Key, nil] the key to revoke. If nil, this key will
    #   revoke itself.
    # @return [KeySignature]
    def start_revocation_signature(target = nil)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_key_revocation_signature_create, @ptr, target&.ptr,
                   pptr)
      psig = pptr.read_pointer
      KeySignature.new(psig) unless psig.null?
    end

    # Remove unneeded signatures from the key, its userids and subkeys.
    #
    # @note Any signature handles related to this key, its uids or subkeys
    #   should not be used after this call.
    #
    # @param invalid [Boolean] remove signatures that are invalid and were
    #   never valid
    # @param unknown_key [Boolean] remove signatures made by an unknown
    #   key
    # @param non_self [Boolean] remove signatures that are not
    #   self-signatures
    # @return [void]
    def remove_signatures(invalid: false, unknown_key: false,
                          non_self: false)
      flags = 0
      flags |= LibRnp::RNP_KEY_SIGNATURE_INVALID if invalid
      flags |= LibRnp::RNP_KEY_SIGNATURE_UNKNOWN_KEY if unknown_key
      flags |= LibRnp::RNP_KEY_SIGNATURE_NON_SELF_SIG if non_self
      Rnp.call_ffi(:rnp_key_remove_signatures, @ptr, flags, nil, nil)
    end

    # Remove a single signature from the key.
    #
    # @note The signature must have been obtained via this key or one of
    #   its userids. Other handles of the same signature should not be
    #   used after this call.
    #
    # @param signature [Signature] the signature to remove
    # @return [void]
    def remove_signature(signature)
      Rnp.call_ffi(:rnp_signature_remove, @ptr, signature.ptr)
    end

    # Revoke the key (or subkey) by generating and adding a revocation
    # signature.
    #
    # @note For a primary key the secret key must be available (otherwise
    #   the keyrings are searched for a secret key authorized to issue
    #   revocation signatures). For a subkey the primary secret key must
    #   be available. If the secret key is locked, the password will be
    #   asked via the password provider.
    #
    # @param hash [String, nil] the hash algorithm to use for the
    #   signature (nil for the default)
    # @param code [String, nil] the revocation reason code: 'no',
    #   'superseded', 'compromised' or 'retired' (nil for 'no')
    # @param reason [String, nil] the human-readable revocation reason
    # @return [void]
    def revoke(hash: nil, code: nil, reason: nil)
      Rnp.call_ffi(:rnp_key_revoke, @ptr, 0, hash, code, reason)
    end

    # Set the key's expiration time. This requires re-signing, so the
    # secret key (or, for a subkey, the secret primary key) must be
    # available. If the secret key is locked, the password will be asked
    # via the password provider.
    #
    # @param seconds [Integer] the expiration time in seconds, calculated
    #   from the key creation time (0 if the key doesn't expire)
    # @return [void]
    def set_expiration(seconds)
      Rnp.call_ffi(:rnp_key_set_expiration, @ptr, seconds)
    end

    # Get the default key for the specified usage. Accepts a primary key
    # and returns one of its subkeys suitable for the desired usage (or
    # the primary key itself, if suitable).
    #
    # @param usage [String, Symbol] the desired key usage ('sign',
    #   'certify', 'encrypt', etc)
    # @param subkeys_only [Boolean] if true, only subkeys are considered;
    #   otherwise the primary key may be returned if it is suitable
    # @return [Key, nil] nil if no key with the desired usage was found
    def default_key(usage, subkeys_only: false)
      flags = subkeys_only ? LibRnp::RNP_KEY_SUBKEYS_ONLY : 0
      pptr = FFI::MemoryPointer.new(:pointer)
      rc = LibRnp.rnp_key_get_default_key(@ptr, usage.to_s, flags, pptr)
      if [LibRnp::RNP_ERROR_KEY_NOT_FOUND,
          LibRnp::RNP_ERROR_NO_SUITABLE_KEY].include?(rc)
        return nil
      end
      Rnp.raise_error('rnp_key_get_default_key failed', rc) unless rc.zero?
      pkey = pptr.read_pointer
      Key.new(pkey) unless pkey.null?
    end

    # Export the key in the minimal form used by the Autocrypt feature
    # (primary key, userid, signature, subkey, binding signature).
    #
    # @param subkey [Key, nil] the subkey to export (nil to pick the
    #   first suitable one)
    # @param uid [String, nil] the userid to export (may be nil if the
    #   key has only one userid)
    # @param base64 [Boolean] if true, the output is base64-encoded
    #   instead of binary OpenPGP packets
    # @param output [Output] the output to write to. If nil, the result
    #   will be returned directly as a String.
    # @return [nil, String]
    def export_autocrypt(subkey: nil, uid: nil, base64: false, output: nil)
      flags = base64 ? LibRnp::RNP_KEY_EXPORT_BASE64 : 0
      Output.default(output) do |output_|
        Rnp.call_ffi(:rnp_key_export_autocrypt, @ptr, subkey&.ptr, uid,
                     output_.ptr, flags)
      end
    end

    # Generate and export a revocation signature for the key.
    #
    # @note This only exports the revocation signature. To actually
    #   revoke the key, import the signature into the keystore or use
    #   {#revoke}.
    #
    # @param output [Output] the output to write the signature to. If
    #   nil, the result will be returned directly as a String.
    # @param armored [Boolean] whether to ASCII-armor the output
    # @param hash (see #revoke)
    # @param code (see #revoke)
    # @param reason (see #revoke)
    # @return [nil, String]
    def export_revocation(output: nil, armored: true, hash: nil, code: nil,
                          reason: nil)
      flags = armored ? LibRnp::RNP_KEY_EXPORT_ARMORED : 0
      Output.default(output) do |output_|
        Rnp.call_ffi(:rnp_key_export_revocation, @ptr, output_.ptr, flags,
                     hash, code, reason)
      end
    end

    # Tweak the Curve25519 secret key's least and most significant bits
    # so that the exported secret key is compatible with implementations
    # which do not tweak these bits automatically (see RFC 7748, sec. 5).
    #
    # @note This is an advanced operation. It requires an unlocked
    #   ECDH Curve25519 secret key, so make sure to call {#lock}
    #   afterwards.
    #
    # @return [void]
    def x25519_bits_tweak
      Rnp.call_ffi(:rnp_key_25519_bits_tweak, @ptr)
    end

    # Check whether the Curve25519 secret key's bits are correctly set
    # (tweaked). If not, {#x25519_bits_tweak} should be called so that
    # the exported secret key is compatible with implementations which
    # do not tweak these bits automatically (see RFC 7748, sec. 5).
    #
    # @note This is an advanced operation. It requires an unlocked
    #   ECDH Curve25519 secret key.
    #
    # @return [Boolean] true if the secret key's bits are correctly set
    def x25519_bits_tweaked?
      presult = FFI::MemoryPointer.new(:bool)
      Rnp.call_ffi(:rnp_key_25519_bits_tweaked, @ptr, presult)
      presult.read(:bool)
    end

    private

    def string_property(func)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(func, @ptr, pptr)
      begin
        pvalue = pptr.read_pointer
        pvalue.read_string unless pvalue.null?
      ensure
        LibRnp.rnp_buffer_destroy(pvalue)
      end
    end

    def bool_property(func)
      presult = FFI::MemoryPointer.new(:bool)
      Rnp.call_ffi(func, @ptr, presult)
      presult.read(:bool)
    end

    def buf_property(func)
      pptr = FFI::MemoryPointer.new(:pointer)
      pbuflen = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(func, @ptr, pptr, pbuflen)
      begin
        pbuf = pptr.read_pointer
        buflen = pbuflen.read(:size_t)
        pbuf.read_bytes(buflen) unless pbuf.null?
      ensure
        LibRnp.rnp_buffer_destroy(pbuf)
      end
    end

    def userid_iterator
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_key_get_uid_count, @ptr, pcount)
      count = pcount.read(:size_t)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...count).each do |i|
        Rnp.call_ffi(:rnp_key_get_uid_at, @ptr, i, pptr)
        begin
          puserid = pptr.read_pointer
          yield puserid.read_string unless puserid.null?
        ensure
          LibRnp.rnp_buffer_destroy(puserid)
        end
      end
    end

    def uid_iterator
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_key_get_uid_count, @ptr, pcount)
      count = pcount.read(:size_t)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...count).each do |i|
        Rnp.call_ffi(:rnp_key_get_uid_handle_at, @ptr, i, pptr)
        begin
          phandle = pptr.read_pointer
          puserid = nil
          next if phandle.nil?
          Rnp.call_ffi(:rnp_key_get_uid_at, @ptr, i, pptr)
          puserid = pptr.read_pointer
          yield UserID.new(phandle, puserid.read_string, self) unless puserid.null?
          phandle = nil
        ensure
          LibRnp.rnp_uid_handle_destroy(phandle)
          LibRnp.rnp_buffer_destroy(puserid)
        end
      end
    end

    def signature_iterator
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_key_get_signature_count, @ptr, pcount)
      count = pcount.read(:size_t)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...count).each do |i|
        Rnp.call_ffi(:rnp_key_get_signature_at, @ptr, i, pptr)
        psig = pptr.read_pointer
        yield Signature.new(psig) unless psig.null?
      end
    end

    def export(public_key: false, secret_key: false, with_subkeys: false, armored: true, output: nil)
      flags = 0
      flags |= LibRnp::RNP_KEY_EXPORT_ARMORED if armored
      flags |= LibRnp::RNP_KEY_EXPORT_PUBLIC if public_key
      flags |= LibRnp::RNP_KEY_EXPORT_SECRET if secret_key
      flags |= LibRnp::RNP_KEY_EXPORT_SUBKEYS if with_subkeys
      Rnp.call_ffi(:rnp_key_export, @ptr, output.ptr, flags)
    end

    def subkey_iterator
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_key_get_subkey_count, @ptr, pcount)
      count = pcount.read(:size_t)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...count).each do |i|
        Rnp.call_ffi(:rnp_key_get_subkey_at, @ptr, i, pptr)
        begin
          psubkey = pptr.read_pointer
          yield Rnp::Key.new(psubkey) unless psubkey.null?
        end
      end
    end
  end # class
end # class

