# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Class that represents an editable key signature (a certification,
  # direct-key or revocation signature) being built.
  #
  # It is created via one of {Key#start_certification},
  # {Key#start_direct_signature} or {Key#start_revocation_signature},
  # customized via the setter methods, and finalized (which also adds it
  # to the corresponding key) via {#sign}.
  #
  # @note The signing (certifying) key must be secret and must remain in
  #   the keyring until {#sign} is called.
  class KeySignature
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_signature_handle_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    # Set the hash algorithm used during signing.
    #
    # @param hash [String] the hash algorithm name ('SHA256', etc)
    # @return [void]
    def hash=(hash)
      Rnp.call_ffi(:rnp_key_signature_set_hash, @ptr, hash.to_s)
    end

    # Set the signature creation time (the current time is used by
    # default).
    #
    # @param creation_time [Time, Integer] the creation time. As an
    #   integer, this is the number of seconds since the unix epoch.
    # @return [void]
    def creation_time=(creation_time)
      creation_time = creation_time.to_i if creation_time.is_a?(::Time)
      Rnp.call_ffi(:rnp_key_signature_set_creation, @ptr, creation_time)
    end

    # Set the key usage flags, i.e. whether the key is usable for signing,
    # encryption, etc.
    #
    # @note RNP does not check whether the flags are applicable to the key
    #   itself (i.e. the signing flag for an encryption-only key).
    #
    # @param flags [Integer] OR-ed combination of the
    #   LibRnp::RNP_KEY_USAGE_* constants
    # @return [void]
    def key_flags=(flags)
      Rnp.call_ffi(:rnp_key_signature_set_key_flags, @ptr, flags)
    end

    # Set the key expiration time. Makes sense only for self-certification
    # or direct-key signatures.
    #
    # @param expiration [Integer] the number of seconds since the key
    #   creation time when the key is considered valid. A value of 0
    #   indicates no expiration.
    # @return [void]
    def key_expiration=(expiration)
      Rnp.call_ffi(:rnp_key_signature_set_key_expiration, @ptr, expiration)
    end

    # Set the key features. Makes sense only for self-signatures.
    #
    # @param features [Integer] OR-ed combination of the
    #   LibRnp::RNP_KEY_FEATURE_* constants
    # @return [void]
    def features=(features)
      Rnp.call_ffi(:rnp_key_signature_set_features, @ptr, features)
    end

    # Add a preferred symmetric algorithm. Should be called for each
    # algorithm, with the first ones having higher priority.
    #
    # @param cipher [String] the cipher algorithm name
    # @return [void]
    def add_preferred_cipher(cipher)
      Rnp.call_ffi(:rnp_key_signature_add_preferred_alg, @ptr, cipher.to_s)
    end

    # Add a preferred hash algorithm. Should be called for each algorithm,
    # with the first ones having higher priority.
    #
    # @param hash [String] the hash algorithm name
    # @return [void]
    def add_preferred_hash(hash)
      Rnp.call_ffi(:rnp_key_signature_add_preferred_hash, @ptr, hash.to_s)
    end

    # Add a preferred compression algorithm. Should be called for each
    # algorithm, with the first ones having higher priority.
    #
    # @param zalg [String] the compression algorithm name
    # @return [void]
    def add_preferred_compression(zalg)
      Rnp.call_ffi(:rnp_key_signature_add_preferred_zalg, @ptr, zalg.to_s)
    end

    # Set whether the certified userid should be considered as the primary
    # one. Makes sense only for self-certifications.
    #
    # @param primary [Boolean]
    # @return [void]
    def primary_uid=(primary)
      Rnp.call_ffi(:rnp_key_signature_set_primary_uid, @ptr, primary)
    end

    # Set the key server URL applicable for the key.
    #
    # @param key_server [String, nil] the key server URL. If nil or empty,
    #   the key server field is removed from the signature.
    # @return [void]
    def key_server=(key_server)
      Rnp.call_ffi(:rnp_key_signature_set_key_server, @ptr, key_server)
    end

    # Set the key server preferences flags.
    #
    # @param flags [Integer] OR-ed combination of the
    #   LibRnp::RNP_KEY_SERVER_* constants
    # @return [void]
    def key_server_prefs=(flags)
      Rnp.call_ffi(:rnp_key_signature_set_key_server_prefs, @ptr, flags)
    end

    # Set the revocation reason code and text. Makes sense only for
    # revocation signatures.
    #
    # @param code [String, nil] the revocation reason code ('no reason',
    #   'superseded', 'compromised', 'retired'). If nil, the default one
    #   is used.
    # @param reason [String, nil] the human-readable reason
    # @return [void]
    def set_revocation_reason(code, reason)
      Rnp.call_ffi(:rnp_key_signature_set_revocation_reason, @ptr, code,
                   reason)
    end

    # Set the designated revoker (a key which is allowed to revoke this
    # key). Only a single revoker can be set: subsequent calls overwrite
    # the previous one.
    #
    # @param key [Key] the revoker's key
    # @param sensitive [Boolean] whether information about the revocation
    #   key should be considered sensitive
    # @return [void]
    def set_revoker(key, sensitive: false)
      flags = sensitive ? LibRnp::RNP_REVOKER_SENSITIVE : 0
      Rnp.call_ffi(:rnp_key_signature_set_revoker, @ptr, key.ptr, flags)
    end

    # Set the signature trust level and amount. Makes sense only for
    # certifications of other keys.
    #
    # @param level [Integer] the trust level
    # @param amount [Integer] the trust amount
    # @return [void]
    def set_trust_level(level, amount)
      Rnp.call_ffi(:rnp_key_signature_set_trust_level, @ptr, level, amount)
    end

    # Finalize and sign the signature, adding it to the corresponding key.
    #
    # @return [self]
    def sign
      Rnp.call_ffi(:rnp_key_signature_sign, @ptr)
      self
    end
  end
end
