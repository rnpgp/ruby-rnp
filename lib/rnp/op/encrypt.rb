# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'set'

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Encryption operation
  class Encrypt
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_op_encrypt_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    # Add a recipient.
    #
    # @param recipient [Key] the recipient
    # @return [self]
    def add_recipient(recipient)
      Rnp.call_ffi(:rnp_op_encrypt_add_recipient, @ptr, recipient.ptr)
      self
    end

    # Add a signer.
    #
    # @param signer [Key] the signer
    # @param hash (see #hash=)
    # @param creation_time (see #creation_time=)
    # @param expiration_time (see #expiration_time=)
    # @return [self]
    def add_signer(signer, hash: nil, creation_time: nil, expiration_time: nil)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_op_encrypt_add_signature, @ptr, signer.ptr, pptr)
      psig = pptr.read_pointer
      Sign.set_signature_options(
        psig,
        hash: hash,
        creation_time: creation_time,
        expiration_time: expiration_time
      )
      self
    end

    # Add a password.
    #
    # @param password [String] the password
    # @param s2k_hash [String] the hash algorithm to use for the
    #   string-to-key key derivation.
    # @param s2k_iterations [Integer] the number of iterations for the
    #   string-to-key key derivation. A value of 0 will choose
    #   a default.
    # @param s2k_cipher [String] the cipher algorithm used to wrap the key.
    # @note This is a separate cipher from the one used to encrypt the main
    #   payload/stream (see {#cipher=}). This cipher may not be used in all
    #   circumstances. For example, when encrypting with *only* a password
    #   (no public keys), this cipher would generally not be used.
    #   When encrypting with a combination of one or more passwords and one
    #   or more public keys, this cipher would generally be used.
    # @return [self]
    def add_password(password, s2k_hash: nil, s2k_iterations: 0,
                     s2k_cipher: nil)
      Rnp.call_ffi(:rnp_op_encrypt_add_password, @ptr, password, s2k_hash,
                   s2k_iterations, s2k_cipher)
      self
    end

    # Set a group of options.
    #
    # @note Some options are related to signatures and will have no effect if
    # there are no signers.
    #
    # @param armored (see #armored=)
    # @param compression (see #compression=)
    # @param cipher (see #cipher=)
    # @param hash (see #hash=)
    # @param creation_time (see #creation_time=)
    # @param expiration_time (see #expiration_time=)
    def options=(armored: nil, compression: nil, cipher: nil, aead: nil,
                 hash: nil, creation_time: nil, expiration_time: nil)
      self.armored = armored unless armored.nil?
      self.compression = compression unless compression.nil?
      self.cipher = cipher unless cipher.nil?
      self.aead = aead unless aead.nil?
      self.hash = hash unless hash.nil?
      self.creation_time = creation_time unless creation_time.nil?
      self.expiration_time = expiration_time unless expiration_time.nil?
    end

    # Set whether the output will be ASCII-armored.
    #
    # @param armored [Boolean] true if the output should be
    #        ASCII-armored, false otherwise.
    def armored=(armored)
      Rnp.call_ffi(:rnp_op_encrypt_set_armor, @ptr, armored)
    end

    # Set the compression algorithm and level.
    #
    # @param [Hash<Symbol>] compression
    # @option compression [String] :algorithm the compression algorithm
    #   (bzip2, etc)
    # @option compression [Integer] :level the compression level. This should
    #   generally be between 0 (no compression) and 9 (best compression).
    def compression=(compression)
      if !compression.is_a?(Hash) || Set.new(compression.keys) != Set.new(%i[algorithm level])
        raise ArgumentError,
              'Compression option must be of the form: {algorithm: \'zlib\', level: 5}'
      end
      Rnp.call_ffi(:rnp_op_encrypt_set_compression, @ptr,
                   compression[:algorithm], compression[:level])
    end

    # Set the cipher used to encrypt the input.
    #
    # @param cipher [String] the cipher algorithm name
    def cipher=(cipher)
      Rnp.call_ffi(:rnp_op_encrypt_set_cipher, @ptr, cipher)
    end

    # Set the AEAD algorithm for encryption.
    #
    # @param mode [String] the AEAD algorithm to use for encryption
    def aead=(mode)
      Rnp.call_ffi(:rnp_op_encrypt_set_aead, @ptr, mode.to_s)
    end

    # Set the hash algorithm used for calculating signatures.
    #
    # @note This is only valid when there is one or more signer.
    #
    # @param hash [String] the hash algorithm name
    def hash=(hash)
      Rnp.call_ffi(:rnp_op_encrypt_set_hash, @ptr, hash)
    end

    # Set the creation time for signatures.
    #
    # @note This is only valid when there is one or more signer.
    #
    # @param creation_time [Time, Integer] the creation time to use for all
    #   signatures. As an integer, this is the number of seconds
    #   since the unix epoch.
    def creation_time=(creation_time)
      creation_time = creation_time.to_i if creation_time.is_a?(::Time)
      Rnp.call_ffi(:rnp_op_encrypt_set_creation_time, @ptr, creation_time)
    end

    # Set the expiration time for signatures.
    #
    # @note This is only valid when there is one or more signer.
    #
    # @param expiration_time [Integer] the lifetime of the signatures, as the number
    #        of seconds. The actual expiration date/time is the creation time
    #        plus this value. A value of 0 will create signatures that do not
    #        expire.
    def expiration_time=(expiration_time)
      Rnp.call_ffi(:rnp_op_encrypt_set_expiration_time, @ptr, expiration_time)
    end

    # Execute the operation.
    #
    # This should only be called once.
    #
    # @return [void]
    def execute
      Rnp.call_ffi(:rnp_op_encrypt_execute, @ptr)
    end
  end # class
end # class

