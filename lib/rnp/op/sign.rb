# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Signing operation
  class Sign
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_op_sign_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    # Add a signer.
    #
    # @note The optional (per-signature) options here are not supported by RNP
    #   internally at the time of this writing.
    #
    # @param signer [Key] the signer
    # @param hash [String] (see #hash=)
    # @param creation_time (see #creation_time=)
    # @param expiration_time (see #expiration_time=)
    # @return [self]
    def add_signer(signer, hash: nil, creation_time: nil, expiration_time: nil)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_op_sign_add_signature, @ptr, signer.ptr, pptr)
      psig = pptr.read_pointer
      self.class.set_signature_options(
        psig,
        hash: hash,
        creation_time: creation_time,
        expiration_time: expiration_time
      )
    end

    # Set a group of options.
    #
    # @param armored see {#armored=}
    # @param compression see {#compression=}
    # @param hash see {#hash=}
    # @param creation_time see {#creation_time=}
    # @param expiration_time see {#expiration_time=}
    def options=(armored: nil, compression: nil, hash: nil,
                 creation_time: nil, expiration_time: nil)
      self.armored = armored unless armored.nil?
      self.compression = compression unless compression.nil?
      self.hash = hash unless hash.nil?
      self.creation_time = creation_time unless creation_time.nil?
      self.expiration_time = expiration_time unless expiration_time.nil?
    end

    # Set whether the output will be ASCII-armored.
    #
    # @param armored [Boolean] true if the output should be
    #        ASCII-armored, false otherwise.
    def armored=(armored)
      Rnp.call_ffi(:rnp_op_sign_set_armor, @ptr, armored)
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
      Rnp.call_ffi(:rnp_op_sign_set_compression, @ptr, compression[:algorithm],
                   compression[:level])
    end

    # Set the hash algorithm used for the signatures.
    #
    # @param hash [String] the hash algorithm name
    def hash=(hash)
      Rnp.call_ffi(:rnp_op_sign_set_hash, @ptr, hash)
    end

    # Set the creation time for signatures.
    #
    # @param creation_time [Time, Integer] the creation time to use for all
    #   signatures. As an integer, this is the number of seconds since the
    #   unix epoch.
    def creation_time=(creation_time)
      creation_time = creation_time.to_i if creation_time.is_a?(::Time)
      Rnp.call_ffi(:rnp_op_sign_set_creation_time, @ptr, creation_time)
    end

    # Set the expiration time for signatures.
    #
    # @param expiration_time [Integer] the lifetime of the signature(s), as the
    #   number of seconds. The actual expiration date/time is the creation time
    #   plus this value. A value of 0 will create signatures that do not expire.
    def expiration_time=(expiration_time)
      Rnp.call_ffi(:rnp_op_sign_set_expiration_time, @ptr, expiration_time)
    end

    # Execute the operation.
    #
    # This should only be called once.
    #
    # @return [void]
    def execute
      Rnp.call_ffi(:rnp_op_sign_execute, @ptr)
    end

    # @api private
    def self.set_signature_options(psig, hash:, creation_time:,
                                   expiration_time:)
      Rnp.call_ffi(:rnp_op_sign_signature_set_hash, psig, value) unless hash.nil?
      creation_time = creation_time.to_i if creation_time.is_a?(::Time)
      Rnp.call_ffi(:rnp_op_sign_signature_set_creation_time, psig, value) unless creation_time.nil?
      Rnp.call_ffi(:rnp_op_sign_signature_set_expiration_time, psig, value) unless expiration_time.nil?
    end
  end # class
end # class

