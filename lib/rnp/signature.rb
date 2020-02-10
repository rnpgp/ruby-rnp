# frozen_string_literal: true

# (c) 2020 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Class that represents a signature.
  class Signature
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

    # The type of the signing key (RSA, etc).
    #
    # @return [String]
    def type
      string_property(:rnp_signature_get_alg)
    end

    # The hash algorithm used in the signature.
    #
    # @return [String]
    def hash
      string_property(:rnp_signature_get_hash_alg)
    end

    # The signer's key id.
    #
    # @return [String]
    def keyid
      string_property(:rnp_signature_get_keyid)
    end

    # The time this signature was created at.
    #
    # @return [Time]
    def creation_time
      pcreation = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_signature_get_creation, @ptr, pcreation)
      Time.at(pcreation.read(:uint32))
    end

    # The signer's key.
    #
    # @return [Key]
    def signer
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_signature_get_signer, @ptr, pptr)
      pkey = pptr.read_pointer
      Key.new(pkey) unless pkey.null?
    end

    # JSON representation of this signature (as a Hash).
    #
    # @param mpi [Boolean] if true then MPIs will be included
    # @param raw [Boolean] if true then raw data will be included
    # @param grip [Boolean] if true then grips will be included
    # @return [Hash]
    def json(mpi: false, raw: false, grip: false)
      flags = 0
      flags |= LibRnp::RNP_JSON_DUMP_MPI if mpi
      flags |= LibRnp::RNP_JSON_DUMP_RAW if raw
      flags |= LibRnp::RNP_JSON_DUMP_GRIP if grip
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_signature_packet_to_json, @ptr, flags, pptr)
      begin
        pvalue = pptr.read_pointer
        JSON.parse(pvalue.read_string) unless pvalue.null?
      ensure
        LibRnp.rnp_buffer_destroy(pvalue)
      end
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
  end
end
