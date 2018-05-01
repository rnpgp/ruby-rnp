# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Verification operation
  class Verify
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      @signatures = nil
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_op_verify_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    # Execute the operation.
    #
    # This should only be called once.
    #
    # @return [void]
    # @raise [InvalidSignatureError, BadFormatError, ...] if the signature is
    #        expired, not correctly formed, invalid, etc.
    def execute
      Rnp.call_ffi(:rnp_op_verify_execute, @ptr)
    end

    # Check if all signatures are good.
    #
    # @return [Boolean] true if all signatures are valid and not expired.
    def good?
      sigs = signatures
      sigs.size && sigs.all?(&:good?)
    end

    # Get a list of the checked signatures.
    #
    # @return [Array<Signature>]
    def signatures
      return @signatures unless @signatures.nil?
      @signatures = []
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...signature_count).each do |i|
        Rnp.call_ffi(:rnp_op_verify_get_signature_at, @ptr, i, pptr)
        psig = pptr.read_pointer
        @signatures << Signature.new(psig)
      end
      @signatures
    end

    # Class representing an individual signature.
    class Signature
      # @api private
      attr_reader :status
      # The hash algorithm used for the signature
      # @return [String]
      attr_reader :hash
      # The key that created the signature
      # @return [Key]
      attr_reader :key
      # The creation time of the signature
      # @return [Time]
      attr_reader :creation_time
      # The expiration (as the number of seconds after {creation_time})
      # @return [Integer]
      attr_reader :expiration_time

      # @api private
      def initialize(ptr)
        # status
        @status = LibRnp.rnp_op_verify_signature_get_status(ptr)
        pptr = FFI::MemoryPointer.new(:pointer)

        # creation and expiration
        pcreation_time = FFI::MemoryPointer.new(:uint32)
        pexpiration_time = FFI::MemoryPointer.new(:uint32)
        Rnp.call_ffi(:rnp_op_verify_signature_get_times, ptr, pcreation_time,
                     pexpiration_time)
        @creation_time = Time.at(pcreation_time.read(:uint32))
        @expiration_time = pexpiration_time.read(:uint32)

        # hash
        Rnp.call_ffi(:rnp_op_verify_signature_get_hash, ptr, pptr)
        begin
          phash = pptr.read_pointer
          @hash = phash.read_string unless phash.null?
        ensure
          LibRnp.rnp_buffer_destroy(phash)
        end

        # key
        Rnp.call_ffi(:rnp_op_verify_signature_get_key, ptr, pptr)
        pkey = pptr.read_pointer
        @key = Key.new(pkey) unless pkey.null?
      end

      # Check if this signature is good.
      #
      # @return [Boolean] true if the signature is valid and not expired
      def good?
        @status == LibRnp::RNP_SUCCESS
      end

      # Check if this signature is valid.
      #
      # @note A valid signature may also be expired.
      #
      # @return [Boolean] true if the signature is valid
      def valid?
        @status == LibRnp::RNP_SUCCESS ||
          @status == LibRnp::RNP_ERROR_SIGNATURE_EXPIRED
      end

      # Check if this signature is expired.
      #
      # @return [Boolean] true if the signature is expired
      def expired?
        @status == LibRnp::RNP_ERROR_SIGNATURE_EXPIRED
      end
    end

    private

    def signature_count
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_op_verify_get_signature_count, @ptr, pcount)
      pcount.read(:size_t)
    end
  end # class
end # class

