# frozen_string_literal: true

# (c) 2020 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'
require 'rnp/signature'

class Rnp
  # Class that represents a UserID
  class UserID
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr, userid)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      @userid = userid
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_uid_handle_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    def to_s
      @userid
    end

    # Enumerate each {Signature} for this key.
    #
    # @return [self, Enumerator]
    def each_signature(&block)
      block or return enum_for(:signature_iterator)
      signature_iterator(&block)
      self
    end

    # Get a list of all {Signature}s for this key.
    #
    # @return [Array<Signature>]
    def signatures
      each_signature.to_a
    end

    # Check if this key is revoked.
    #
    # @return [Boolean]
    def revoked?
      presult = FFI::MemoryPointer.new(:bool)
      Rnp.call_ffi(:rnp_uid_is_revoked, @ptr, presult)
      presult.read(:bool)
    end

    private

    def signature_iterator
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_uid_get_signature_count, @ptr, pcount)
      count = pcount.read(:size_t)
      (0...count).each do |i|
        pptr = FFI::MemoryPointer.new(:pointer)
        Rnp.call_ffi(:rnp_uid_get_signature_at, @ptr, i, pptr)
        psig = pptr.read_pointer
        yield Signature.new(psig) unless psig.null?
      end
    end
  end
end
