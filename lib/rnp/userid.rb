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
    def initialize(ptr, userid, key = nil)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      @userid = userid
      # the uid handle references the owning key internally, so the key
      # must be retained while this handle is alive
      @key = key
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

    # Get the userid's data. Its representation depends on {#type}: for
    # LibRnp::RNP_USER_ID it is the userid string, for
    # LibRnp::RNP_USER_ATTR it is the binary attribute data (e.g. a
    # photo).
    #
    # @return [String] the raw userid data (binary encoding)
    def data
      pptr = FFI::MemoryPointer.new(:pointer)
      psize = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_uid_get_data, @ptr, pptr, psize)
      begin
        pdata = pptr.read_pointer
        pdata.read_bytes(psize.read(:size_t)) unless pdata.null?
      ensure
        LibRnp.rnp_buffer_destroy(pdata)
      end
    end

    # Get the userid's type.
    #
    # @return [Integer] LibRnp::RNP_USER_ID for a regular userid (name
    #   and email) or LibRnp::RNP_USER_ATTR for a binary attribute
    #   (e.g. a photo)
    def type
      ptype = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_uid_get_type, @ptr, ptype)
      ptype.read(:uint32)
    end

    # Check whether the userid is marked as primary.
    #
    # @return [Boolean]
    def primary?
      bool_property(:rnp_uid_is_primary)
    end

    # Check whether the userid is valid. A userid is considered valid if
    # the key itself is valid and the userid has at least one valid,
    # non-expired self-certification.
    #
    # @return [Boolean]
    def valid?
      bool_property(:rnp_uid_is_valid)
    end

    # Check if this userid is revoked.
    #
    # @return [Boolean]
    def revoked?
      bool_property(:rnp_uid_is_revoked)
    end

    # Get the userid's revocation signature, if any.
    #
    # @return [Signature, nil] nil if the userid is not revoked
    def revocation_signature
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_uid_get_revocation_signature, @ptr, pptr)
      psig = pptr.read_pointer
      Signature.new(psig) unless psig.null?
    end

    # Enumerate each {Signature} for this userid.
    #
    # @return [self, Enumerator]
    def each_signature(&block)
      block or return enum_for(:signature_iterator)
      signature_iterator(&block)
      self
    end

    # Get a list of all {Signature}s for this userid.
    #
    # @return [Array<Signature>]
    def signatures
      each_signature.to_a
    end

    # Remove the userid with all of its signatures from the key.
    #
    # @note This handle must still be destroyed afterwards (which happens
    #   automatically), but it, as well as any other handles pointing to
    #   the same userid, must not be used anymore.
    #
    # @return [void]
    def remove
      raise Rnp::Error, 'no owning key available' if @key.nil?
      Rnp.call_ffi(:rnp_uid_remove, @key.ptr, @ptr)
    end

    private

    def bool_property(func)
      presult = FFI::MemoryPointer.new(:bool)
      Rnp.call_ffi(func, @ptr, presult)
      presult.read(:bool)
    end

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
