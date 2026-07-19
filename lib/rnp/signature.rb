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

    # The signature type ('binary', 'text', 'certification (generic)',
    # 'subkey binding', etc).
    #
    # @return [String]
    def signature_type
      string_property(:rnp_signature_get_type)
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

    # The signer's key fingerprint.
    #
    # @return [String, nil] nil if not available in the signature
    def fingerprint
      string_property(:rnp_signature_get_key_fprint)
    end

    # The time this signature was created at.
    #
    # @return [Time]
    def creation_time
      pcreation = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_signature_get_creation, @ptr, pcreation)
      Time.at(pcreation.read(:uint32))
    end

    # The expiration time of the signature, as the number of seconds after
    # the creation time (0 if the signature never expires).
    #
    # @return [Integer]
    def expiration_time
      pexpiration = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_signature_get_expiration, @ptr, pexpiration)
      pexpiration.read(:uint32)
    end

    # The key features stored in the signature, as OR-ed
    # LibRnp::RNP_KEY_FEATURE_* constants (0 if not available).
    #
    # @return [Integer]
    def features
      uint32_property(:rnp_signature_get_features)
    end

    # The key usage flags stored in the signature, as OR-ed
    # LibRnp::RNP_KEY_USAGE_* constants (0 if not available).
    #
    # @return [Integer]
    def key_flags
      uint32_property(:rnp_signature_get_key_flags)
    end

    # The key expiration time stored in the signature, as the number of
    # seconds since the key creation time (0 if the key never expires).
    #
    # @return [Integer]
    def key_expiration
      uint32_property(:rnp_signature_get_key_expiration)
    end

    # Whether the signature indicates that the corresponding userid should
    # be considered as the primary one.
    #
    # @return [Boolean]
    def primary_uid?
      pprimary = FFI::MemoryPointer.new(:bool)
      Rnp.call_ffi(:rnp_signature_get_primary_uid, @ptr, pprimary)
      pprimary.read(:bool)
    end

    # The key server URL stored in the signature.
    #
    # @return [String] empty if not present in the signature
    def key_server
      string_property(:rnp_signature_get_key_server)
    end

    # The key server preferences flags stored in the signature
    # (LibRnp::RNP_KEY_SERVER_* constants).
    #
    # @return [Integer]
    def key_server_prefs
      uint32_property(:rnp_signature_get_key_server_prefs)
    end

    # The fingerprint of the designated revocation key, if available.
    #
    # @return [String] empty if not present in the signature
    def revoker
      string_property(:rnp_signature_get_revoker)
    end

    # The revocation reason data stored in the signature.
    #
    # @return [Hash<Symbol, String>] a hash with :code and :reason keys.
    #   Values are empty strings when not available in the signature.
    def revocation_reason
      pcode = FFI::MemoryPointer.new(:pointer)
      preason = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_signature_get_revocation_reason, @ptr, pcode, preason)
      begin
        pvalue = pcode.read_pointer
        code = pvalue.read_string unless pvalue.null?
        pvalue = preason.read_pointer
        reason = pvalue.read_string unless pvalue.null?
        { code: code, reason: reason }
      ensure
        LibRnp.rnp_buffer_destroy(pcode.read_pointer)
        LibRnp.rnp_buffer_destroy(preason.read_pointer)
      end
    end

    # The trust level and amount stored in the signature.
    #
    # @return [Hash<Symbol, Integer>] a hash with :level and :amount keys
    #   (0 when not available in the signature).
    def trust_level
      plevel = FFI::MemoryPointer.new(:uint8)
      pamount = FFI::MemoryPointer.new(:uint8)
      Rnp.call_ffi(:rnp_signature_get_trust_level, @ptr, plevel, pamount)
      { level: plevel.read(:uint8), amount: pamount.read(:uint8) }
    end

    # The preferred symmetric algorithms listed in the signature
    # (self-signatures only).
    #
    # @return [Array<String>]
    def preferred_ciphers
      preferred_algs(:rnp_signature_get_preferred_alg_count,
                     :rnp_signature_get_preferred_alg)
    end

    # The preferred hash algorithms listed in the signature
    # (self-signatures only).
    #
    # @return [Array<String>]
    def preferred_hashes
      preferred_algs(:rnp_signature_get_preferred_hash_count,
                     :rnp_signature_get_preferred_hash)
    end

    # The preferred compression algorithms listed in the signature
    # (self-signatures only).
    #
    # @return [Array<String>]
    def preferred_compressions
      preferred_algs(:rnp_signature_get_preferred_zalg_count,
                     :rnp_signature_get_preferred_zalg)
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

    # Check the signature validity, revalidating it if it was not
    # validated before.
    #
    # @param revalidate [Boolean] force revalidation even if the signature
    #   was already validated (key signatures only)
    # @return [Boolean] true if the signature is valid
    def valid?(revalidate: false)
      flags = revalidate ? LibRnp::RNP_SIGNATURE_REVALIDATE : 0
      LibRnp.rnp_signature_is_valid(@ptr, flags) == LibRnp::RNP_SUCCESS
    end

    # Export the signature.
    #
    # @param output [Output] the output to write the signature to.
    #   If nil, the result will be returned directly as a String.
    # @param armored [Boolean] whether to ASCII-armor the output
    # @return [nil, String]
    def export(armored: true, output: nil)
      Output.default(output) do |output_|
        flags = armored ? LibRnp::RNP_KEY_EXPORT_ARMORED : 0
        Rnp.call_ffi(:rnp_signature_export, @ptr, output_.ptr, flags)
      end
    end

    # Enumerate each {Subpacket} of this signature.
    #
    # @return [self, Enumerator]
    def each_subpacket(&block)
      block or return enum_for(:subpacket_iterator)
      subpacket_iterator(&block)
      self
    end

    # Get a list of all {Subpacket}s of this signature.
    #
    # @return [Array<Subpacket>]
    def subpackets
      each_subpacket.to_a
    end

    # Find the subpacket of the given type.
    #
    # @param type [Integer] the subpacket type, per the OpenPGP
    #   specification
    # @param hashed [Boolean] if true then only the hashed area is
    #   searched, otherwise both the hashed and unhashed areas
    # @param skip [Integer] number of matching subpackets to skip,
    #   allowing to iterate over subpackets of the same type
    # @return [Subpacket, nil] nil if no matching subpacket was found
    def subpacket(type, hashed: false, skip: 0)
      pptr = FFI::MemoryPointer.new(:pointer)
      rc = LibRnp.rnp_signature_subpacket_find(@ptr, type, hashed, skip, pptr)
      return nil if rc == LibRnp::RNP_ERROR_NOT_FOUND
      Rnp.raise_error('rnp_signature_subpacket_find failed', rc) unless rc.zero?
      psubpkt = pptr.read_pointer
      Subpacket.new(psubpkt) unless psubpkt.null?
    end

    # Class representing a signature subpacket.
    #
    # This is a value object: the data is copied out of the signature and
    # the underlying handle is released on creation.
    class Subpacket
      # The subpacket type, per the OpenPGP specification.
      # @return [Integer]
      attr_reader :type
      # The raw subpacket data.
      # @return [String]
      attr_reader :data

      # @api private
      def initialize(ptr)
        raise Rnp::Error, 'NULL pointer' if ptr.null?
        ptype = FFI::MemoryPointer.new(:uint8)
        phashed = FFI::MemoryPointer.new(:bool)
        pcritical = FFI::MemoryPointer.new(:bool)
        Rnp.call_ffi(:rnp_signature_subpacket_info, ptr, ptype, phashed,
                     pcritical)
        @type = ptype.read(:uint8)
        @hashed = phashed.read(:bool)
        @critical = pcritical.read(:bool)
        pdata = FFI::MemoryPointer.new(:pointer)
        psize = FFI::MemoryPointer.new(:size_t)
        Rnp.call_ffi(:rnp_signature_subpacket_data, ptr, pdata, psize)
        begin
          pvalue = pdata.read_pointer
          @data = pvalue.read_bytes(psize.read(:size_t)) unless pvalue.null?
        ensure
          LibRnp.rnp_buffer_destroy(pvalue)
        end
      ensure
        LibRnp.rnp_signature_subpacket_destroy(ptr) if ptr && !ptr.null?
      end

      # Whether the subpacket is stored in the hashed area.
      #
      # @return [Boolean]
      def hashed?
        @hashed
      end

      # Whether the subpacket has the critical bit set.
      #
      # @return [Boolean]
      def critical?
        @critical
      end
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

    # Verification errors recorded for this signature.
    #
    # @note Requires librnp 0.18.0 or newer.
    #
    # @return [Array<Integer>] a list of error codes (rnp_result_t values)
    #   describing why the signature failed verification. An empty array
    #   means no errors were recorded.
    def errors
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_signature_error_count, @ptr, pcount)
      perror = FFI::MemoryPointer.new(:uint32)
      (0...pcount.read(:size_t)).map do |idx|
        Rnp.call_ffi(:rnp_signature_error_at, @ptr, idx, perror)
        perror.read(:uint32)
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

    def uint32_property(func)
      pvalue = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(func, @ptr, pvalue)
      pvalue.read(:uint32)
    end

    def preferred_algs(count_func, at_func)
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(count_func, @ptr, pcount)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...pcount.read(:size_t)).map do |idx|
        Rnp.call_ffi(at_func, @ptr, idx, pptr)
        begin
          palg = pptr.read_pointer
          palg.read_string unless palg.null?
        ensure
          LibRnp.rnp_buffer_destroy(palg)
        end
      end
    end

    def subpacket_iterator
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_signature_subpacket_count, @ptr, pcount)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...pcount.read(:size_t)).each do |idx|
        Rnp.call_ffi(:rnp_signature_subpacket_at, @ptr, idx, pptr)
        psubpkt = pptr.read_pointer
        yield Subpacket.new(psubpkt) unless psubpkt.null?
      end
    end
  end
end
