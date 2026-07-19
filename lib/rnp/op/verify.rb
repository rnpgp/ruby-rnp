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
    def initialize(ptr, input = nil, output = nil)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      # retain the input and output so they are not garbage collected
      # before the operation is executed
      @input = input
      @output = output
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

    # Set flags which control the data verification/decryption process.
    #
    # @note All flags are set at once: flags not present in a subsequent
    #   call will be unset.
    #
    # @param flags [Integer] OR-ed combination of the LibRnp::RNP_VERIFY_*
    #   constants
    # @return [void]
    def flags=(flags)
      Rnp.call_ffi(:rnp_op_verify_set_flags, @ptr, flags)
    end

    # Get the format of the literal data stored in the message, if available.
    #
    # @return [String, nil] the single-character format ('b' for binary,
    #   't' for text, 'u' for UTF-8 text, 'l' for local) or nil if this
    #   information is not available.
    def format
      pformat = FFI::MemoryPointer.new(:uint8)
      Rnp.call_ffi(:rnp_op_verify_get_format, @ptr, pformat)
      format = pformat.read(:uint8)
      format.zero? ? nil : format.chr
    end

    # Get information about the data protection (encryption) used in the
    # processed message.
    #
    # @return [Hash<Symbol>] a hash with the following keys:
    #   * :mode [String] the encryption mode: 'none' (not encrypted),
    #     'cfb', 'cfb-mdc', 'aead-ocb' or 'aead-eax'
    #   * :cipher [String] the symmetric cipher used, or nil if the
    #     message was not encrypted
    #   * :valid [Boolean] true if the message integrity protection
    #     (MDC or AEAD) was used and validated successfully
    def protection_info
      pmode = FFI::MemoryPointer.new(:pointer)
      pcipher = FFI::MemoryPointer.new(:pointer)
      pvalid = FFI::MemoryPointer.new(:bool)
      Rnp.call_ffi(:rnp_op_verify_get_protection_info, @ptr, pmode, pcipher,
                   pvalid)
      begin
        pvalue = pmode.read_pointer
        mode = pvalue.read_string unless pvalue.null?
        pvalue = pcipher.read_pointer
        cipher = pvalue.read_string unless pvalue.null?
        { mode: mode, cipher: cipher, valid: pvalid.read(:bool) }
      ensure
        LibRnp.rnp_buffer_destroy(pmode.read_pointer)
        LibRnp.rnp_buffer_destroy(pcipher.read_pointer)
      end
    end

    # Get the file name and modification time embedded in the message's
    # literal data packet. Makes sense only for embedded signature
    # verification.
    #
    # @return [Hash<Symbol>] a hash with the following keys:
    #   * :file_name [String, nil] the embedded file name, if any
    #   * :file_mtime [Time] the embedded modification time (the unix
    #     epoch if not available)
    def file_info
      pfilename = FFI::MemoryPointer.new(:pointer)
      pmtime = FFI::MemoryPointer.new(:uint32)
      Rnp.call_ffi(:rnp_op_verify_get_file_info, @ptr, pfilename, pmtime)
      begin
        pvalue = pfilename.read_pointer
        file_name = pvalue.read_string unless pvalue.null?
        { file_name: file_name, file_mtime: Time.at(pmtime.read(:uint32)) }
      ensure
        LibRnp.rnp_buffer_destroy(pfilename.read_pointer)
      end
    end

    # Get a list of recipients (public keys) the message was encrypted to.
    #
    # @return [Array<Recipient>]
    def recipients
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_op_verify_get_recipient_count, @ptr, pcount)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...pcount.read(:size_t)).map do |idx|
        Rnp.call_ffi(:rnp_op_verify_get_recipient_at, @ptr, idx, pptr)
        Recipient.new(pptr.read_pointer)
      end
    end

    # Get the recipient whose key was used to decrypt the message.
    #
    # @return [Recipient, nil] nil if the message was not decrypted with
    #   a public key (or not decrypted at all).
    def used_recipient
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_op_verify_get_used_recipient, @ptr, pptr)
      precipient = pptr.read_pointer
      Recipient.new(precipient) unless precipient.null?
    end

    # Get a list of password-based (symenc) entries the message was
    # encrypted to.
    #
    # @return [Array<Symenc>]
    def symencs
      pcount = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_op_verify_get_symenc_count, @ptr, pcount)
      pptr = FFI::MemoryPointer.new(:pointer)
      (0...pcount.read(:size_t)).map do |idx|
        Rnp.call_ffi(:rnp_op_verify_get_symenc_at, @ptr, idx, pptr)
        Symenc.new(pptr.read_pointer)
      end
    end

    # Get the password-based (symenc) entry that was used to decrypt the
    # message.
    #
    # @return [Symenc, nil] nil if the message was not decrypted with
    #   a password (or not decrypted at all).
    def used_symenc
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_op_verify_get_used_symenc, @ptr, pptr)
      psymenc = pptr.read_pointer
      Symenc.new(psymenc) unless psymenc.null?
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
        @ptr = ptr

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

      # Get the full signature handle, providing access to extended
      # information (verification errors, JSON dump, etc).
      #
      # @see Rnp::Signature
      # @return [Rnp::Signature]
      def handle
        pptr = FFI::MemoryPointer.new(:pointer)
        Rnp.call_ffi(:rnp_op_verify_signature_get_handle, @ptr, pptr)
        Rnp::Signature.new(pptr.read_pointer)
      end
    end

    # Class representing a public-key recipient of an encrypted message.
    #
    # This is a value object: the information is copied out of the
    # verification operation when the object is created.
    class Recipient
      # The keyid of the key the message was encrypted to. This may be all
      # zeroes for a hidden recipient.
      # @return [String]
      attr_reader :keyid
      # The public key algorithm used to encrypt to this recipient.
      # @return [String]
      attr_reader :alg

      # @api private
      def initialize(ptr)
        raise Rnp::Error, 'NULL pointer' if ptr.null?
        @keyid = Recipient.string_property(:rnp_recipient_get_keyid, ptr)
        @alg = Recipient.string_property(:rnp_recipient_get_alg, ptr)
      end

      # @api private
      def self.string_property(func, ptr)
        pptr = FFI::MemoryPointer.new(:pointer)
        Rnp.call_ffi(func, ptr, pptr)
        begin
          pvalue = pptr.read_pointer
          pvalue.read_string unless pvalue.null?
        ensure
          LibRnp.rnp_buffer_destroy(pvalue)
        end
      end
    end

    # Class representing a password-based (symenc) entry of an encrypted
    # message.
    #
    # This is a value object: the information is copied out of the
    # verification operation when the object is created.
    class Symenc
      # The cipher used to encrypt the data encryption key (or the whole
      # message).
      # @return [String]
      attr_reader :cipher
      # The AEAD algorithm used, or 'None'.
      # @return [String]
      attr_reader :aead_alg
      # The hash algorithm used to derive the key from the password.
      # @return [String]
      attr_reader :hash_alg
      # The string-to-key type ('Simple', 'Salted' or
      # 'Iterated and salted').
      # @return [String]
      attr_reader :s2k_type
      # The number of iterations for an iterated-and-salted s2k
      # (0 otherwise).
      # @return [Integer]
      attr_reader :s2k_iterations

      # @api private
      def initialize(ptr)
        raise Rnp::Error, 'NULL pointer' if ptr.null?
        @cipher = Recipient.string_property(:rnp_symenc_get_cipher, ptr)
        @aead_alg = Recipient.string_property(:rnp_symenc_get_aead_alg, ptr)
        @hash_alg = Recipient.string_property(:rnp_symenc_get_hash_alg, ptr)
        @s2k_type = Recipient.string_property(:rnp_symenc_get_s2k_type, ptr)
        piterations = FFI::MemoryPointer.new(:uint32)
        Rnp.call_ffi(:rnp_symenc_get_s2k_iterations, ptr, piterations)
        @s2k_iterations = piterations.read(:uint32)
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

