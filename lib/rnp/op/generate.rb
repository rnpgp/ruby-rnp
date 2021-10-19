# frozen_string_literal: true

# (c) 2019 Ribose Inc.

require "ffi"

require "rnp/error"
require "rnp/ffi/librnp"
require "rnp/utils"

class Rnp
  # Key generation operation
  class Generate
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr)
      raise Rnp::Error, "NULL pointer" if ptr.null?

      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_op_generate_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    # Set a group of options.
    #
    # @param [Hash] opts set several options in one place
    # @option opts [Integer] :bits (see #bits=)
    # @option opts [Integer] :qbits (see #qbits=)
    # @option opts [Integer] :curve (see #curve=)
    # @option opts [String] :hash (see #hash=)
    # @option opts [String] :s2k_hash (see #s2k_hash=)
    # @option opts [Integer] :s2k_iterations (see #s2k_iterations=)
    # @option opts [String] :s2k_cipher (see #s2k_cipher=)
    # @option opts [String] :password (see #password=)
    # @option opts [String] :protection_mode (see #protection_mode=)
    # @option opts [Integer] :lifetime (see #lifetime=)
    # @option opts [String] :userid (see #userid=)
    # @option opts [String] :usage (see #usage=)
    def options=(opts)
      %i{bits qbits curve hash s2k_hash s2k_iterations
         s2k_cipher password protection_mode lifetime
         userid usage preferences}.each do |prop|
        value = opts[prop]
        send("#{prop}=", value) unless value.nil?
      end
    end

    # Set the bit length of the key.
    #
    # @param len [Integer] the desired bit length
    def bits=(len)
      Rnp.call_ffi(:rnp_op_generate_set_bits, @ptr, len)
    end

    # Set the bit length of the q parameter for a DSA key.
    #
    # @note This is only valid for DSA keys.
    #
    # @param len [Integer] the desired bit length
    def qbits=(len)
      Rnp.call_ffi(:rnp_op_generate_set_dsa_qbits, @ptr, len)
    end

    # Set the desired curve for this ECC key.
    #
    # @note This is only valid for ECC keys which permit specifying a curve.
    #
    # @param curve [String] the curve
    def curve=(curve)
      Rnp.call_ffi(:rnp_op_generate_set_curve, @ptr, curve.to_s)
    end

    # Set the hash algorithm used in the self-signature of the key.
    #
    # @param hash [String] the hash algorithm name
    def hash=(hash)
      Rnp.call_ffi(:rnp_op_generate_set_hash, @ptr, hash.to_s)
    end

    # Set the hash algorithm used to protect the key.
    #
    # @param hash [String] the hash algorithm name
    def s2k_hash=(hash)
      Rnp.call_ffi(:rnp_op_generate_set_protection_hash, @ptr, hash.to_s)
    end

    # Set the s2k iteration count used to protect the key.
    #
    # @param iter [Integer] the hash algorithm name
    def s2k_iterations=(iter)
      Rnp.call_ffi(:rnp_op_generate_set_protection_iterations, @ptr, iter)
    end

    # Set the cipher used to protect the key.
    #
    # @param cipher [String] the cipher algorithm name
    def s2k_cipher=(cipher)
      Rnp.call_ffi(:rnp_op_generate_set_protection_cipher, @ptr, cipher.to_s)
    end

    # Set the password used to protect the key.
    #
    # @param password [String] the password
    def password=(password)
      Rnp.call_ffi(:rnp_op_generate_set_protection_password, @ptr, password)
    end

    # Set the protection mode for this key.
    #
    # @note This is only valid for keys saved in the G10 format.
    #
    # @param mode [String] the protection mode (OCB, CBC, etc)
    def protection_mode=(mode)
      Rnp.call_ffi(:rnp_op_generate_set_protection_mode, @ptr, mode.to_s)
    end

    # Set the number of seconds for this key to remain valid.
    #
    # This determines the expiration time (creation time + lifetime).
    #
    # @param secs [Integer] the number of seconds until this key will be
    #   considered expired. A value of 0 indicates no expiration.
    #   Note that there is an upper limit of 2^32-1.
    def lifetime=(secs)
      Rnp.call_ffi(:rnp_op_generate_set_expiration, @ptr, secs)
    end

    # Set the userid for this key.
    #
    # @param userid [String] the userid
    def userid=(userid)
      Rnp.call_ffi(:rnp_op_generate_set_userid, @ptr, userid)
    end

    # Set the usage for this key.
    #
    # @param usage [Array<Symbol>,Array<String>,Symbol,String] the usage
    #   (:sign, etc)
    def usage=(usage)
      usage = [usage] unless usage.respond_to?(:each)
      Rnp.call_ffi(:rnp_op_generate_clear_usage, @ptr)
      usage.each do |usg|
        Rnp.call_ffi(:rnp_op_generate_add_usage, @ptr, usg.to_s)
      end
    end

    # Set the preferences for the generated key.

    # @param [Hash] prefs set several preferences in one place
    # @option prefs [Array<String>, Array<Symbol>] :hashes
    # @option prefs [Array<String>, Array<Symbol>] :compression
    # @option prefs [Array<String>, Array<Symbol>] :ciphers
    # @option prefs [String] :key_server
    def preferences=(prefs)
      %i{hashes compression ciphers}.each do |param|
        Rnp.call_ffi(pref_ffi_call(param, clear: true), @ptr)
        prefs[param].each do |pref|
          Rnp.call_ffi(pref_ffi_call(param, add: true),
                       @ptr, pref.to_s)
        end
      end
      Rnp.call_ffi(:rnp_op_generate_set_pref_keyserver, @ptr,
                   prefs[:key_server])
    end

    # Execute the operation.
    #
    # This should only be called once.
    #
    # @return [Key] the generated key
    def execute
      Rnp.call_ffi(:rnp_op_generate_execute, @ptr)
      key
    end

    # Retrieve the key.
    #
    # This should only be called after #execute.
    #
    # @return [Key]
    def key
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_op_generate_get_key, @ptr, pptr)
      pkey = pptr.read_pointer
      Key.new(pkey) unless pkey.null?
    end

    # @api private
    private

    def pref_ffi_call(param, add: false, clear: false)
      if add
        fn = { hashes: :hash, ciphers: :cipher }.fetch(param, param)
        "rnp_op_generate_add_pref_#{fn}".to_sym
      elsif clear
        "rnp_op_generate_clear_pref_#{param}".to_sym
      else
        raise ArgumentError, "add or clear must be passed"
      end
    end
  end
end
