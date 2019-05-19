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
    # @param bits (see #bits=)
    # @param qbits (see #qbits=)
    # @param curve (see #curve=)
    # @param hash (see #hash=)
    # @param s2k_hash (see #s2k_hash=)
    # @param s2k_iterations (see #s2k_iterations=)
    # @param s2k_cipher (see #s2k_cipher=)
    # @param password (see #password=)
    # @param protection_mode (see #protection_mode=)
    # @param lifetime (see #lifetime=)
    # @param userid (see #userid=)
    # @param usage (see #usage=)
    def options=(bits: nil, qbits: nil, curve: nil, hash: nil,
                 s2k_hash: nil, s2k_iterations: nil, s2k_cipher: nil,
                 password: nil, protection_mode: nil, lifetime: nil,
                 userid: nil, usage: nil, preferences: nil)
      self.bits = bits unless bits.nil?
      self.qbits = qbits unless qbits.nil?
      self.curve = curve unless curve.nil?
      self.hash = hash unless hash.nil?
      self.s2k_hash = s2k_hash unless s2k_hash.nil?
      self.s2k_iterations = s2k_iterations unless s2k_iterations.nil?
      self.s2k_cipher = s2k_cipher unless s2k_cipher.nil?
      self.password = password unless password.nil?
      self.protection_mode = protection_mode unless protection_mode.nil?
      self.lifetime = lifetime unless lifetime.nil?
      self.userid = userid unless userid.nil?
      self.usage = usage unless usage.nil?
      self.preferences = preferences unless preferences.nil?
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
    #
    # @param hashes [Array<String>, Array<Symbol>]
    # @param compression [Array<String>, Array<Symbol>]
    # @param ciphers [Array<String>, Array<Symbol>]
    # @param key_server [String]
    def preferences=(hashes: nil, compression: nil, ciphers: nil,
                     key_server: nil)
      Rnp.call_ffi(:rnp_op_generate_clear_pref_hashes, @ptr)
      Rnp.call_ffi(:rnp_op_generate_clear_pref_compression, @ptr)
      Rnp.call_ffi(:rnp_op_generate_clear_pref_ciphers, @ptr)
      hashes&.each do |pref|
        Rnp.call_ffi(:rnp_op_generate_add_pref_hash, @ptr, pref.to_s)
      end
      compression&.each do |pref|
        Rnp.call_ffi(:rnp_op_generate_add_pref_compression, @ptr, pref.to_s)
      end
      ciphers&.each do |pref|
        Rnp.call_ffi(:rnp_op_generate_add_pref_cipher, @ptr, pref.to_s)
      end
      Rnp.call_ffi(:rnp_op_generate_set_pref_keyserver, @ptr, key_server)
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
  end
end
