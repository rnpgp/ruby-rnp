module NetPGP

require 'forwardable'

require_relative 'publickey'
require_relative 'utils'

# Secret key
#
class SecretKey
  extend Forwardable
  delegate [:creation_time, :expiration_time, :expiration_time=,
            :fingerprint, :fingerprint_hex, :key_id, :key_id_hex] => :@public_key

  attr_accessor :public_key,
                :string_to_key_usage,
                :string_to_key_specifier,
                :symmetric_key_algorithm,
                :hash_algorithm,
                :mpi,
                :userids,
                :parent,
                :subkeys,
                :raw_subpackets,
                :encrypted,
                :passphrase

  def initialize
    @public_key = nil
    @string_to_key_usage = nil
    @string_to_key_specifier = nil
    @symmetric_key_algorithm = nil
    @hash_algorithm = nil
    @mpi = {}
    @userids = []
    @parent = nil
    @subkeys = []
    @raw_subpackets = []
    @encrypted = false
    @passphrase = ''
  end

  # Checks if a key is encrypted. An encrypted key requires a
  # passphrase for signing/decrypting/etc and will have nil values
  # for key material/mpis.
  #
  # @return [Boolean]
  def encrypted?
    @encrypted
  end

  # Decrypts data using this secret key.
  #
  # Note: {#passphrase} must be set to the correct passphrase prior
  # to this call. If no passphrase is required, it should be set to
  # '' (not nil).
  #
  # @param data [String] the encrypted data to be decrypted.
  # @param armored [Boolean] whether the encrypted data is ASCII armored.
  def decrypt(data, armored=true)
    begin
      rd, wr = IO.pipe
      wr.write(@passphrase + "\n")
      native_keyring_ptr = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
      native_keyring = LibNetPGP::PGPKeyring.new(native_keyring_ptr)
      NetPGP::keys_to_native_keyring([self], native_keyring)
      pgpio = create_pgpio
      data_ptr = FFI::MemoryPointer.new(:uint8, data.bytesize)
      data_ptr.write_bytes(data)
      passfp = LibC::fdopen(rd.to_i, 'r')
      mem_ptr = LibNetPGP::pgp_decrypt_buf(pgpio, data_ptr, data_ptr.size,
                                           native_keyring, nil,
                                           armored ? 1 : 0, 0, passfp, 1, nil)
      return nil if mem_ptr.null?
      mem = LibNetPGP::PGPMemory.new(mem_ptr)
      mem[:buf].read_bytes(mem[:length])
    ensure
      rd.close
      wr.close
    end
  end

  # Signs data using this secret key.
  #
  # Note: {#passphrase} must be set to the correct passphrase prior
  # to this call. If no passphrase is required, it should be set to ''.
  #
  # @param data [String] the data to be signed.
  # @param armored [Boolean] whether the output should be ASCII armored.
  # @param options [Hash] less-often used options that override defaults.
  #   * :from [Time] (defaults to Time.now) - signature creation time
  #   * :duration [Numeric] (defaults to 0) - signature duration/expiration
  #   * :hash_algorithm [NetPGP::HashAlgorithm] (defaults to SHA1) -
  #     hash algorithm to use
  #   * :cleartext [Boolean] (defaults to false) - whether this should be
  #     a cleartext/clearsign signature, which includes the original
  #     data in cleartext in the same document.
  # @return [String] the signed data, or nil on error.
  def sign(data, armored=true, options={})
    valid_options = [:from, :duration, :hash_algorithm, :cleartext]
    for option in options.keys
      raise if not valid_options.include?(option)
    end

    armored = armored ? 1 : 0
    from = options[:from] || Time.now
    duration = options[:duration] || 0
    hashalg = options[:hash_algorithm] || HashAlgorithm::SHA1
    cleartext = options[:cleartext] ? 1 : 0

    from = from.to_i
    hashname = HashAlgorithm::to_s(hashalg)

    pgpio = create_pgpio
    data_buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
    data_buf.write_bytes(data)
    seckey = decrypted_seckey
    return nil if not seckey
    memory = nil
    begin
      memory_ptr = LibNetPGP::pgp_sign_buf(pgpio, data_buf, data_buf.size, seckey, from, duration, hashname, armored, cleartext)
      return nil if not memory_ptr or memory_ptr.null?
      memory = LibNetPGP::PGPMemory.new(memory_ptr)
      signed_data = memory[:buf].read_bytes(memory[:length])
      signed_data
    ensure
      LibNetPGP::pgp_memory_free(memory) if memory
    end
  end

  # Cleartext signs data using this secret key.
  # This is a shortcut for {#sign}.
  #
  # Note: {#passphrase} must be set to the correct passphrase prior
  # to this call. If no passphrase is required, it should be set to ''.
  #
  # @param data [String] the data to be signed.
  # @param armored [Boolean] whether the output should be ASCII armored.
  # @param options [Hash] less-often used options that override defaults.
  #   * :from [Time] (defaults to Time.now) - signature creation time
  #   * :duration [Integer] (defaults to 0) - signature duration/expiration
  #   * :hash_algorithm [{NetPGP::HashAlgorithm}] (defaults to SHA1) -
  #     hash algorithm to use
  # @return [String] the signed data, or nil on error.
  def clearsign(data, armored=true, options={})
    options[:cleartext] = true
    sign(data, armored, options)
  end

  # Creates a detached signature of a file.
  #
  # Note: {#passphrase} must be set to the correct passphrase prior
  # to this call. If no passphrase is required, it should be set to ''.
  #
  # @param infile [String] the path to the input file for which a
  #   signature will be created.
  # @param sigfile [String] the path to the signature file that will
  #   be created.
  #
  #   This can be nil, in which case the filename will be the infile
  #   parameter with '.asc' appended.
  #
  # @param armored [Boolean] whether the output should be ASCII armored.
  # @param options [Hash] less-often used options that override defaults.
  #   * :from [Time] (defaults to Time.now) - signature creation time
  #   * :duration [Integer] (defaults to 0) - signature duration/expiration
  #   * :hash_algorithm [{NetPGP::HashAlgorithm}] (defaults to SHA1) -
  #     hash algorithm to use
  # @return [Boolean] whether the signing was successful.
  def detached_sign(infile, sigfile=nil, armored=true, options={})
    valid_options = [:from, :duration, :hash_algorithm]
    for option in options.keys
      raise if not valid_options.include?(option)
    end

    armored = armored ? 1 : 0
    from = options[:from] || Time.now
    duration = options[:duration] || 0
    hashalg = options[:hash_algorithm] || HashAlgorithm::SHA1

    hashname = HashAlgorithm::to_s(hashalg)
    from = from.to_i

    pgpio = create_pgpio
    # Note: pgp_sign_detached calls pgp_seckey_free for us
    seckey = decrypted_seckey
    return false if not seckey
    ret = LibNetPGP::pgp_sign_detached(pgpio, infile, sigfile, seckey, hashname, from, duration, armored, 1)
    return ret == 1
  end

  def add_subkey(subkey)
    raise if subkey.subkeys.any?
    subkey.parent = self
    @subkeys.push(subkey)
  end

  def self.generate(options={})
    valid_options = [:key_length, :public_key_algorithm, :algorithm_params,
                     :hash_algorithm, :symmetric_key_algorithm]
    for option in options.keys
      raise if not valid_options.include?(option)
    end

    key_length = options[:key_length] || 4096
    pkalg = options[:public_key_algorithm] || PublicKeyAlgorithm::RSA
    pkalg_params = options[:algorithm_params] || {e: 65537}
    hashalg = options[:hash_algorithm] || HashAlgorithm::SHA1
    skalg = options[:symmetric_key_algorithm] || SymmetricKeyAlgorithm::CAST5
    hashalg_s = HashAlgorithm::to_s(hashalg)
    skalg_s = SymmetricKeyAlgorithm::to_s(skalg)

    native_key = nil
    begin
      native_key = LibNetPGP::pgp_rsa_new_key(key_length, pkalg_params[:e], hashalg_s, skalg_s)
      SecretKey::from_native(native_key[:key][:seckey])
    ensure
      LibNetPGP::pgp_keydata_free(native_key) if native_key
    end
  end

  def self.from_native(sk, encrypted=false)
    seckey = SecretKey.new
    seckey.public_key = PublicKey::from_native(sk[:pubkey])
    seckey.string_to_key_usage = LibNetPGP::enum_value(sk[:s2k_usage])
    seckey.string_to_key_specifier = LibNetPGP::enum_value(sk[:s2k_specifier])
    seckey.symmetric_key_algorithm = LibNetPGP::enum_value(sk[:alg])
    seckey.hash_algorithm = LibNetPGP::enum_value(sk[:hash_alg]) || HashAlgorithm::SHA1
    seckey.mpi = NetPGP::mpis_from_native(sk[:pubkey][:alg], sk)
    seckey.encrypted = encrypted
    seckey
  end

  def to_native(native)
    @public_key.to_native(native[:pubkey])
    native[:s2k_usage] = @string_to_key_usage
    native[:s2k_specifier] = @string_to_key_specifier
    native[:alg] = @symmetric_key_algorithm
    native[:hash_alg] = @hash_algorithm
    NetPGP::mpis_to_native(PublicKeyAlgorithm::to_native(@public_key.public_key_algorithm), @mpi, native)
  end

  def to_native_key(native_key)
    raise if not native_key[:packets].null?
    native_key[:type] = :PGP_PTAG_CT_SECRET_KEY
    native_key[:sigid] = @public_key.key_id
    to_native(native_key[:key][:seckey])
    @userids.each {|userid|
      LibNetPGP::dynarray_append_item(native_key, 'uid', :string, userid)
    }
    @raw_subpackets.each {|bytes|
      packet = LibNetPGP::PGPSubPacket.new
      length = bytes.bytesize
      packet[:length] = length
      packet[:raw] = LibC::calloc(1, length)
      packet[:raw].write_bytes(bytes)
      LibNetPGP::dynarray_append_item(native_key, 'packet', LibNetPGP::PGPSubPacket, packet)
    }
  end

  private
  def decrypted_seckey
    native_mem = LibC::calloc(1, LibNetPGP::PGPKey.size)
    native = LibNetPGP::PGPKey.new(native_mem)
    to_native_key(native)
    rd, wr = IO.pipe
    wr.write(@passphrase + "\n")
    wr.close
    passfp = LibC::fdopen(rd.to_i, 'r')
    decrypted = LibNetPGP::pgp_decrypt_seckey(native, passfp)
    rd.close
    LibC::fclose(passfp)
    return nil if not decrypted or decrypted.null?
    LibNetPGP::PGPSecKey.new(decrypted)
  end

  def create_pgpio
    pgpio = LibNetPGP::PGPIO.new
    pgpio[:outs] = LibC::fdopen($stdout.to_i, 'w')
    pgpio[:errs] = LibC::fdopen($stderr.to_i, 'w')
    pgpio[:res] = pgpio[:errs]
    pgpio
  end

end

end # module NetPGP

