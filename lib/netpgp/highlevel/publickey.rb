module NetPGP

require_relative 'utils'

class PublicKey
  attr_accessor :version,
                :creation_time,
                :expiration_time,
                :public_key_algorithm,
                :mpi,
                :userids,
                :parent,
                :subkeys

  def initialize
    @version = nil
    @creation_time = nil
    @expiration_time = 0
    @public_key_algorithm = nil
    @mpi = {}
    @userids = []
    @parent = nil
    @subkeys = []
  end

  def fingerprint
    fp = LibNetPGP::PGPFingerprint.new
    native_pubkey_ptr = LibC::calloc(1, LibNetPGP::PGPPubKey.size)
    native_pubkey = LibNetPGP::PGPPubKey.new(native_pubkey_ptr)
    native_pubkey_auto = FFI::AutoPointer.new(native_pubkey_ptr, LibNetPGP::PGPPubKey.method(:release))
    to_native(native_pubkey)
    hash = @version == 3 ? :PGP_HASH_MD5 : :PGP_HASH_SHA1
    ret = LibNetPGP::pgp_fingerprint(fp, native_pubkey, hash)
    raise 'pgp_fingerprint failed' if ret != 1
    fp[:fingerprint].to_s[0, fp[:length]]
  end

  def fingerprint_hex
    fingerprint.bytes.collect {|byte| '%02X' % byte}.join
  end

  def key_id
    keyid_ptr = FFI::MemoryPointer.new(:uint8, LibNetPGP::PGP_KEY_ID_SIZE)
    native_pubkey = LibNetPGP::PGPPubKey.new
    to_native(native_pubkey)
    ret = LibNetPGP::pgp_keyid(keyid_ptr, LibNetPGP::PGP_KEY_ID_SIZE, native_pubkey, :PGP_HASH_SHA1)
    raise 'pgp_keyid failed' if ret != 1
    keyid_ptr.read_bytes(LibNetPGP::PGP_KEY_ID_SIZE)
  end

  def key_id_hex
    key_id.bytes.collect {|byte| '%02X' % byte}.join
  end

  def key_length
    case @public_key_algorithm
    when PublicKeyAlgorithm::RSA,
         PublicKeyAlgorithm::RSA_ENCRYPT_ONLY,
         PublicKeyAlgorithm::RSA_SIGN_ONLY
      return NetPGP::bignum_byte_count(@mpi[:n]) * 8
    when PublicKeyAlgorithm::DSA
      case NetPGP::bignum_byte_count(@mpi[:q])
      when 20
        1024
      when 28
        2048
      when 32
        3072
      end
    when PublicKeyAlgorithm::ELGAMAL
      NetPGP::bignum_byte_count(@mpi[:y]) * 8
    end
    0
  end

  def encrypt(data, armored=true, sk_algorithm=SymmetricKeyAlgorithm::CAST5)
    cipher = SymmetricKeyAlgorithm::to_s(sk_algorithm)
    memory = nil

    begin
      pubkey_ptr = LibC::calloc(1, LibNetPGP::PGPKey.size)
      pubkey = LibNetPGP::PGPKey.new(pubkey_ptr)
      pubkey_auto = FFI::AutoPointer.new(pubkey_ptr, LibNetPGP::PGPKey.method(:release))

      to_native_key(pubkey)
      data_buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
      data_buf.write_bytes(data)
      pgpio = LibNetPGP::PGPIO.new
      pgpio[:outs] = LibC::fdopen($stdout.to_i, 'w')
      pgpio[:errs] = LibC::fdopen($stderr.to_i, 'w')
      pgpio[:res] = pgpio[:errs]
      memory_ptr = LibNetPGP::pgp_encrypt_buf(pgpio, data_buf, data_buf.size, pubkey, armored ? 1 : 0, cipher)
      return nil if memory_ptr.null?
      memory = LibNetPGP::PGPMemory.new(memory_ptr)
      memory[:buf].read_bytes(memory[:length])
    ensure
      LibNetPGP::pgp_memory_free(memory) if memory
    end
  end

  def verify(data, armored=true)
    NetPGP::verify([self], data, armored)
  end

  def add_subkey(subkey)
    subkey.parent = self
    @subkeys.push(subkey)
  end

  def self.from_native(native)
    pubkey = PublicKey.new
    pubkey.version = LibNetPGP::enum_value(native[:version])
    pubkey.creation_time = Time.at(native[:birthtime])
    if pubkey.version == 3
      pubkey.expiration_time = Time.at(native[:birthtime]) + (native[:days_valid] * 86400)
    end
    pubkey.public_key_algorithm = PublicKeyAlgorithm::from_native(native[:alg])
    pubkey.mpi = NetPGP::mpis_from_native(native[:alg], native)
    pubkey
  end

  def to_native(native)
    native[:version] = @version
    native[:birthtime] = @creation_time.to_i
    if @version == 3 and @expiration_time 
      native[:days_valid] = ((@expiration_time.to_i - @creation_time.to_i) / 86400).to_i
    else
      native[:duration] = (@expiration_time.to_i - @creation_time.to_i).to_i
    end
    native[:alg] = @public_key_algorithm
    NetPGP::mpis_to_native(native[:alg], @mpi, native)
  end

  def to_native_key(native_key)
    native_key[:type] = :PGP_PTAG_CT_PUBLIC_KEY
    native_key[:sigid] = key_id
    to_native(native_key[:key][:pubkey])
    @userids.each {|userid|
      LibNetPGP::dynarray_append_item(native_key, 'uid', :string, userid)
    }
  end

end

end # module NetPGP

