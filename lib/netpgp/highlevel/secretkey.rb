module NetPGP

require_relative 'publickey'
require_relative 'utils'

class SecretKey
  attr_accessor :public_key,
                :expiration_time,
                :string_to_key_usage,
                :string_to_key_specifier,
                :symmetric_key_algorithm,
                :hash_algorithm,
                :mpi,
                :userids,
                :parent,
                :raw_subpackets,
                :encrypted

  def initialize
    @public_key = nil
    @expiration_time = 0
    @string_to_key_usage = nil
    @string_to_key_specifier = nil
    @symmetric_key_algorithm = nil
    @hash_algorithm = nil
    @mpi = {}
    @userids = []
    @parent = nil
    @raw_subpackets = []
    @encrypted = false
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

  def encrypted?
    @encrypted
  end

  def decrypt(data, passphrase=nil, armored=true)
    begin
      rd, wr = IO.pipe
      wr.write(passphrase + "\n")
      native_keyring_ptr = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
      native_keyring = LibNetPGP::PGPKeyring.new(native_keyring_ptr)
      NetPGP::keyring_to_native([self], native_keyring)
      pgpio = LibNetPGP::PGPIO.new
      pgpio[:outs] = LibC::fdopen($stdout.to_i, 'w')
      pgpio[:errs] = LibC::fdopen($stderr.to_i, 'w')
      pgpio[:res] = pgpio[:errs]
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

end

end # module NetPGP

