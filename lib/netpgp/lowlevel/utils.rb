require_relative 'libopenssl'
require_relative 'libc'

module LibNetPGP

  # BIGNUM* to hexadecimal string
  def self.bn2hex(bn)
    str, ptr = LibOpenSSL::BN_bn2hex(bn)
    LibC::free(ptr)
    str
  end

  # Ruby Fixnum to BIGNUM*
  def self.num2bn(num)
    bn_ptr = FFI::MemoryPointer.new(:pointer)
    hex = num.to_s(16)
    ret = LibOpenSSL::BN_hex2bn(bn_ptr, hex)
    raise 'Fixnum to BIGNUM conversion failed' if ret == 0
    bn = bn_ptr.get_pointer(0)
    bn_ptr.free
    bn
  end

end

