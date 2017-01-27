require_relative 'libopenssl'
require_relative 'libc'

module LibNetPGP

  def self.bn2hex(bn)
    str, ptr = LibOpenSSL::BN_bn2hex(bn)
    LibC::free(ptr)
    str
  end

end

