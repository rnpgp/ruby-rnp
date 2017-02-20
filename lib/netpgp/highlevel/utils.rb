module NetPGP

def self.mpi_from_native(native)
  mpi = {}
  native.members.each {|member|
    if native[member].null?
      mpi[member] = nil
    else
      mpi[member] = LibNetPGP::bn2hex(native[member]).hex
    end
  }
  mpi
end

def self.mpis_from_native(alg, native)
  case alg
    when :PGP_PKA_RSA, :PGP_PKA_RSA_ENCRYPT_ONLY, :PGP_PKA_RSA_SIGN_ONLY
      material = native[:key][:rsa]
    when :PGP_PKA_DSA
      material = native[:key][:dsa]
    when :PGP_PKA_ELGAMAL
      material = native[:key][:elgamal]
    else
      raise 'Unsupported PK algorithm'
  end
  NetPGP::mpi_from_native(material)
end

def self.mpi_to_native(mpi, native)
  mpi.each {|name,value|
    if mpi[name] == nil
      native[name] = nil
    else
      native[name] = LibNetPGP::num2bn(value)
    end
  }
end

def self.mpis_to_native(alg, mpi, native)
  case alg
    when :PGP_PKA_RSA, :PGP_PKA_RSA_ENCRYPT_ONLY, :PGP_PKA_RSA_SIGN_ONLY
      material = native[:key][:rsa]
    when :PGP_PKA_DSA
      material = native[:key][:dsa]
    when :PGP_PKA_ELGAMAL
      material = native[:key][:elgamal]
    else
      raise "Unsupported PK algorithm: #{alg}"
  end
  NetPGP::mpi_to_native(mpi, material)
end

end # module NetPGP

