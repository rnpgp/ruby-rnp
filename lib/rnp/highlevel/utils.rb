module RNP

def self.bignum_byte_count(bn)
  # Note: This probably assumes that the ruby implementation
  # uses the same BN representation that libnetpgp does.
  # It may be better to convert and use BN_num_bytes (or bits).
  bn.to_s(16).length / 2
end

def self.stream_errors(stream)
  error_ptr = stream[:errors]

  errors = []
  until error_ptr.null?
    error = LibRNP::PGPError.new(error_ptr)

    error_desc = "#{error[:file]}:#{error[:line]}: #{error[:errcode]} #{error[:comment]}"
    errors.push(error_desc)

    error_ptr = error[:next]
  end
  errors
end

def self.mpi_from_native(native)
  mpi = {}
  native.members.each {|member|
    if native[member].null?
      mpi[member] = nil
    else
      mpi[member] = LibRNP::bn2hex(native[member]).hex
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
      raise "Unsupported PK algorithm: #{alg}"
  end
  RNP::mpi_from_native(material)
end

def self.mpi_to_native(mpi, native)
  mpi.each {|name,value|
    if mpi[name] == nil
      native[name] = nil
    else
      native[name] = LibRNP::num2bn(value)
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
  # Ensure we're not leaking memory from a prior call.
  # This just frees all the BNs.
  if native.is_a?(LibRNP::PGPSecKey)
    LibRNP::pgp_seckey_free(native)
  elsif native.is_a?(LibRNP::PGPPubKey)
    LibRNP::pgp_pubkey_free(native)
  else
    raise
  end
  RNP::mpi_to_native(mpi, material)
end


# Add a subkey binding signature (type 0x18) to a key.
# Note that this should be used for encryption subkeys.
#
# @param key [LibRNP::PGPKey]
# @param subkey [LibRNP::PGPKey]
def self.add_subkey_signature(key, subkey)
  sig = nil
  sigoutput = nil
  mem_sig = nil
  begin
    sig = LibRNP::pgp_create_sig_new
    LibRNP::pgp_sig_start_subkey_sig(sig, key[:key][:pubkey], subkey[:key][:pubkey], :PGP_SIG_SUBKEY)
    LibRNP::pgp_add_time(sig, subkey[:key][:pubkey][:birthtime], 'birth')
    # TODO expiration
    LibRNP::pgp_add_issuer_keyid(sig, key[:sigid])
    LibRNP::pgp_end_hashed_subpkts(sig)

    sigoutput_ptr = FFI::MemoryPointer.new(:pointer)
    mem_sig_ptr = FFI::MemoryPointer.new(:pointer)
    LibRNP::pgp_setup_memory_write(sigoutput_ptr, mem_sig_ptr, 128)
    sigoutput = LibRNP::PGPOutput.new(sigoutput_ptr.read_pointer)
    LibRNP::pgp_write_sig(sigoutput, sig, key[:key][:pubkey], key[:key][:seckey])
    mem_sig = LibRNP::PGPMemory.new(mem_sig_ptr.read_pointer)
    sigpkt = LibRNP::PGPSubPacket.new
    sigpkt[:length] = LibRNP::pgp_mem_len(mem_sig)
    sigpkt[:raw] = LibRNP::pgp_mem_data(mem_sig)
    LibRNP::pgp_add_subpacket(subkey, sigpkt)
  ensure
    LibRNP::pgp_create_sig_delete(sig) if sig
    LibRNP::pgp_teardown_memory_write(sigoutput, mem_sig) if mem_sig
  end
end

end # module RNP

