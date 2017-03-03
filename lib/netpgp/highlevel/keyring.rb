require 'English'

module NetPGP

PARSE_KEYRING = Proc.new do |state, passphrase_provider, pkt, data|
  next :PGP_RELEASE_MEMORY if state[:errors].any?
  
  begin
    lastkey = state[:keys].last
    case pkt[:tag]
    when :PGP_PTAG_CT_PUBLIC_KEY
      key = PublicKey::from_native(pkt[:u][:pubkey])
      state[:keys].push(key)
    when :PGP_PTAG_CT_PUBLIC_SUBKEY
      key = PublicKey::from_native(pkt[:u][:pubkey])
      lastkey.add_subkey(key)
      state[:keys].push(key)
    when :PGP_PTAG_CT_ENCRYPTED_SECRET_KEY
      key = SecretKey::from_native(pkt[:u][:seckey], true)
      state[:keys].push(key)
    when :PGP_PTAG_CT_ENCRYPTED_SECRET_SUBKEY
      key = SecretKey::from_native(pkt[:u][:seckey], true)
      lastkey.add_subkey(key)
      state[:keys].push(key)
    when :PGP_PTAG_CT_SECRET_KEY
      key = SecretKey::from_native(pkt[:u][:seckey])
      state[:keys].push(key)
    when :PGP_PTAG_CT_SECRET_SUBKEY
      key = SecretKey::from_native(pkt[:u][:seckey])
      lastkey.add_subkey(key)
      state[:keys].push(key)
    when :PGP_GET_PASSPHRASE
      seckey_ptr = pkt[:u][:skey_passphrase][:seckey]
      seckey = LibNetPGP::PGPSecKey.new(seckey_ptr)
      key = SecretKey::from_native(seckey)
      passphrase = passphrase_provider.call(key)
      if passphrase and passphrase != ''
        passphrase_mem = LibC::calloc(1, passphrase.bytesize + 1)
        passphrase_mem.write_bytes(passphrase)
        pkt[:u][:skey_passphrase][:passphrase].write_pointer(passphrase_mem)
        next :PGP_KEEP_MEMORY
      end
    when :PGP_PARSER_PACKET_END
      if lastkey.is_a? NetPGP::SecretKey 
        raw_packet = pkt[:u][:packet]
        bytes = raw_packet[:raw].read_bytes(raw_packet[:length])
        lastkey.raw_subpackets.push(bytes)
      end
    when :PGP_PTAG_CT_USER_ID
      lastkey.userids.push(pkt[:u][:userid].force_encoding('utf-8'))
    when :PGP_PTAG_SS_KEY_EXPIRY
      lastkey.expiration_time = lastkey.creation_time + pkt[:u][:ss_time]
    else
      # For debugging
      #puts "Unhandled tag: #{pkt[:tag]}"
    end # case
  rescue
    state[:errors].push($ERROR_INFO)
  end
  next :PGP_RELEASE_MEMORY
end

DEFAULT_PASSPHRASE_PROVIDER = Proc.new do |seckey|
  nil
end

def self.load_keyring(data, armored=true, &passphrase_provider)
  # Just for readability
  print_errors = 0
  stream_mem = LibC::calloc(1, LibNetPGP::PGPStream.size)
  # This will free the above memory (PGPStream is a ManagedStruct)
  stream = LibNetPGP::PGPStream.new(stream_mem)
  stream[:readinfo][:accumulate] = 1
  LibNetPGP::pgp_parse_options(stream, :PGP_PTAG_SS_ALL, :PGP_PARSE_PARSED)

  # This memory will be GC'd
  mem = FFI::MemoryPointer.new(:uint8, data.bytesize)
  mem.write_bytes(data)

  LibNetPGP::pgp_reader_set_memory(stream, mem, mem.size)
  state = {keys: [], errors: []}
  provider = block_given? ? passphrase_provider : DEFAULT_PASSPHRASE_PROVIDER
  callback = NetPGP::PARSE_KEYRING.curry[state][provider]
  LibNetPGP::pgp_set_callback(stream, callback, nil)
  LibNetPGP::pgp_reader_push_dearmour(stream) if armored
  if LibNetPGP::pgp_parse(stream, print_errors) != 1
    state[:errors].push('pgp_parse failed')
  end
  LibNetPGP::pgp_reader_pop_dearmour(stream) if armored

  errors = stream_errors(stream)
  state[:errors].push(errors) if errors.any?

  raise state[:errors].join("\n") if state[:errors].any?
  state[:keys]
end

def self.keyring_to_native(keyring, native)
  raise if not native[:keys].null?

  for key in keyring
    native_key = LibNetPGP::PGPKey.new
    key.to_native_key(native_key)
    LibNetPGP::dynarray_append_item(native, 'key', LibNetPGP::PGPKey, native_key)
  end
end

end # module NetPGP

