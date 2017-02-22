require 'netpgp.rb'

describe 'rsa key generation' do
  before(:all) {
    @key = LibNetPGP::pgp_rsa_new_selfsign_key(1024, 65537, 'John Doe', 'SHA1', 'cast5')
    expect(@key.null?).to be false
    expect(
      LibNetPGP::pgp_add_userid(@key, 'Joe Doe')
    ).to_not eql nil
    expect(
      LibNetPGP::pgp_add_selfsigned_userid(@key, 'Jane Doe')
    ).to eql 1
  }
  after(:all) {
    LibNetPGP::pgp_keydata_free(@key)
  }

  it 'has correct userids' do
    expect(LibNetPGP::dynarray_count(@key, 'uid')).to eql 3
    expect(LibNetPGP::dynarray_get_item(@key, 'uid', :string, 0)).to eql 'John Doe'
    expect(LibNetPGP::dynarray_get_item(@key, 'uid', :string, 1)).to eql 'Joe Doe'
    expect(LibNetPGP::dynarray_get_item(@key, 'uid', :string, 2)).to eql 'Jane Doe'
  end

  # pgp_parse callback that just collects pkt[:tag]
  PARSE_CALLBACK_COLLECT_TAGS = Proc.new do |results, pkt, data|
    results.push(pkt[:tag])
    next :PGP_RELEASE_MEMORY
  end

  it 'has valid packets' do
    expect(
      LibNetPGP::dynarray_count(@key, 'packet')
    ).to eql 2
    (0..LibNetPGP::dynarray_count(@key, 'packet') - 1).each {|n|
      stream_mem = LibC::calloc(1, LibNetPGP::PGPStream.size)
      stream = LibNetPGP::PGPStream.new(stream_mem)
      stream[:readinfo][:accumulate] = 1
      LibNetPGP::pgp_parse_options(stream, :PGP_PTAG_SS_ALL, :PGP_PARSE_PARSED)
      packet = LibNetPGP::dynarray_get_item(@key, 'packet', LibNetPGP::PGPSubPacket, n)
      expect(packet).to_not eql nil
      bytes = packet[:raw].get_bytes(0, packet[:length])
      mem = FFI::MemoryPointer.new(:uint8, bytes.size)
      mem.put_bytes(0, bytes)
      LibNetPGP::pgp_reader_set_memory(stream, mem, mem.size)
      results = []
      callback = PARSE_CALLBACK_COLLECT_TAGS.curry[results]
      LibNetPGP::pgp_set_callback(stream, callback, nil)
      expect(
        LibNetPGP::pgp_parse(stream, 1)
      ).to eql 1
      expect(results).to eql([
        :PGP_PARSER_PTAG,
        :PGP_PTAG_CT_SIGNATURE_HEADER,
        :PGP_PTAG_SS_CREATION_TIME,
        :PGP_PTAG_SS_ISSUER_KEY_ID,
        :PGP_PTAG_SS_PRIMARY_USER_ID,
        :PGP_PTAG_CT_SIGNATURE_FOOTER,
        :PGP_PARSER_PACKET_END
      ])
    }
  end

  it 'has expected type' do
     expect(@key[:type]).to eql :PGP_PTAG_CT_SECRET_KEY
  end

  it 'seckey pubkey has expected properties' do
    pubkey = @key[:key][:seckey][:pubkey]
    expect(pubkey[:version]).to eql :PGP_V4
    expect(pubkey[:alg]).to eql :PGP_PKA_RSA
    expect(
      LibNetPGP::bn2hex(pubkey[:key][:rsa][:e]).hex
    ).to eql 65537
  end

  it 'seckey has expected string-to-key info' do
    expect(
      @key[:key][:seckey][:s2k_usage]
    ).to eql :PGP_S2KU_ENCRYPTED_AND_HASHED
    expect(
      @key[:key][:seckey][:s2k_specifier]
    ).to eql :PGP_S2KS_SALTED
  end

  it 'has expected algorithms' do
    expect(@key[:key][:seckey][:alg]).to eql :PGP_SA_CAST5
    expect(@key[:key][:seckey][:hash_alg]).to eql :PGP_HASH_SHA1
  end

  it 'seckey has valid rsa mpi' do
    rsaseckey = @key[:key][:seckey][:key][:rsa]
    # just making sure these don't raise exceptions
    LibNetPGP::bn2hex(rsaseckey[:d])
    LibNetPGP::bn2hex(rsaseckey[:p])
    LibNetPGP::bn2hex(rsaseckey[:q])
    LibNetPGP::bn2hex(rsaseckey[:u])
  end


  it 'sigkey pubkey has expected properties' do
    pubkey = @key[:key][:seckey][:pubkey]
    expect(pubkey[:version]).to eql :PGP_V4
    expect(pubkey[:alg]).to eql :PGP_PKA_RSA
    expect(
      LibNetPGP::bn2hex(pubkey[:key][:rsa][:e]).hex
    ).to eql 65537
  end

end

