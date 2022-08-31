# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'spec_helper'

describe Rnp.instance_method(:sign) do
  before do
    @rnp = Rnp.new
    @rnp.load_keys(format: 'GPG',
                   input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    @signer1 = @rnp.find_key(userid: 'key0-uid0')
    @signer2 = @rnp.find_key(userid: 'key1-uid0')
  end

  it 'raises an error for keys that cannot sign' do
    @rnp.password_provider = 'password'
    signer1 = @rnp.find_key(keyid: '1ED63EE56FADC34D')
    signer2 = @rnp.find_key(userid: 'key1-uid0')
    expect do
      @rnp.sign(
        signers: [signer1, signer2],
        input: Rnp::Input.from_string('data'),
        output: Rnp::Output.to_null
      )
    end.to raise_error(Rnp::NoSuitableKeyError)
  end

  it 'fails without a password provider' do
    @rnp.password_provider = nil
    expect do
      @rnp.sign(signers: [@signer1, @signer2],
                input: Rnp::Input.from_string('data'),
                output: Rnp::Output.to_null)
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'fails with an incorrect password' do
    @rnp.password_provider = proc { next 'badpass' }
    expect do
      @rnp.sign(signers: [@signer1, @signer2],
                input: Rnp::Input.from_string('data'),
                output: Rnp::Output.to_null)
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'returns the signature directly if provided no output' do
    @rnp.password_provider = 'password'
    data = @rnp.sign(signers: [@signer1], input: Rnp::Input.from_string('data'))
    expect(data.class).to be String
    expect(data.size).to_not be 0

    @rnp.verify(input: Rnp::Input.from_string(data))
  end

  it 'uses the output specified, when provided' do
    @rnp.password_provider = 'password'
    outs = StringIO.new
    output = Rnp::Output.to_io(outs)
    expect(
      @rnp.sign(signers: [@signer1], input: Rnp::Input.from_string('data'), output: output)
    ).to eql nil
    sig = outs.string
    expect(sig.size).to_not be 0
    # verify
    output = Rnp::Output.to_string
    @rnp.verify(input: Rnp::Input.from_string(sig), output: output)
    expect(output.string).to eql 'data'
  end

  describe Rnp.instance_method(:verify) do
    before do
      outs = StringIO.new
      @rnp.password_provider = 'password'
      @rnp.sign(signers: [@signer1, @signer2],
                input: Rnp::Input.from_string('data'),
                output: Rnp::Output.to_io(outs),
                armored: false,
                compression: { algorithm: 'bzip2', level: 4 },
                hash: 'SHA256',
                creation_time: 0,
                expiration_time: 1_000)
      @sig = outs.string.force_encoding(Encoding::BINARY)
    end

    it 'verifies a valid signature' do
      @rnp.verify(input: Rnp::Input.from_string(@sig))
    end

    it 'raises an error on a corrupted signature' do
      badsig = @sig.dup
      badsig[badsig.size / 2] = (badsig[badsig.size / 2].ord ^ 0xff).chr
      # depending on what part we corrupt, this could raise different errors
      expect do
        @rnp.verify(input: Rnp::Input.from_string(badsig))
      end.to raise_error(Rnp::Error)
    end

    it 'raises an error on invalid data' do
      expect do
        @rnp.verify(input: Rnp::Input.from_string('abc'))
      end.to raise_error(Rnp::BadFormatError)
    end
  end # verification
end # sign

describe Rnp.instance_method(:cleartext_sign) do
  before do
    @rnp = Rnp.new
    @rnp.load_keys(format: 'GPG',
                   input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    @signer1 = @rnp.find_key(userid: 'key0-uid0')
    @signer2 = @rnp.find_key(userid: 'key1-uid0')
  end

  it 'fails without a password provider' do
    @rnp.password_provider = nil
    expect do
      @rnp.cleartext_sign(
        signers: [@signer1, @signer2],
        input: Rnp::Input.from_string('data'),
        output: Rnp::Output.to_null
      )
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'fails with an incorrect password' do
    @rnp.password_provider = proc { next 'badpass' }
    expect do
      @rnp.cleartext_sign(
        signers: [@signer1, @signer2],
        input: Rnp::Input.from_string('data'),
        output: Rnp::Output.to_null
      )
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'returns the signature directly if provided no output' do
    @rnp.password_provider = 'password'
    data = @rnp.cleartext_sign(signers: [@signer1], input: Rnp::Input.from_string('data'))
    expect(data.class).to be String
    expect(data.size).to_not be 0

    @rnp.verify(input: Rnp::Input.from_string(data))
  end

  it 'uses the output specified, when provided' do
    @rnp.password_provider = 'password'
    outs = StringIO.new
    output = Rnp::Output.to_io(outs)
    expect(
      @rnp.cleartext_sign(signers: [@signer1], input: Rnp::Input.from_string("data"), output: output)
    ).to eql nil
    sig = outs.string
    expect(sig.size).to_not be 0
    # verify
    output = Rnp::Output.to_string
    @rnp.verify(input: Rnp::Input.from_string(sig), output: output)
    expect(output.string).to eql "data\r\n"
  end

  it 'appears to generate a cleartext signature' do
    @rnp.password_provider = 'password'
    sig = @rnp.cleartext_sign(signers: [@signer1], input: Rnp::Input.from_string("data"))
    expect(sig.include?('-----BEGIN PGP SIGNATURE-----')).to be true
    expect(sig.include?('-----END PGP SIGNATURE-----')).to be true
  end

  describe Rnp.instance_method(:verify) do
    before do
      outs = StringIO.new
      @rnp.password_provider = 'password'
      @rnp.cleartext_sign(
        signers: [@signer1, @signer2],
        input: Rnp::Input.from_string('data'),
        output: Rnp::Output.to_io(outs),
        compression: { algorithm: 'bzip2', level: 4 },
        hash: 'SHA256',
        creation_time: 0,
        expiration_time: 1_000
      )
      @sig = outs.string.force_encoding(Encoding::UTF_8)
    end

    it 'verifies a valid signature' do
      @rnp.verify(input: Rnp::Input.from_string(@sig))
    end

    it 'raises an error on a corrupted signature' do
      badsig = @sig.dup
      badsig[badsig.size / 2] = (badsig[badsig.size / 2].ord ^ 0xff).chr
      # depending on what part we corrupt, this could raise different errors
      expect do
        @rnp.verify(input: Rnp::Input.from_string(badsig))
      end.to raise_error(Rnp::Error)
    end

    it 'raises an error on invalid data' do
      expect do
        @rnp.verify(input: Rnp::Input.from_string('abc'))
      end.to raise_error(Rnp::BadFormatError)
    end
  end # verification
end # cleartext_sign

describe Rnp.instance_method(:detached_sign) do
  before do
    @rnp = Rnp.new
    @rnp.load_keys(format: 'GPG',
                   input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    @signer1 = @rnp.find_key(userid: 'key0-uid0')
    @signer2 = @rnp.find_key(userid: 'key1-uid0')
  end

  it 'fails without a password provider' do
    @rnp.password_provider = nil
    expect do
      @rnp.detached_sign(
        signers: [@signer1, @signer2],
        input: Rnp::Input.from_string('data'),
        output: Rnp::Output.to_null
      )
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'fails with an incorrect password' do
    @rnp.password_provider = proc { next 'badpass' }
    expect do
      @rnp.detached_sign(
        signers: [@signer1, @signer2],
        input: Rnp::Input.from_string('data'),
        output: Rnp::Output.to_null
      )
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'returns the signature directly if provided no output' do
    @rnp.password_provider = 'password'
    signature = @rnp.detached_sign(signers: [@signer1], input: Rnp::Input.from_string('data'))
    expect(signature.class).to be String
    expect(signature.size).to_not be 0

    @rnp.detached_verify(data: Rnp::Input.from_string('data'), signature: Rnp::Input.from_string(signature))
  end

  it 'uses the output specified, when provided' do
    @rnp.password_provider = 'password'
    outs = StringIO.new
    expect(
      @rnp.detached_sign(signers: [@signer1], input: Rnp::Input.from_string('data'), output: Rnp::Output.to_io(outs))
    ).to eql nil
    signature = outs.string
    expect(signature.size).to_not be 0
    # verify
    @rnp.detached_verify(data: Rnp::Input.from_string('data'), signature: Rnp::Input.from_string(signature))
  end

  describe Rnp.instance_method(:detached_verify) do
    before do
      @rnp.password_provider = 'password'
      @data = 'data'
      @signature = @rnp.detached_sign(
        signers: [@signer1, @signer2],
        input: Rnp::Input.from_string(@data),
        compression: { algorithm: 'bzip2', level: 9 },
        hash: 'SHA256',
        creation_time: 0,
        expiration_time: 1_000
      )
    end

    it 'verifies a valid signature' do
      @rnp.detached_verify(data: Rnp::Input.from_string(@data), signature: Rnp::Input.from_string(@signature))
    end

    it 'raises an error on truncated data' do
      data = @data.byteslice(0, @data.bytesize - 1)
      expect do
        @rnp.detached_verify(data: Rnp::Input.from_string(data), signature: Rnp::Input.from_string(@signature))
      end.to raise_error(Rnp::InvalidSignatureError)
    end

    it 'raises an error on modified data' do
      data = @data.dup
      data[data.size / 2] = (data[data.size / 2].ord ^ 0xff).chr
      expect do
        @rnp.detached_verify(data: Rnp::Input.from_string(data), signature: Rnp::Input.from_string(@signature))
      end.to raise_error(Rnp::InvalidSignatureError)
    end

    it 'raises an error on a corrupt signature' do
      badsig = @signature.dup
      badsig[badsig.size / 2] = (badsig[badsig.size / 2].ord ^ 0xff).chr
      if Rnp.has?("require-single-valid-signature")
        @rnp.detached_verify(data: Rnp::Input.from_string(@data), signature: Rnp::Input.from_string(badsig))
        badsig[badsig.size - 2] = (badsig[badsig.size - 2].ord ^ 0xff).chr
        expect do
          @rnp.detached_verify(data: Rnp::Input.from_string(@data), signature: Rnp::Input.from_string(badsig))
        end.to raise_error(Rnp::InvalidSignatureError)
      else
        expect do
          @rnp.detached_verify(data: Rnp::Input.from_string(@data), signature: Rnp::Input.from_string(badsig))
        end.to raise_error(Rnp::InvalidSignatureError)
      end
    end
  end # verification
end # detached_sign

