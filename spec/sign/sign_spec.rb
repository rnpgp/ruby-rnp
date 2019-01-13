# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'tempfile'

require 'spec_helper'

describe Rnp::Sign do
  it 'raises an error for keys that cannot sign' do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    sign = rnp.start_sign(input: Rnp::Input.from_string('data'),
                          output: Rnp::Output.to_null)
    expect do
      sign.add_signer(rnp.find_key(keyid: '1ED63EE56FADC34D'))
    end.to raise_error(Rnp::NoSuitableKeyError)
  end

  it 'raises an error for keys that have no secret key available' do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    sign = rnp.start_sign(input: Rnp::Input.from_string('data'),
                          output: Rnp::Output.to_null)
    expect do
      sign.add_signer(rnp.find_key(userid: 'key0-uid0'))
    end.to raise_error(Rnp::NoSuitableKeyError)
  end
end # sign

describe Rnp::Verify do
  it do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    output = Rnp::Output.to_string
    sign = rnp.start_sign(input: Rnp::Input.from_string('data'),
                          output: output)
    # these values won't be used, since they're modified later (before execute)
    sign.hash = 'SHA256'
    sign.expiration_time = 120
    sign.add_signer(rnp.find_key(userid: 'key0-uid1'))
    sign.add_signer(
      rnp.find_key(userid: 'key1-uid2'),
      if Rnp.has?('per-signature-opts')
        {
          hash: 'SHA256',
          expiration_time: 120
        }
      else
        {}
      end
    )
    # these values will be used for sigs that do not explicitly set these
    sign.hash = 'SHA512'
    sign.expiration_time = 60
    rnp.password_provider = 'password'
    sign.execute
    signature = output.string

    verify = rnp.start_verify(input: Rnp::Input.from_string(signature),
                              output: Rnp::Output.to_null)
    verify.execute
    expect(verify.good?).to be true

    sigs = verify.signatures
    expect(sigs.length).to be 2

    expect(sigs[0].hash).to eql 'SHA512'
    expect(sigs[0].key.keyid).to eql '7BC6709B15C23A4A'
    expect(Time.now - sigs[0].creation_time).to be <= 5
    expect(sigs[0].expiration_time).to eql 60
    expect(sigs[0].good?).to be true
    expect(sigs[0].valid?).to be true
    expect(sigs[0].expired?).to be false

    if Rnp.has?('per-signature-opts')
      expect(sigs[1].hash).to eql 'SHA256'
      expect(sigs[1].expiration_time).to eql 120
    else
      expect(sigs[1].hash).to eql 'SHA512'
      expect(sigs[1].expiration_time).to eql 60
    end
    expect(sigs[1].key.keyid).to eql '2FCADF05FFA501BB'
    expect(Time.now - sigs[0].creation_time).to be <= 5
    expect(sigs[1].good?).to be true
    expect(sigs[1].valid?).to be true
    expect(sigs[1].expired?).to be false
  end
end

