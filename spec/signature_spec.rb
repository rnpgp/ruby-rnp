# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'spec_helper'

describe Rnp::Signature.instance_method(:errors),
         skip: !LibRnp::HAVE_RNP_SIGNATURE_ERROR_COUNT do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = 'password'
    rnp
  end

  let(:data) { 'data to sign' }
  let(:signature) do
    rnp.detached_sign(input: Rnp::Input.from_string(data),
                      signers: [rnp.find_key(userid: 'key0-uid1')],
                      hash: 'SHA256',
                      armored: false)
  end

  def verify_errors(data, signature)
    verify = rnp.start_detached_verify(data: Rnp::Input.from_string(data),
                                       signature: Rnp::Input.from_string(signature))
    begin
      verify.execute
    rescue Rnp::InvalidSignatureError
      # errors are still available via the signature handle
    end
    verify.signatures[0].handle.errors
  end

  context 'valid signature' do
    it 'has no errors' do
      expect(verify_errors(data, signature)).to eql []
    end

    it 'provides a handle with extended information' do
      verify = rnp.start_detached_verify(data: Rnp::Input.from_string(data),
                                         signature: Rnp::Input.from_string(signature))
      verify.execute
      handle = verify.signatures[0].handle
      expect(handle).to be_a Rnp::Signature
      expect(handle.type).to eql 'RSA'
      expect(handle.errors).to eql []
    end
  end

  context 'corrupted signature' do
    let(:corrupted) do
      raw = signature.dup
      raw[-10] = (raw[-10].ord ^ 0xFF).chr
      raw
    end

    it 'has errors' do
      expect(verify_errors(data, corrupted))
        .to eql [LibRnp::RNP_ERROR_SIGNATURE_INVALID]
    end
  end

  context 'key signature' do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(
        format: 'GPG',
        input: Rnp::Input.from_path('spec/data/keys/ecc-p384-pub.asc')
      )
      rnp
    end

    it 'has no errors' do
      key = rnp.find_key(keyid: '242A3AA5EA85F44A')
      expect(key.uids[0].signatures[0].errors).to eql []
    end
  end
end
