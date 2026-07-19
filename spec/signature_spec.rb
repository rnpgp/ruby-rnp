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

describe Rnp::Signature do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = 'password'
    rnp
  end
  let(:key) { rnp.find_key(userid: 'key0-uid1') }

  context 'key self-signature' do
    let(:sig) { key.uids[0].signatures[0] }

    describe Rnp::Signature.instance_method(:signature_type),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_TYPE do
      it 'returns the signature type' do
        expect(sig.signature_type).to eql 'certification (positive)'
      end
    end

    describe Rnp::Signature.instance_method(:features),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_FEATURES do
      it 'returns the key features' do
        expect(sig.features).to eql LibRnp::RNP_KEY_FEATURE_MDC
      end
    end

    describe Rnp::Signature.instance_method(:key_flags),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_KEY_FLAGS do
      it 'returns the key usage flags' do
        expect(sig.key_flags).to eql(LibRnp::RNP_KEY_USAGE_CERTIFY |
                                     LibRnp::RNP_KEY_USAGE_SIGN)
      end
    end

    describe Rnp::Signature.instance_method(:key_expiration),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_KEY_EXPIRATION do
      it 'returns the key expiration' do
        expect(sig.key_expiration).to be_kind_of(Integer)
      end
    end

    describe Rnp::Signature.instance_method(:primary_uid?),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_PRIMARY_UID do
      it 'returns whether the userid is primary' do
        expect(sig.primary_uid?).to be false
      end
    end

    describe Rnp::Signature.instance_method(:key_server),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_KEY_SERVER do
      it 'returns an empty string when not present' do
        expect(sig.key_server).to eql ''
      end
    end

    describe Rnp::Signature.instance_method(:key_server_prefs),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_KEY_SERVER_PREFS do
      it 'returns the key server preferences' do
        expect(sig.key_server_prefs).to eql LibRnp::RNP_KEY_SERVER_NO_MODIFY
      end
    end

    describe Rnp::Signature.instance_method(:revoker),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_REVOKER do
      it 'returns an empty string when not present' do
        expect(sig.revoker).to eql ''
      end
    end

    describe Rnp::Signature.instance_method(:revocation_reason),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_REVOCATION_REASON do
      it 'returns empty values when not present' do
        expect(sig.revocation_reason).to eql({ code: '', reason: '' })
      end
    end

    describe Rnp::Signature.instance_method(:trust_level),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_TRUST_LEVEL do
      it 'returns the trust level and amount' do
        expect(sig.trust_level).to eql({ level: 0, amount: 0 })
      end
    end

    describe Rnp::Signature.instance_method(:preferred_ciphers),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_PREFERRED_ALG do
      it 'returns the preferred symmetric algorithms' do
        expect(sig.preferred_ciphers)
          .to eql %w[AES256 AES192 AES128 CAST5 TRIPLEDES IDEA]
      end
    end

    describe Rnp::Signature.instance_method(:preferred_hashes),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_PREFERRED_HASH do
      it 'returns the preferred hash algorithms' do
        expect(sig.preferred_hashes)
          .to eql %w[SHA256 SHA1 SHA384 SHA512 SHA224]
      end
    end

    describe Rnp::Signature.instance_method(:preferred_compressions),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_PREFERRED_ZALG do
      it 'returns the preferred compression algorithms' do
        expect(sig.preferred_compressions).to eql %w[ZLIB BZip2 ZIP]
      end
    end

    describe Rnp::Signature.instance_method(:valid?),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_IS_VALID do
      it 'returns true for a valid signature' do
        expect(sig.valid?).to be true
      end

      it 'revalidates the signature',
         skip: !Rnp.has?('signature-validity-status') do
        expect(sig.valid?(revalidate: true)).to be true
      end
    end

    describe Rnp::Signature.instance_method(:expiration_time),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_GET_EXPIRATION do
      it 'returns the signature expiration time' do
        expect(sig.expiration_time).to be_kind_of(Integer)
      end
    end

    describe 'subpackets', skip: !LibRnp::HAVE_RNP_SIGNATURE_SUBPACKET_COUNT do
      it 'enumerates the subpackets' do
        subpackets = sig.subpackets
        expect(subpackets.size).to be 8
        subpackets.each do |subpkt|
          expect(subpkt.type).to be_kind_of(Integer)
          expect(subpkt.data).to be_kind_of(String)
          expect([true, false]).to include subpkt.hashed?
          expect([true, false]).to include subpkt.critical?
        end
      end

      it 'finds a subpacket by type' do
        # signature creation time subpacket
        subpkt = sig.subpacket(2)
        expect(subpkt.type).to be 2
        expect(subpkt.hashed?).to be true
        expect(subpkt.data.unpack1('N')).to eql sig.creation_time.to_i
      end

      it 'returns nil when no subpacket matches' do
        expect(sig.subpacket(250)).to be_nil
      end

      it 'enumerates subpackets with each_subpacket' do
        expect(sig.each_subpacket.to_a.size).to be 8
      end
    end

    describe Rnp::Signature.instance_method(:export),
             skip: !LibRnp::HAVE_RNP_SIGNATURE_EXPORT do
      it 'exports an armored signature' do
        exported = sig.export
        expect(exported.start_with?("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"))
          .to be true
        expect(exported.end_with?("-----END PGP PUBLIC KEY BLOCK-----\r\n"))
          .to be true
      end

      it 'exports a binary signature' do
        exported = sig.export(armored: false)
        expect(exported.encoding).to eql Encoding::BINARY
        # a signature packet (old format, tag 2)
        expect(exported.getbyte(0) & 0x3F).to eql 2
      end
    end
  end

  context 'data signature' do
    let(:sig) do
      signature = rnp.detached_sign(input: Rnp::Input.from_string('data'),
                                    signers: [key],
                                    hash: 'SHA256',
                                    armored: false)
      verify = rnp.start_detached_verify(data: Rnp::Input.from_string('data'),
                                         signature: Rnp::Input.from_string(signature))
      verify.execute
      verify.signatures[0].handle
    end

    it 'has the expected type and signer' do
      expect(sig.signature_type).to eql 'binary'
      expect(sig.type).to eql 'RSA'
      expect(sig.hash).to eql 'SHA256'
      expect(sig.keyid).to eql key.keyid
      expect(sig.fingerprint).to eql key.fingerprint
    end

    it 'is valid',
       skip: !Rnp.has?('signature-validity-status') do
      expect(sig.valid?).to be true
    end

    it 'enumerates the subpackets',
       skip: !LibRnp::HAVE_RNP_SIGNATURE_SUBPACKET_COUNT do
      expect(sig.subpackets.size).to be > 0
      # issuer fingerprint subpacket
      expect(sig.subpacket(33)).to_not be_nil
    end
  end
end
