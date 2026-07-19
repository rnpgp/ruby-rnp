# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'spec_helper'

describe Rnp::KeySignature,
         skip: !LibRnp::HAVE_RNP_KEY_CERTIFICATION_CREATE do
  def generate(rnp, userid)
    op = rnp.start_generate(type: 'RSA')
    op.bits = 1024
    op.userid = userid
    op.execute
    op.key
  end

  let(:rnp) do
    rnp = Rnp.new
    rnp.password_provider = 'password'
    rnp
  end

  describe 'certification' do
    let(:signer) { generate(rnp, 'certifier') }
    let(:target) { generate(rnp, 'certified') }

    it 'certifies another key, applying all customizations' do
      # the signature must not be older than either key
      creation = [signer.creation_time.to_i, target.creation_time.to_i].max
      keysig = signer.start_certification(target.uids[0])
      keysig.hash = 'SHA512'
      keysig.creation_time = creation
      keysig.set_trust_level(2, 120)
      keysig.key_server = 'hkps://keys.example.com'
      keysig.key_server_prefs = LibRnp::RNP_KEY_SERVER_NO_MODIFY
      keysig.add_preferred_cipher('AES256')
      keysig.add_preferred_hash('SHA512')
      keysig.add_preferred_compression('ZLIB')
      keysig.sign

      sig = target.uids[0].signatures.find { |s| s.keyid == signer.keyid }
      expect(sig).to_not be_nil
      expect(sig.signature_type).to eql 'certification (generic)'
      expect(sig.hash).to eql 'SHA512'
      expect(sig.creation_time.to_i).to eql creation
      expect(sig.trust_level).to eql({ level: 2, amount: 120 })
      expect(sig.key_server).to eql 'hkps://keys.example.com'
      expect(sig.key_server_prefs).to eql LibRnp::RNP_KEY_SERVER_NO_MODIFY
      expect(sig.preferred_ciphers).to eql %w[AES256]
      expect(sig.preferred_hashes).to eql %w[SHA512]
      expect(sig.preferred_compressions).to eql %w[ZLIB]
      expect(sig.fingerprint).to eql signer.fingerprint
      expect(sig.valid?).to be true
    end

    it 'certifies with an explicit type' do
      keysig = signer.start_certification(target.uids[0], type: 'persona')
      keysig.sign
      sig = target.uids[0].signatures.find { |s| s.keyid == signer.keyid }
      expect(sig.signature_type).to eql 'certification (persona)'
    end

    it 'self-certifies, marking the userid as primary' do
      keysig = target.start_certification(target.uids[0])
      keysig.primary_uid = true
      keysig.sign
      sig = target.uids[0].signatures.find do |s|
        s.keyid == target.keyid && s.primary_uid?
      end
      expect(sig).to_not be_nil
      expect(sig.signature_type).to eql 'certification (positive)'
    end
  end

  describe 'direct-key signature' do
    let(:key) { generate(rnp, 'direct') }

    it 'creates a direct-key self-signature, applying customizations' do
      keysig = key.start_direct_signature
      keysig.features = LibRnp::RNP_KEY_FEATURE_MDC
      keysig.key_flags = LibRnp::RNP_KEY_USAGE_CERTIFY |
                         LibRnp::RNP_KEY_USAGE_SIGN
      keysig.key_expiration = 86_400
      keysig.sign

      sig = key.signatures.find { |s| s.signature_type == 'direct' }
      expect(sig).to_not be_nil
      expect(sig.features).to eql LibRnp::RNP_KEY_FEATURE_MDC
      expect(sig.key_flags).to eql(LibRnp::RNP_KEY_USAGE_CERTIFY |
                                   LibRnp::RNP_KEY_USAGE_SIGN)
      expect(sig.key_expiration).to eql 86_400
      expect(sig.valid?).to be true
    end

    it 'creates a direct-key signature over another key' do
      other = generate(rnp, 'other')
      keysig = key.start_direct_signature(other)
      keysig.sign
      sig = other.signatures.find { |s| s.keyid == key.keyid }
      expect(sig).to_not be_nil
      expect(sig.signature_type).to eql 'direct'
    end
  end

  describe 'revocation signature' do
    let(:key) { generate(rnp, 'revokee') }

    it 'revokes the key with a reason' do
      keysig = key.start_revocation_signature
      keysig.set_revocation_reason('retired', 'no longer used')
      keysig.sign

      expect(key.revoked?).to be true
      expect(key.retired?).to be true
      expect(key.revocation_reason).to eql 'no longer used'

      sig = key.revocation_signature
      expect(sig).to_not be_nil
      expect(sig.signature_type).to eql 'key revocation'
      expect(sig.revocation_reason).to eql({ code: 'retired',
                                             reason: 'no longer used' })
      expect(sig.valid?).to be true
    end
  end

  describe 'signature removal' do
    let(:signer) { generate(rnp, 'remover') }
    let(:target) { generate(rnp, 'removee') }

    before do
      signer.start_certification(target.uids[0]).sign
    end

    # Note: no per-method skip metadata here. The setup above requires
    # the key certification API (librnp 0.18+), which gates the whole
    # file; an inner 'skip: false' (e.g. when the removal API is present
    # but the certification API is not, as in librnp 0.17.x) would
    # override the outer skip and run the example anyway.
    describe Rnp::Key.instance_method(:remove_signature) do
      it 'removes a single signature' do
        sig = target.uids[0].signatures.find { |s| s.keyid == signer.keyid }
        expect(sig).to_not be_nil
        target.remove_signature(sig)
        keyids = target.uids[0].signatures.map(&:keyid)
        expect(keyids).to_not include signer.keyid
      end
    end

    describe Rnp::Key.instance_method(:remove_signatures) do
      it 'removes non-self signatures' do
        expect(target.uids[0].signatures.map(&:keyid))
          .to include signer.keyid
        target.remove_signatures(non_self: true)
        expect(target.uids[0].signatures.map(&:keyid))
          .to_not include signer.keyid
        # the self-signature is kept
        expect(target.uids[0].signatures.map(&:keyid))
          .to include target.keyid
      end
    end
  end
end
