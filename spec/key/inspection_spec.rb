# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'spec_helper'

describe 'key inspection' do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp
  end
  let(:key) { rnp.find_key(userid: 'key0-uid1') }

  describe Rnp::Key.instance_method(:version),
           skip: !LibRnp::HAVE_RNP_KEY_GET_VERSION do
    it 'returns the key version' do
      expect(key.version).to eql 4
    end
  end

  describe Rnp::Key.instance_method(:expired?),
           skip: !LibRnp::HAVE_RNP_KEY_IS_EXPIRED do
    it 'returns false for a key without expiration' do
      expect(key.expired?).to be false
    end
  end

  describe Rnp::Key.instance_method(:valid?),
           skip: !LibRnp::HAVE_RNP_KEY_IS_VALID do
    it 'returns true for a valid key' do
      expect(key.valid?).to be true
    end

    it 'returns false for a revoked key' do
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keys/ecc-p256-revoked-key.asc'))
      revoked = rnp.find_key(userid: 'ecc-p256')
      expect(revoked.valid?).to be false
    end
  end

  describe Rnp::Key.instance_method(:valid_till),
           skip: !LibRnp::HAVE_RNP_KEY_VALID_TILL64 do
    it 'returns nil for a key that never expires' do
      expect(key.valid_till).to be_nil
    end

    it 'returns a time for a key that is no longer valid' do
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keys/ecc-p256-revoked-key.asc'))
      revoked = rnp.find_key(userid: 'ecc-p256')
      expect(revoked.valid_till).to be_kind_of(Time)
    end

    it 'returns the expiration time for an expiring key' do
      op = rnp.start_generate(type: 'RSA')
      op.bits = 1024
      op.userid = 'expiring'
      op.lifetime = 3600
      op.execute
      generated = op.key
      expect(generated.valid_till.to_i)
        .to eql(generated.creation_time.to_i + 3600)
    end
  end

  describe Rnp::Key.instance_method(:revokers),
           skip: !LibRnp::HAVE_RNP_KEY_GET_REVOKER_COUNT do
    it 'returns an empty list when there are no designated revokers' do
      expect(key.revokers).to eql []
    end
  end

  describe Rnp::Key.instance_method(:primary_fingerprint),
           skip: !LibRnp::HAVE_RNP_KEY_GET_PRIMARY_FPRINT do
    it 'returns the primary fingerprint for a subkey' do
      subkey = key.subkeys[0]
      expect(subkey.primary_fingerprint).to eql key.fingerprint
    end

    it 'raises an error for a primary key' do
      expect { key.primary_fingerprint }.to raise_error(Rnp::Error)
    end
  end

  describe Rnp::Key.instance_method(:revocation_signature),
           skip: !LibRnp::HAVE_RNP_KEY_GET_REVOCATION_SIGNATURE do
    it 'returns nil for a key that is not revoked' do
      expect(key.revocation_signature).to be_nil
    end

    it 'returns the revocation signature for a revoked key' do
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keys/ecc-p256-revoked-key.asc'))
      revoked = rnp.find_key(userid: 'ecc-p256')
      sig = revoked.revocation_signature
      expect(sig).to be_a Rnp::Signature
      expect(sig.signature_type).to eql 'key revocation'
    end
  end

  describe 'protection info',
           skip: !LibRnp::HAVE_RNP_KEY_GET_PROTECTION_TYPE do
    context 'protected key' do
      it 'returns the protection type and mode' do
        expect(key.protection_type).to eql 'Encrypted-Hashed'
        expect(key.protection_mode).to eql 'CFB'
      end

      it 'returns the cipher, hash and iterations' do
        expect(key.protection_cipher).to eql 'CAST5'
        expect(key.protection_hash).to eql 'SHA1'
        expect(key.protection_iterations).to be > 0
      end
    end

    context 'unprotected key' do
      let(:key) do
        op = rnp.start_generate(type: 'RSA')
        op.bits = 1024
        op.userid = 'unprotected'
        op.execute
        op.key
      end

      it 'returns None for the type and mode' do
        expect(key.protection_type).to eql 'None'
        expect(key.protection_mode).to eql 'None'
      end

      it 'raises an error for the cipher, hash and iterations' do
        expect { key.protection_cipher }.to raise_error(Rnp::Error)
        expect { key.protection_hash }.to raise_error(Rnp::Error)
        expect { key.protection_iterations }.to raise_error(Rnp::Error)
      end
    end
  end
end
