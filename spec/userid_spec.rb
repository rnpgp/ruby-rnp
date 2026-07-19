# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'spec_helper'

describe Rnp::UserID do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = 'password'
    rnp
  end
  let(:key) { rnp.find_key(userid: 'key0-uid1') }
  let(:uid) { key.uids[0] }

  describe Rnp::UserID.instance_method(:data) do
    it 'returns the userid string for a regular userid' do
      expect(uid.data).to eql 'key0-uid0'
    end
  end

  describe Rnp::UserID.instance_method(:type) do
    it 'returns the userid type' do
      expect(uid.type).to eql LibRnp::RNP_USER_ID
    end
  end

  describe Rnp::UserID.instance_method(:primary?) do
    it 'returns whether the userid is primary' do
      expect(uid.primary?).to be false
    end
  end

  describe Rnp::UserID.instance_method(:valid?) do
    it 'returns true for a valid userid' do
      expect(uid.valid?).to be true
    end
  end

  describe Rnp::UserID.instance_method(:revoked?) do
    it 'returns false for a non-revoked userid' do
      expect(uid.revoked?).to be false
    end
  end

  describe Rnp::UserID.instance_method(:revocation_signature) do
    it 'returns nil for a non-revoked userid' do
      expect(uid.revocation_signature).to be_nil
    end
  end

  context 'ecc-p256-revoked-uid' do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(
        format: 'GPG',
        input: Rnp::Input.from_path('spec/data/keys/ecc-p256-revoked-uid.asc')
      )
      rnp
    end
    let(:key) { rnp.find_key(userid: 'ecc-p256') }

    it 'reports the revoked userid' do
      revoked = key.uids.find { |u| u.to_s == 'ecc-p256-revoked' }
      expect(revoked.revoked?).to be true
      expect(revoked.valid?).to be false
    end

    it 'returns the revocation signature' do
      sig = key.uids.find { |u| u.to_s == 'ecc-p256-revoked' }
               .revocation_signature
      expect(sig).to be_a Rnp::Signature
      expect(sig.signature_type).to eql 'certification revocation'
    end

    it 'keeps the non-revoked userid valid' do
      good = key.uids.find { |u| u.to_s == 'ecc-p256' }
      expect(good.revoked?).to be false
      expect(good.valid?).to be true
    end
  end

  describe 'primary userid' do
    it 'reports the primary flag' do
      op = rnp.start_generate(type: 'RSA')
      op.bits = 1024
      op.userid = 'first-uid'
      op.execute
      generated = op.key
      expect(generated.uids[0].primary?).to be false
      generated.add_userid('second-uid', primary: true)
      expect(generated.uids.find { |u| u.to_s == 'second-uid' }.primary?)
        .to be true
    end
  end

  describe Rnp::UserID.instance_method(:remove) do
    it 'removes the userid from the key' do
      op = rnp.start_generate(type: 'RSA')
      op.bits = 1024
      op.userid = 'first-uid'
      op.execute
      generated = op.key
      generated.add_userid('second-uid')
      expect(generated.uids.map(&:to_s)).to eql %w[first-uid second-uid]
      generated.uids.find { |u| u.to_s == 'second-uid' }.remove
      expect(generated.uids.map(&:to_s)).to eql %w[first-uid]
    end
  end

  describe 'key handle lifetime' do
    it 'keeps the owning key alive while the uid is in use' do
      # the uid handle references the key internally; the key object
      # must not be garbage collected while the uid is alive
      uid = rnp.find_key(userid: 'key0-uid1').uids[0]
      GC.start
      expect(uid.valid?).to be true
    end
  end
end
