# frozen_string_literal: true

# (c) 2020 Ribose Inc.

require "json"

require "spec_helper"

describe Rnp::Key.instance_method(:signatures),
         skip: !LibRnp::HAVE_RNP_KEY_GET_SIGNATURE_AT do
  context 'ecc-p256-revoked-sub' do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(
        format: "GPG",
        input: Rnp::Input.from_path("spec/data/keys/ecc-p256-revoked-sub.asc"),
      )
      rnp
    end

    context 'ecc-p256' do
      let(:key) { rnp.find_key(userid: "ecc-p256") }

      it 'is not revoked' do
        expect(key.revoked?).to be false
      end
    end

    context '37E285E9E9851491' do
      let(:key) { rnp.find_key(keyid: "37E285E9E9851491") }

      it 'is revoked' do
        expect(key.revoked?).to be true
      end

      it 'has the correct revocation reason' do
        expect(key.revocation_reason).to eql 'Subkey revocation test.'
      end

      it 'is not superseded' do
        expect(key.superseded?).to be false
      end

      it 'is compromised' do
        expect(key.compromised?).to be true
      end

      it 'is not retired' do
        expect(key.retired?).to be false
      end
    end
  end

  context 'ecc-p256-revoked-key' do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(
        format: "GPG",
        input: Rnp::Input.from_path("spec/data/keys/ecc-p256-revoked-key.asc"),
      )
      rnp
    end
    let(:key) { rnp.find_key(userid: "ecc-p256") }

    it 'is revoked' do
      expect(key.revoked?).to be true
    end

    it 'has the correct revocation reason' do
      expect(key.revocation_reason).to eql 'Superseded key test.'
    end

    it 'is superseded' do
      expect(key.superseded?).to be true
    end

    it 'is not compromised' do
      expect(key.compromised?).to be false
    end

    it 'is not retired' do
      expect(key.retired?).to be false
    end
  end
end
