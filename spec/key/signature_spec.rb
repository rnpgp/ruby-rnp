# frozen_string_literal: true

# (c) 2020 Ribose Inc.

require 'json'

require 'spec_helper'

describe Rnp::Key.instance_method(:signatures),
         skip: !LibRnp::HAVE_RNP_KEY_GET_SIGNATURE_AT do
  context 'ecc-p384-pub' do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(
        format: 'GPG',
        input: Rnp::Input.from_path('spec/data/keys/ecc-p384-pub.asc')
      )
      rnp
    end
    let(:key) { rnp.find_key(keyid: '242A3AA5EA85F44A') }

    it 'has the correct signature count' do
      expect(key.signatures.size).to be 0
    end

    describe 'uids' do
      it 'has the correct uid count' do
        expect(key.uids.size).to be 1
      end

      it 'has the correct uid values' do
        expect(key.uids.map(&:to_s)).to eql ['ecc-p384']
      end

      it 'can check revocation status' do
        expect(key.uids.map(&:revoked?).all?(false)).to be true
      end

      describe 'signatures' do
        let(:sig) { key.uids[0].signatures[0] }

        it 'has the correct signature count' do
          expect(key.uids[0].signatures.size).to be 1
        end

        it 'has the correct creation time' do
          expect(sig.creation_time).to eql Time.at(1549119505)
        end

        it 'has the correct type' do
          expect(sig.type).to eql 'ECDSA'
        end

        it 'has the correct hash alg' do
          expect(sig.hash).to eql 'SHA384'
        end

        it 'has the correct keyid' do
          expect(sig.keyid).to eql '242A3AA5EA85F44A'
        end

        it 'has the correct signer' do
          expect(sig.signer.keyid).to eql '242A3AA5EA85F44A'
        end
      end
    end

    describe 'subkeys' do
      let(:subkey) { key.subkeys[0] }
      let(:sig) { subkey.signatures[0] }

      it 'has the correct signature count' do
        expect(subkey.signatures.size).to be 1
      end

      it 'has the correct creation time' do
        expect(sig.creation_time).to eql Time.at(1549119513)
      end

      it 'has the correct type' do
        expect(sig.type).to eql 'ECDSA'
      end

      it 'has the correct hash alg' do
        expect(sig.hash).to eql 'SHA384'
      end

      it 'has the correct keyid' do
        expect(sig.keyid).to eql '242A3AA5EA85F44A'
      end

      it 'has the correct signer' do
        expect(sig.signer.keyid).to eql '242A3AA5EA85F44A'
      end

      it 'generates correct json' do
        json = sig.json[0]
        pp json
        expect(json['header']['tag.str']).to eql 'Signature'
        expect(json['type.str']).to eql 'Subkey Binding Signature'
        expect(json['algorithm.str']).to eql 'ECDSA'
        expect(json['hash algorithm.str']).to eql 'SHA384'
        expect(json['subpackets'][0]['type.str']).to eql 'key flags'
        expect(json['subpackets'][0]['flags.str']).to eql %w[encrypt_comm encrypt_storage]

        expect(json['subpackets'][1]['type.str']).to eql 'issuer fingerprint'
        expect(json['subpackets'][1]['fingerprint']).to eql 'ab25cba042dd924c3acc3ed3242a3aa5ea85f44a'

        expect(json['subpackets'][2]['type.str']).to eql 'signature creation time'
        expect(json['subpackets'][2]['creation time']).to eql 1549119513

        expect(json['subpackets'][3]['type.str']).to eql 'issuer key ID'
        expect(json['subpackets'][3]['issuer keyid']).to eql '242a3aa5ea85f44a'
      end
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

    context 'userid ecc-p256' do
      let(:uid) { key.uids[0] }
      it 'is not revoked' do
        expect(uid.to_s).to eql 'ecc-p256'
        expect(uid.revoked?).to be false
      end
    end

    context 'userid ecc-p256-revoked' do
      let(:uid) { key.uids[1] }
      it 'is revoked' do
        expect(uid.to_s).to eql 'ecc-p256-revoked'
        expect(uid.revoked?).to be true
      end
    end
  end
end
