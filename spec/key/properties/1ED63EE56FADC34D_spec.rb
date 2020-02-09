# frozen_string_literal: true

# (c) 2018,2019 Ribose Inc.

require 'json'

require 'spec_helper'

describe Rnp::Key do
  context '1ED63EE56FADC34D' do
    before do
      @rnp = Rnp.new
      @rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    end
    let(:key) { @rnp.find_key(keyid: '1ED63EE56FADC34D') }

    it "has the correct type",
       skip: !LibRnp::HAVE_RNP_KEY_GET_ALG do
      expect(key.type).to eql "RSA"
    end

    it "can not be used to sign",
       skip: !LibRnp::HAVE_RNP_KEY_ALLOWS_USAGE do
      expect(key.can?(:sign)).to be false
    end

    it "can be used to encrypt",
       skip: !LibRnp::HAVE_RNP_KEY_ALLOWS_USAGE do
      expect(key.can?(:encrypt)).to be true
    end

    it 'has the correct creation time',
       skip: !LibRnp::HAVE_RNP_KEY_GET_CREATION do
      expect(key.creation_time).to eql Time.at(1500569820)
    end

    it 'has the correct primary grip',
       skip: !LibRnp::HAVE_RNP_KEY_GET_PRIMARY_GRIP do
      expect(key.primary_grip).to eql '66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA'
    end

    it 'has the correct fingerprint' do
      expect(key.fingerprint).to eql 'E332B27CAF4742A11BAA677F1ED63EE56FADC34D'
    end

    it 'has the correct keyid' do
      expect(key.keyid).to eql '1ED63EE56FADC34D'
    end

    it 'has the correct grip' do
      expect(key.grip).to eql 'D9839D61EDAF0B3974E0A4A341D6E95F3479B9B7'
    end

    it "has the correct bit length", skip: !LibRnp::HAVE_RNP_KEY_GET_BITS do
      expect(key.bits).to be 1024
    end

    it 'raises an error when requesting primary userid' do
      expect { key.primary_userid }.to raise_error(Rnp::Error)
    end

    describe Rnp::Key.instance_method(:each_userid) do
      it 'returns an empty enumerator' do
        enumerator = key.each_userid
        expect(enumerator.class).to be Enumerator
        uids = enumerator.to_a
        expect(uids.size).to be 0
      end

      it 'produces no userids' do
        uids = []
        key.each_userid { |userid| uids << userid }
        expect(uids.size).to be 0
      end
    end

    it 'has no userids' do
      expect(key.userids.size).to be 0
    end

    it 'is a primary key' do
      expect(key.primary?).to be false
    end

    it 'is not a subkey' do
      expect(key.sub?).to be true
    end

    describe Rnp::Key.instance_method(:public_key_present?) do
      it { expect(key.public_key_present?).to be true }
    end

    describe Rnp::Key.instance_method(:secret_key_present?) do
      it { expect(key.secret_key_present?).to be false }
    end

    describe Rnp::Key.instance_method(:public_key_data) do
      let(:data) { key.public_key_data }

      it { expect(data.class).to be String }
      it { expect(data.encoding).to be Encoding::BINARY }
      it { expect(Rnp.key_format(data)).to eql 'GPG' }
    end

    describe Rnp::Key.instance_method(:secret_key_data) do
      it { expect{ key.secret_key_data }.to raise_error(Rnp::NoSuitableKeyError) }
    end

    context 'when the secret key has been loaded' do
      before do
        @rnp.load_keys(format: 'GPG',
                       input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
      end

      describe Rnp::Key.instance_method(:secret_key_present?) do
        it { expect(key.secret_key_present?).to be true }
      end

      describe Rnp::Key.instance_method(:secret_key_data) do
        let(:data) { key.secret_key_data }

        it { expect(data.class).to be String }
        it { expect(data.encoding).to be Encoding::BINARY }
        it { expect(Rnp.key_format(data)).to eql 'GPG' }
      end
    end

    describe Rnp::Key.instance_method(:json) do
      let(:data) do
        key.json(
          public_mpis: true,
          secret_mpis: false,
          signatures: true,
          signature_mpis: false
        )
      end

      it 'has the correct key type' do
        expect(data['type']).to eql 'RSA'
      end
    end
  end # 7BC6709B15C23A4A
end # Key

