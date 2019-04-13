# frozen_string_literal: true

# (c) 2018,2019 Ribose Inc.

require 'json'

require 'spec_helper'

describe Rnp::Key do
  context '7BC6709B15C23A4A' do
    before do
      @rnp = Rnp.new
      @rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    end
    let(:key) { @rnp.find_key(keyid: '7BC6709B15C23A4A') }

    it "has the correct type",
       skip: !LibRnp::HAVE_RNP_KEY_GET_ALG do
      expect(key.type). to eql "RSA"
    end

    it 'has the correct fingerprint' do
      expect(key.fingerprint).to eql 'E95A3CBF583AA80A2CCC53AA7BC6709B15C23A4A'
    end

    it 'has the correct keyid' do
      expect(key.keyid).to eql '7BC6709B15C23A4A'
    end

    it 'has the correct grip' do
      expect(key.grip).to eql '66D6A0800A3FACDE0C0EB60B16B3669ED380FDFA'
    end

    it 'has the correct primary userid' do
      expect(key.primary_userid).to eql 'key0-uid0'
    end

    describe Rnp::Key.instance_method(:each_subkey),
             skip: !LibRnp::HAVE_RNP_KEY_GET_SUBKEY_AT do
      it "correctly iterates" do
        enumerator = key.each_subkey
        expect(enumerator.class).to be Enumerator
        keys = enumerator.to_a
        expect(keys.size).to be 3
        expect(
          (keys.select { |k| k.keyid == "1ED63EE56FADC34D" }).size,
        ).to be 1
        expect(
          (keys.select { |k| k.keyid == "1D7E8A5393C997A8" }).size,
        ).to be 1
        expect(
          (keys.select { |k| k.keyid == "8A05B89FAD5ADED1" }).size,
        ).to be 1
      end

      it "correctly iterates w/block" do
        keys = []
        key.each_subkey { |k| keys << k }
        expect(keys.size).to be 3
        expect(
          (keys.select { |k| k.keyid == "1ED63EE56FADC34D" }).size,
        ).to be 1
        expect(
          (keys.select { |k| k.keyid == "1D7E8A5393C997A8" }).size,
        ).to be 1
        expect(
          (keys.select { |k| k.keyid == "8A05B89FAD5ADED1" }).size,
        ).to be 1
      end
    end

    describe Rnp::Key.instance_method(:subkeys),
             skip: !LibRnp::HAVE_RNP_KEY_GET_SUBKEY_AT do
      it "has the correct subkeys" do
        keys = key.subkeys
        expect(
          (keys.select { |k| k.keyid == "1ED63EE56FADC34D" }).size,
        ).to be 1
        expect(
          (keys.select { |k| k.keyid == "1D7E8A5393C997A8" }).size,
        ).to be 1
        expect(
          (keys.select { |k| k.keyid == "8A05B89FAD5ADED1" }).size,
        ).to be 1
      end
    end

    describe Rnp::Key.instance_method(:each_userid) do
      it 'correctly iterates userids' do
        enumerator = key.each_userid
        expect(enumerator.class).to be Enumerator
        uids = enumerator.to_a
        expect(uids.size).to be 3
        expect(uids.include?('key0-uid0')).to be true
        expect(uids.include?('key0-uid1')).to be true
        expect(uids.include?('key0-uid2')).to be true
      end

      it 'correctly iterates userids w/block' do
        uids = []
        key.each_userid { |userid| uids << userid }
        expect(uids.size).to be 3
        expect(uids.include?('key0-uid0')).to be true
        expect(uids.include?('key0-uid1')).to be true
        expect(uids.include?('key0-uid2')).to be true
      end
    end

    it 'has correct userids' do
      uids = key.userids
      expect(uids.size).to be 3
      expect(uids.include?('key0-uid0')).to be true
      expect(uids.include?('key0-uid1')).to be true
      expect(uids.include?('key0-uid2')).to be true
    end

    it 'is a primary key' do
      expect(key.primary?).to be true
    end

    it 'is not a subkey' do
      expect(key.sub?).to be false
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

