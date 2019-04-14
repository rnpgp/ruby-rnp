# frozen_string_literal: true

# (c) 2018,2019 Ribose Inc.

require 'json'

require 'spec_helper'

describe Rnp::Key do
  context '4BE147BB22DF1E60' do
    before do
      @rnp = Rnp.new('KBX', 'G10')
      @rnp.load_keys(format: 'KBX',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg21/pubring.kbx'))
    end
    let(:key) { @rnp.find_key(keyid: '4BE147BB22DF1E60') }

    it "has the correct type",
       skip: !LibRnp::HAVE_RNP_KEY_GET_ALG do
      expect(key.type).to eql "RSA"
    end

    it "can be used to sign",
       skip: !LibRnp::HAVE_RNP_KEY_ALLOWS_USAGE do
      expect(key.can?(:sign)).to be true
    end

    it "can not be used to encrypt",
       skip: !LibRnp::HAVE_RNP_KEY_ALLOWS_USAGE do
      expect(key.can?(:encrypt)).to be false
    end

    it 'has the correct fingerprint' do
      expect(key.fingerprint).to eql '4F2E62B74E6A4CD333BC19004BE147BB22DF1E60'
    end

    it 'has the correct keyid' do
      expect(key.keyid).to eql '4BE147BB22DF1E60'
    end

    it 'has the correct grip' do
      expect(key.grip).to eql '7EAB41A2F46257C36F2892696F5A2F0432499AD3'
    end

    it "has the correct bit length", skip: !LibRnp::HAVE_RNP_KEY_GET_BITS do
      expect(key.bits).to be 2048
    end

    it 'raises an error when requesting primary userid' do
      expect(key.primary_userid).to eql 'test1'
    end

    describe Rnp::Key.instance_method(:each_userid) do
      it 'correctly iterates userids' do
        enumerator = key.each_userid
        expect(enumerator.class).to be Enumerator
        uids = enumerator.to_a
        expect(uids.size).to be 1
        expect(uids[0]).to eql 'test1'
      end

      it 'correctly iterates userids w/block' do
        uids = []
        key.each_userid { |userid| uids << userid }
        expect(uids.size).to be 1
        expect(uids[0]).to eql 'test1'
      end
    end

    it 'has correct userids' do
      uids = key.userids
      expect(uids.size).to be 1
      expect(uids[0]).to eql 'test1'
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
        @rnp.load_keys(format: 'G10',
                       input: Rnp::Input.from_path('spec/data/keyrings/gpg21/private-keys-v1.d'))
      end

      describe Rnp::Key.instance_method(:secret_key_present?) do
        it { expect(key.secret_key_present?).to be true }
      end

      describe Rnp::Key.instance_method(:secret_key_data) do
        let(:data) { key.secret_key_data }

        it { expect(data.class).to be String }
        it { expect(data.encoding).to be Encoding::BINARY }
        it { expect(Rnp.key_format(data)).to eql 'G10' }
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

