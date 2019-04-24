# frozen_string_literal: true

# (c) 2019 Ribose Inc.

require "spec_helper"

describe Rnp::Key do
  context "2FCADF05FFA501BB" do
    before do
      @rnp = Rnp.new
      @rnp.load_keys(
        format: "GPG",
        input: Rnp::Input.from_path("spec/data/keyrings/gpg/pubring.gpg"),
      )
    end
    let(:key) { @rnp.find_key(keyid: "2FCADF05FFA501BB") }

    it "has the correct type",
       skip: !LibRnp::HAVE_RNP_KEY_GET_ALG do
      expect(key.type).to eql "DSA"
    end

    it "has the correct fingerprint" do
      expect(key.fingerprint).to eql "BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB"
    end

    it "has the correct keyid" do
      expect(key.keyid).to eql "2FCADF05FFA501BB"
    end

    it "has the correct grip",
       skip: !Rnp.has?("dsa-elg-grip-calc") do
      expect(key.grip).to eql "B2A7F6C34AA2C15484783E9380671869A977A187"
    end

    it "has the correct bit length", skip: !LibRnp::HAVE_RNP_KEY_GET_BITS do
      expect(key.bits).to be 1024
    end

    it "has the correct q bit length",
       skip: !LibRnp::HAVE_RNP_KEY_GET_DSA_QBITS do
      expect(key.qbits).to be 160
    end

    it "has the correct primary userid" do
      expect(key.primary_userid).to eql "key1-uid0"
    end

    describe Rnp::Key.instance_method(:each_userid) do
      it "correctly iterates userids" do
        enumerator = key.each_userid
        expect(enumerator.class).to be Enumerator
        uids = enumerator.to_a
        expect(uids.size).to be 3
        expect(uids.include?("key1-uid0")).to be true
        expect(uids.include?("key1-uid1")).to be true
        expect(uids.include?("key1-uid2")).to be true
      end

      it "correctly iterates userids w/block" do
        uids = []
        key.each_userid { |userid| uids << userid }
        expect(uids.size).to be 3
        expect(uids.include?("key1-uid0")).to be true
        expect(uids.include?("key1-uid1")).to be true
        expect(uids.include?("key1-uid2")).to be true
      end
    end

    it "has correct userids" do
      uids = key.userids
      expect(uids.size).to be 3
      expect(uids.include?("key1-uid0")).to be true
      expect(uids.include?("key1-uid1")).to be true
      expect(uids.include?("key1-uid2")).to be true
    end

    it "is a primary key" do
      expect(key.primary?).to be true
    end

    it "is not a subkey" do
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
      it { expect(Rnp.key_format(data)).to eql "GPG" }
    end

    describe Rnp::Key.instance_method(:secret_key_data) do
      it do
        expect { key.secret_key_data }.to raise_error(Rnp::NoSuitableKeyError)
      end
    end

    context "when the secret key has been loaded" do
      before do
        @rnp.load_keys(
          format: "GPG",
          input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
        )
      end

      describe Rnp::Key.instance_method(:secret_key_present?) do
        it { expect(key.secret_key_present?).to be true }
      end

      describe Rnp::Key.instance_method(:secret_key_data) do
        let(:data) { key.secret_key_data }

        it { expect(data.class).to be String }
        it { expect(data.encoding).to be Encoding::BINARY }
        it { expect(Rnp.key_format(data)).to eql "GPG" }
      end
    end

    describe Rnp::Key.instance_method(:json) do
      let(:data) do
        key.json(
          public_mpis: true,
          secret_mpis: false,
          signatures: true,
          signature_mpis: false,
        )
      end

      it "has the correct key type" do
        expect(data["type"]).to eql "DSA"
      end
    end
  end
end
