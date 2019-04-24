# frozen_string_literal: true

# (c) 2019 Ribose Inc.

require "spec_helper"

describe Rnp::Key do
  context "1095C3ED6D43C03B" do
    before do
      @rnp = Rnp.new
      @rnp.load_keys(format: "GPG",
                     input: Rnp::Input.from_string("
-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEXLO69BYJKwYBBAHaRw8BAQdAWsoBwHOLMrbp7ykSSCD7FYG7tMYT74aLn5wh
Q63nmJC0BmVjZHNhMIiQBBMWCAA4FiEEMuxFQcPhApFLtGbaEJXD7W1DwDsFAlyz
uvQCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQEJXD7W1DwDs/cwD+PQt4
GnDUFFW2omo7XJh6AUUC4eUnKQoMWoD3iwYetCwA/1leV7sUdsvs5wvkp+LJVDTW
dbpkwTCmBVbAmazgea0B
=omFJ
-----END PGP PUBLIC KEY BLOCK-----
"))
    end
    let(:key) { @rnp.find_key(keyid: "1095C3ED6D43C03B") }

    it "has the correct type",
       skip: !LibRnp::HAVE_RNP_KEY_GET_ALG do
      expect(key.type).to eql "EDDSA"
    end

    it "has the correct curve",
       skip: !LibRnp::HAVE_RNP_KEY_GET_CURVE do
      expect(key.curve).to eql "Ed25519"
    end

    it "has the correct fingerprint" do
      expect(key.fingerprint).to eql "32EC4541C3E102914BB466DA1095C3ED6D43C03B"
    end

    it "has the correct keyid" do
      expect(key.keyid).to eql "1095C3ED6D43C03B"
    end

    it "has the correct grip" do
      expect(key.grip).to eql "C52C89C07E9222082474F499C8BC25D7A6DDD63E"
    end

    it "has the correct bit length", skip: !LibRnp::HAVE_RNP_KEY_GET_BITS do
      expect(key.bits).to be 255
    end

    it "has the correct primary userid" do
      expect(key.primary_userid).to eql "ecdsa0"
    end

    describe Rnp::Key.instance_method(:each_subkey),
             skip: !LibRnp::HAVE_RNP_KEY_GET_SUBKEY_AT do
      it "correctly iterates" do
        enumerator = key.each_subkey
        expect(enumerator.class).to be Enumerator
        keys = enumerator.to_a
        expect(keys.size).to be 0
      end

      it "correctly iterates w/block" do
        keys = []
        key.each_subkey { |k| keys << k }
        expect(keys.size).to be 0
      end
    end

    describe Rnp::Key.instance_method(:subkeys),
             skip: !LibRnp::HAVE_RNP_KEY_GET_SUBKEY_AT do
      it "has the correct subkeys" do
        keys = key.subkeys
        expect(keys.size).to be 0
      end
    end

    describe Rnp::Key.instance_method(:each_userid) do
      it "correctly iterates userids" do
        enumerator = key.each_userid
        expect(enumerator.class).to be Enumerator
        uids = enumerator.to_a
        expect(uids.size).to be 1
        expect(uids.include?("ecdsa0")).to be true
      end

      it "correctly iterates userids w/block" do
        uids = []
        key.each_userid { |userid| uids << userid }
        expect(uids.size).to be 1
        expect(uids.include?("ecdsa0")).to be true
      end
    end

    it "has correct userids" do
      uids = key.userids
      expect(uids.size).to be 1
      expect(uids.include?("ecdsa0")).to be true
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
        @rnp.load_keys(format: "GPG",
                       input: Rnp::Input.from_string("
-----BEGIN PGP PRIVATE KEY BLOCK-----

lFgEXLO69BYJKwYBBAHaRw8BAQdAWsoBwHOLMrbp7ykSSCD7FYG7tMYT74aLn5wh
Q63nmJAAAQC0U1+3zXW7h5sZ2WTVFDOrqJ1EPHcpwlJjh3nmjebKRhCftAZlY2Rz
YTCIkAQTFggAOBYhBDLsRUHD4QKRS7Rm2hCVw+1tQ8A7BQJcs7r0AhsDBQsJCAcC
BhUKCQgLAgQWAgMBAh4BAheAAAoJEBCVw+1tQ8A7P3MA/j0LeBpw1BRVtqJqO1yY
egFFAuHlJykKDFqA94sGHrQsAP9ZXle7FHbL7OcL5KfiyVQ01nW6ZMEwpgVWwJms
4HmtAQ==
=aCSs
-----END PGP PRIVATE KEY BLOCK-----
"))
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
        expect(data["type"]).to eql "EDDSA"
      end
    end
  end
end
