# frozen_string_literal: true

# (c) 2019 Ribose Inc.

require "spec_helper"

describe Rnp.instance_method(:start_generate),
         skip: !LibRnp::HAVE_RNP_OP_GENERATE_CREATE do
  context "RSA" do
    context "when setting invalid options" do
      let(:rnp) { Rnp.new }
      let(:op) { rnp.start_generate(type: "RSA") }

      it "raises an error when setting qbits" do
        expect { op.qbits = 256 }.to raise_error(Rnp::Error)
      end

      it "raises an error when setting curve" do
        expect { op.curve = "Ed25519" }.to raise_error(Rnp::Error)
      end
    end

    before(:all) do
      @rnp = Rnp.new
      op = @rnp.start_generate(type: "RSA")
      op.options = {
        bits:  1536,
        hash:  "RIPEMD160",
        s2k_hash:  "SM3",
        s2k_iterations:  65_536,
        s2k_cipher:  "SM4",
        password:  "mypass",
        lifetime:  60 * 5,
        userid:  "myuserid",
        usage: :sign,
        preferences: {
          hashes: %i[sha512 sha256],
          compression: %i[zip],
          ciphers: %i[CAST5],
          key_server: "hkp://pgp.mit.edu",
        },
      }
      op.execute
      @key = op.key
      @json = @key.json
      @pkts = Rnp.parse(input: Rnp::Input.from_string(@key.secret_key_data))
      # find the userid self-sig
      @cert = @pkts.detect do |pkt|
        pkt["type.str"] == "Positive User ID certification"
      end
    end

    it "has the correct type" do
      expect(@key.type).to eql "RSA"
    end

    it "has the correct usage" do
      expect(@key.can?(:sign)).to be true
      expect(@key.can?(:encrypt)).to be false
    end

    it "has the correct lifetime" do
      expect(@json["expiration"]).to be (60 * 5)
      subpkt = @cert["subpackets"].detect do |pkt|
        pkt["type.str"] == "key expiration time"
      end
      expect(subpkt["key expiration"]).to be (60 * 5)
    end

    it "has no subkeys" do
      expect(@key.subkeys).to eql []
    end

    it "is locked and protected" do
      expect(@key.locked?).to be true
      expect(@key.protected?).to be true
    end

    it "can be unlocked with the provided password" do
      @key.unlock("mypass")
      expect(@key.locked?).to be false
      @key.lock
    end

    it "has the correct bit length" do
      expect(@key.bits).to be 1536
    end

    it "has the correct hash" do
      expect(@cert["hash algorithm.str"]).to eql "RIPEMD160"
    end

    it "has the correct s2k hash" do
      expect(
        @pkts.detect do |pkt|
          pkt["header"]["tag.str"] == "Secret Key"
        end["material"]["s2k"]["hash algorithm.str"],
      ).to eql "SM3"
    end

    it "has the correct s2k iterations" do
      expect(
        @pkts.detect do |pkt|
          pkt["header"]["tag.str"] == "Secret Key"
        end["material"]["s2k"]["iterations"],
      ).to eql 65_536
    end

    it "has the correct cipher" do
      expect(
        @pkts.detect do |pkt|
          pkt["header"]["tag.str"] == "Secret Key"
        end["material"]["symmetric algorithm.str"],
      ).to eql "SM4"
    end

    it "has the correct userid" do
      expect(@key.userids).to eql ["myuserid"]
    end

    it "has the correct validity period" do
      expect(@json["expiration"]).to be 300
    end

    it "has the correct preferred hashes" do
      subpkt = @cert["subpackets"].detect do |pkt|
        pkt["type.str"] == "preferred hash algorithms"
      end
      expect(
        subpkt["algorithms.str"],
      ).to eql ["SHA512", "SHA256"]
    end

    it "has the correct preferred compression" do
      subpkt = @cert["subpackets"].detect do |pkt|
        pkt["type.str"] == "preferred compression algorithms"
      end
      expect(
        subpkt["algorithms.str"],
      ).to eql ["ZIP"]
    end

    it "has the correct preferred ciphers" do
      subpkt = @cert["subpackets"].detect do |pkt|
        pkt["type.str"] == "preferred symmetric algorithms"
      end
      expect(
        subpkt["algorithms.str"],
      ).to eql ["CAST5"]
    end

    it "has the correct preferred key server" do
      subpkt = @cert["subpackets"].detect do |pkt|
        pkt["type.str"] == "preferred key server"
      end
      expect(subpkt["uri"]).to eql "hkp://pgp.mit.edu"
    end
  end

  context "DSA" do
    context "when setting invalid options" do
      let(:rnp) { Rnp.new }
      let(:op) { rnp.start_generate(type: "DSA") }

      it "raises an error when setting curve" do
        expect { op.curve = "Ed25519" }.to raise_error(Rnp::Error)
      end
    end

    before(:all) do
      @rnp = Rnp.new
      op = @rnp.start_generate(type: "DSA")
      op.options = {
        bits:  1024,
        qbits: 160,
        hash:  "SM3",
        s2k_hash:  "SM3",
        s2k_iterations:  65_536,
        s2k_cipher:  "SM4",
        password:  "mypass",
        lifetime:  60 * 5,
        userid:  "myuserid",
      }
      op.execute
      @key = op.key
      @json = @key.json
    end

    it "has the correct type" do
      expect(@key.type).to eql "DSA"
    end

    it "has no subkeys" do
      expect(@key.subkeys).to eql []
    end

    it "is locked and protected" do
      expect(@key.locked?).to be true
      expect(@key.protected?).to be true
    end

    it "can be unlocked with the provided password" do
      @key.unlock("mypass")
      expect(@key.locked?).to be false
      @key.lock
    end

    it "has the correct bit length" do
      expect(@key.bits).to be 1024
    end

    it "has the correct q bit length" do
      expect(@key.qbits).to be 160
    end

    it "has the correct userid" do
      expect(@key.userids).to eql ["myuserid"]
    end

    it "has the correct validity period" do
      expect(@json["expiration"]).to be 300
    end
  end
end

describe Rnp.instance_method(:start_generate_subkey),
         skip: !LibRnp::HAVE_RNP_OP_GENERATE_SUBKEY_CREATE do
  context "RSA" do
    before(:all) do
      @rnp = Rnp.new
      @primary = @rnp.generate_rsa(userid: "myuserid", bits: 1024,
                                   password: "mypass")
      op = @rnp.start_generate_subkey(primary: @primary, type: "RSA")
      op.options = {
        bits:  1024,
        lifetime:  0,
        password: "mysubpass",
      }
      expect { op.execute }.to raise_error(Rnp::Error)
      @rnp.password_provider = "mypass"
      op.execute
      @key = op.key
      @json = @key.json
    end

    context "when setting invalid options" do
      let(:op) { @rnp.start_generate_subkey(primary: @primary, type: "RSA") }

      it "raises an error when setting userid" do
        expect { op.userid = "myuserid" }.to raise_error(Rnp::Error)
      end

      it "raises an error when setting qbits" do
        expect { op.qbits = 256 }.to raise_error(Rnp::Error)
      end

      it "raises an error when setting curve" do
        expect { op.curve = "Ed25519" }.to raise_error(Rnp::Error)
      end
    end

    it "has the correct type" do
      expect(@key.type).to eql "RSA"
    end

    it "is locked and protected" do
      expect(@key.locked?).to be true
      expect(@key.protected?).to be true
    end

    it "can be unlocked with the provided password" do
      @key.unlock("mysubpass")
      expect(@key.locked?).to be false
      @key.lock
    end

    it "has the correct bit length" do
      expect(@key.bits).to be 1024
    end

    it "is a subkey" do
      expect(@key.sub?).to be true
    end

    it "has no userids" do
      expect(@key.userids).to eql []
    end

    it "has the correct validity period" do
      expect(@json["expiration"]).to be 0
    end
  end

  context "ECDSA + ECDH" do
    before(:all) do
      @rnp = Rnp.new
      @primary = @rnp.generate(type: "ECDSA", curve: "secp256k1",
                               userid: "myuserid", password: nil,
                               bits: 0)
      op = @rnp.start_generate_subkey(primary: @primary, type: "ECDH")
      op.options = {
        curve: "brainpoolP256r1",
      }
      op.execute
      @key = op.key
      @json = @key.json
    end

    context "when setting invalid options" do
      let(:op) { @rnp.start_generate_subkey(primary: @primary, type: "ECDH") }

      it "raises an error when setting userid" do
        expect { op.userid = "myuserid" }.to raise_error(Rnp::Error)
      end
    end

    it "has the correct type" do
      expect(@key.type).to eql "ECDH"
    end

    it "is not locked or protected" do
      expect(@key.locked?).to be false
      expect(@key.protected?).to be false
    end

    it "has the correct curve" do
      expect(@key.curve).to eql "brainpoolP256r1"
    end

    it "is a subkey" do
      expect(@key.sub?).to be true
    end

    it "has no userids" do
      expect(@key.userids).to eql []
    end

    it "has the correct validity period" do
      expect(@json["expiration"]).to be 0
    end
  end
end
