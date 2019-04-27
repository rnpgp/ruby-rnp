# frozen_string_literal: true

# (c) 2019 Ribose Inc.

require "spec_helper"

describe Rnp.method(:parse),
         skip: !LibRnp::HAVE_RNP_DUMP_PACKETS_TO_JSON do
  before(:all) do
    rnp = Rnp.new
    rnp.load_keys(
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/pubring.gpg"),
      format: "GPG",
    )
    key = rnp.find_key(keyid: "8A05B89FAD5ADED1")
    @key_data = key.public_key_data
    @data = Rnp.parse(
      input: Rnp::Input.from_string(@key_data),
    ).freeze
  end

  it "has the correct class" do
    expect(@data.is_a?(Array)).to be true
  end

  it "has the correct packet count" do
    expect(@data.size).to be 2
  end

  context "packet 0" do
    let(:pkt) { @data[0] }
    let(:hdr) { pkt["header"] }

    it "has the correct header values" do
      expect(hdr["offset"]).to be 0
      expect(hdr["tag"]).to be 14
      expect(hdr["tag.str"]).to eql "Public Subkey"
      expect(hdr["length"]).to be 141
      expect(hdr["partial"]).to be false
      expect(hdr["indeterminate"]).to be false
    end

    it "has the correct data values" do
      expect(pkt["version"]).to be 4
      expect(pkt["creation time"]).to be 1500569896
      expect(pkt["algorithm"]).to be 1
      expect(pkt["algorithm.str"]).to eql "RSA"
      expect(pkt["material"]["n.bits"]).to be 1024
      expect(pkt["material"]["e.bits"]).to be 17
      expect(pkt["keyid"]).to eql "8a05b89fad5aded1"
    end
  end

  context "packet 1" do
    let(:pkt) { @data[1] }
    let(:hdr) { pkt["header"] }

    it "has the correct header values" do
      expect(hdr["offset"]).to be 143
      expect(hdr["tag"]).to be 2
      expect(hdr["tag.str"]).to eql "Signature"
      expect(hdr["length"]).to be 159
      expect(hdr["partial"]).to be false
      expect(hdr["indeterminate"]).to be false
    end

    it "has the correct data values" do
      expect(pkt["version"]).to be 4
      expect(pkt["type"]).to be 24
      expect(pkt["type.str"]).to eql "Subkey Binding Signature"
      expect(pkt["algorithm"]).to be 1
      expect(pkt["algorithm.str"]).to eql "RSA"
      expect(pkt["hash algorithm"]).to be 2
      expect(pkt["hash algorithm.str"]).to eql "SHA1"
      expect(pkt["lbits"]).to eql "4c80"
      expect(pkt["material"]["s.bits"]).to eql 1024
    end

    it "has the correct subpacket count" do
      expect(pkt["subpackets"].size).to be 3
    end

    context "subpacket 0" do
      let(:subpkt) { pkt["subpackets"][0] }
      it "has the correct data values" do
        expect(subpkt["type"]).to be 2
        expect(subpkt["type.str"]).to eql "signature creation time"
        expect(subpkt["length"]).to be 4
        expect(subpkt["hashed"]).to be true
        expect(subpkt["critical"]).to be false
        expect(subpkt["creation time"]).to be 1500569896
      end
    end

    context "subpacket 1" do
      let(:subpkt) { pkt["subpackets"][1] }
      it "has the correct data values" do
        expect(subpkt["type"]).to be 27
        expect(subpkt["type.str"]).to eql "key flags"
        expect(subpkt["length"]).to be 1
        expect(subpkt["hashed"]).to be true
        expect(subpkt["critical"]).to be false
        expect(subpkt["flags"]).to be 12
        expect(subpkt["flags.str"]).to eql ["encrypt_comm", "encrypt_storage"]
      end
    end

    context "subpacket 2" do
      let(:subpkt) { pkt["subpackets"][2] }
      it "has the correct data values" do
        expect(subpkt["type"]).to be 16
        expect(subpkt["type.str"]).to eql "issuer key ID"
        expect(subpkt["length"]).to be 8
        expect(subpkt["hashed"]).to be false
        expect(subpkt["critical"]).to be false
        expect(subpkt["issuer keyid"]).to eql "7bc6709b15c23a4a"
      end
    end
  end

  context "when mpi is false" do
    it "does not include MPIs" do
      expect(@data[0]["material"].include?("e.raw")).to be false
    end
  end

  context "when mpi is true" do
    before(:all) do
      @data = Rnp.parse(
        input: Rnp::Input.from_string(@key_data),
        mpi: true,
      ).freeze
    end

    it "does include MPIs" do
      expect(@data[0]["material"].include?("e.raw")).to be true
    end
  end

  context "when raw is false" do
    it "does not include raw bytes" do
      expect(@data[0].include?("raw")).to be false
    end
  end

  context "when raw is true" do
    before(:all) do
      @data = Rnp.parse(
        input: Rnp::Input.from_string(@key_data),
        raw: true,
      ).freeze
    end

    it "does include raw bytes" do
      expect(@data[0].include?("raw")).to be true
    end
  end

  context "when grip is false" do
    it "does not include grips" do
      expect(@data[0].include?("grip")).to be false
    end
  end

  context "when grip is true" do
    before(:all) do
      @data = Rnp.parse(
        input: Rnp::Input.from_string(@key_data),
        grip: true,
      ).freeze
    end

    it "does include grips" do
      expect(@data[0].include?("grip")).to be true
    end
  end
end
