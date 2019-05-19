# frozen_string_literal: true

# (c) 2019 Ribose Inc.

require "set"

require "spec_helper"

describe Rnp.instance_method(:generate_sm2),
         skip: !LibRnp::HAVE_RNP_GENERATE_KEY_SM2 do
  let(:key) do
    @rnp = Rnp.new
    @rnp.generate_sm2(userid: "test1", password: nil)
  end

  let(:subkey) { key.subkeys[0] }

  it "has the correct type" do
    expect(key.type).to eql "SM2"
    expect(subkey.type).to eql "SM2"
  end

  it "has the correct userid" do
    expect(key.userids).to eql ["test1"]
  end

  it "has the correct bit length" do
    expect(key.bits).to eql 256
    expect(subkey.bits).to eql 256
  end

  it "has the correct curve" do
    expect(key.curve).to eql "SM2 P-256"
    expect(subkey.curve).to eql "SM2 P-256"
  end

  it "has the correct usage" do
    expect(key.can?(:sign)).to be true
    expect(key.can?(:encrypt)).to be false
    expect(subkey.can?(:sign)).to be false
    expect(subkey.can?(:encrypt)).to be true
  end

  it "has a subkey" do
    expect(key.subkeys.size).to eql 1
  end

  it "is unlocked" do
    expect(key.locked?).to be false
    expect(subkey.locked?).to be false
  end

  it "is not protected" do
    expect(key.protected?).to be false
    expect(subkey.protected?).to be false
  end

  context "when a password is provided" do
    let(:key) do
      @rnp = Rnp.new
      @rnp.generate_sm2(userid: "test1", password: "pass")
    end

    it "is locked" do
      expect(key.locked?).to be true
      expect(subkey.locked?).to be true
    end

    it "is protected" do
      expect(key.protected?).to be true
      expect(subkey.protected?).to be true
    end

    it "can be unlocked with the correct password" do
      key.unlock("pass")
      expect(key.locked?).to be false
      subkey.unlock("pass")
      expect(subkey.locked?).to be false
    end
  end
end
