# frozen_string_literal: true

# (c) 2019 Ribose Inc.

require "json"

require "spec_helper"

describe Rnp::Key.instance_method(:unload),
         skip: !LibRnp::HAVE_RNP_KEY_REMOVE do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(
      format: "GPG",
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/pubring.gpg")
    )
    rnp.load_keys(
      format: "GPG",
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg")
    )
    rnp
  end
  let(:key) { rnp.find_key(keyid: "1ED63EE56FADC34D") }

  it "unloads the public portion when specified" do
    expect(key.public_key_present?).to be true
    expect(key.secret_key_present?).to be true
    key.unload(unload_public: true, unload_secret: false)
    expect(key.public_key_present?).to be false
    expect(key.secret_key_present?).to be true
  end

  it "unloads the secret portion when specified" do
    expect(key.public_key_present?).to be true
    expect(key.secret_key_present?).to be true
    key.unload(unload_public: false, unload_secret: true)
    expect(key.public_key_present?).to be true
    expect(key.secret_key_present?).to be false
  end

  it "unloads the key entirely when specified" do
    expect(rnp.keyids.include?("1ED63EE56FADC34D")).to be true
    key.unload
    expect(rnp.keyids.include?("1ED63EE56FADC34D")).to be false
  end
end
