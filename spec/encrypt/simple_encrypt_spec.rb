# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'tempfile'
require 'securerandom'

require 'spec_helper'

describe Rnp.instance_method(:encrypt) do
  before do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    recipient = rnp.find_key(userid: 'key0-uid0')

    # write some random-length plaintext
    @plaintext = SecureRandom.hex(rand(1..(32768 * 3))).freeze
    plaintextf = Tempfile.new(['ruby-rnp', '.txt'])
    plaintextf.write(@plaintext)
    plaintextf.close

    @encryptedf = Tempfile.new(['ruby-rnp', '.gpg'])
    rnp.encrypt(recipients: recipient,
                input: Rnp::Input.from_path(plaintextf.path),
                output: Rnp::Output.to_path(@encryptedf.path))
  end

  it 'raises an error when not provided the key' do
    rnp = Rnp.new
    decryptedf = Tempfile.new('ruby-rnp')
    expect {
      rnp.decrypt(input: Rnp::Input.from_path(@encryptedf.path), output: Rnp::Output.to_path(decryptedf.path))
    }.to raise_error(Rnp::NoSuitableKeyError)
  end

  it 'requests the correct key for decrypting' do
    rnp = Rnp.new
    rnp.key_provider = lambda do |idtype, id, secret|
      expect(idtype).to eql 'keyid'
      expect(id).to eql '1ED63EE56FADC34D'
      expect(secret).to eql true
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    end
    decryptedf = Tempfile.new('ruby-rnp')
    expect do
      rnp.decrypt(input: Rnp::Input.from_path(@encryptedf.path), output: Rnp::Output.to_path(decryptedf.path))
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'raises an error when not provided a password' do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    decryptedf = Tempfile.new('ruby-rnp')
    expect do
      rnp.decrypt(input: Rnp::Input.from_path(@encryptedf.path), output: Rnp::Output.to_path(decryptedf.path))
    end.to raise_error(Rnp::BadPasswordError)
  end

  it 'decrypts to the original plaintext' do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = lambda do |key, reason|
      expect(key.keyid).to eql '1ED63EE56FADC34D'
      expect(reason).to eql 'decrypt'
      'password'
    end
    decryptedf = Tempfile.new('ruby-rnp', encoding: Encoding::BINARY)
    rnp.decrypt(input: Rnp::Input.from_io(@encryptedf), output: Rnp::Output.to_path(decryptedf.path))
    decryptedf.open
    expect(decryptedf.read).to eql @plaintext
  end

  context "without AEAD",
          skip: !LibRnp::HAVE_RNP_DUMP_PACKETS_TO_JSON do
    it "does not contain AEAD packets" do
      packets = Rnp.parse(input: Rnp::Input.from_io(@encryptedf))
      expect(
        packets.select { |pkt| pkt["header"]["tag"] == 20 }.any?,
      ).to be false
    end
  end

  context "with AEAD",
          skip: !LibRnp::HAVE_RNP_DUMP_PACKETS_TO_JSON do
    before(:all) do
      rnp = Rnp.new
      rnp.load_keys(
        format: "GPG",
        input: Rnp::Input.from_path("spec/data/keyrings/gpg/pubring.gpg"),
      )
      rnp.load_keys(
        format: "GPG",
        input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
      )
      recipient = rnp.find_key(userid: "key0-uid0")

      # write some random-length plaintext
      @plaintext = SecureRandom.hex(rand(1..(32768 * 3))).freeze

      output = Rnp::Output.to_string
      rnp.encrypt(
        recipients: recipient,
        input: Rnp::Input.from_string(@plaintext),
        output: output,
        aead: :OCB,
      )
      @ciphertext = output.string
    end

    it "does contain AEAD packets" do
      packets = Rnp.parse(input: Rnp::Input.from_string(@ciphertext))
      expect(
        packets.select { |pkt| pkt["header"]["tag"] == 20 }.any?,
      ).to be true
    end
  end
end # Rnp.encrypt

describe Rnp.instance_method(:symmetric_encrypt) do
  let(:plaintext) { @plaintext = SecureRandom.hex(rand(1..(32_768 * 3))).freeze }
  let(:rnp) { Rnp.new }

  context 'with a single password' do
    it 'encrypts and decrypts' do
      encrypted = rnp.symmetric_encrypt(passwords: 'test123',
                                        input: Rnp::Input.from_string(plaintext),
                                        s2k_hash: 'SM3')
      rnp.password_provider = 'test123'
      decrypted = rnp.decrypt(input: Rnp::Input.from_string(encrypted))
      expect(decrypted).to eql plaintext
    end

    it 'raises an error with no password' do
      encrypted = rnp.symmetric_encrypt(passwords: 'test123', input: Rnp::Input.from_string(plaintext))
      expect do
        rnp.decrypt(input: Rnp::Input.from_string(encrypted))
      end.to raise_error(Rnp::BadPasswordError)
    end

    it 'raises an error with a bad password' do
      encrypted = rnp.symmetric_encrypt(passwords: 'test123', input: Rnp::Input.from_string(plaintext))
      rnp.password_provider = 'badpass'
      expect do
        rnp.decrypt(input: Rnp::Input.from_string(encrypted))
      end.to raise_error(Rnp::BadPasswordError)
    end
  end
end # Rnp.symmetric_encrypt

describe Rnp.instance_method(:encrypt_and_sign) do
  before do
    rnp = Rnp.new
    rnp.load_keys(
      format: "GPG",
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/pubring.gpg"),
    )
    rnp.load_keys(
      format: "GPG",
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
    )
    recipient = rnp.find_key(userid: "key0-uid0")

    sender = rnp.find_key(userid: "key1-uid2")
    sender.unlock("password")

    # write some random-length plaintext
    @plaintext = SecureRandom.hex(rand(1..(32768 * 3))).freeze
    plaintextf = Tempfile.new(["ruby-rnp", ".txt"])
    plaintextf.write(@plaintext)
    plaintextf.close

    @encryptedf = Tempfile.new(["ruby-rnp", ".gpg"])
    rnp.encrypt_and_sign(
      recipients: recipient,
      signers: sender,
      input: Rnp::Input.from_path(plaintextf.path),
      output: Rnp::Output.to_path(@encryptedf.path),
    )
  end

  it "raises an error when not provided the key" do
    rnp = Rnp.new
    decryptedf = Tempfile.new("ruby-rnp")
    expect do
      rnp.decrypt(
        input: Rnp::Input.from_path(@encryptedf.path),
        output: Rnp::Output.to_path(decryptedf.path),
      )
    end.to raise_error(Rnp::NoSuitableKeyError)
  end

  it "requests the correct key for decrypting" do
    rnp = Rnp.new
    rnp.key_provider = lambda do |idtype, id, secret|
      expect(idtype).to eql "keyid"
      expect(id).to eql "1ED63EE56FADC34D"
      expect(secret).to eql true
      rnp.load_keys(
        format: "GPG",
        input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
      )
    end
    decryptedf = Tempfile.new("ruby-rnp")
    expect do
      rnp.decrypt(
        input: Rnp::Input.from_path(@encryptedf.path),
        output: Rnp::Output.to_path(decryptedf.path),
      )
    end.to raise_error(Rnp::BadPasswordError)
  end

  it "raises an error when not provided a password" do
    rnp = Rnp.new
    rnp.load_keys(
      format: "GPG",
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
    )
    decryptedf = Tempfile.new("ruby-rnp")
    expect do
      rnp.decrypt(
        input: Rnp::Input.from_path(@encryptedf.path),
        output: Rnp::Output.to_path(decryptedf.path),
      )
    end.to raise_error(Rnp::BadPasswordError)
  end

  it "decrypts to the original plaintext" do
    rnp = Rnp.new
    rnp.load_keys(
      format: "GPG",
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
    )
    rnp.password_provider = lambda do |key, reason|
      expect(key.keyid).to eql "1ED63EE56FADC34D"
      expect(reason).to eql "decrypt"
      "password"
    end
    decryptedf = Tempfile.new("ruby-rnp", encoding: Encoding::BINARY)
    rnp.decrypt(
      input: Rnp::Input.from_io(@encryptedf),
      output: Rnp::Output.to_path(decryptedf.path),
    )
    decryptedf.open
    expect(decryptedf.read).to eql @plaintext
  end

  it "has a valid signature" do
    rnp = Rnp.new
    rnp.load_keys(
      format: "GPG",
      input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
    )
    rnp.password_provider = "password"
    output = Rnp::Output.to_string
    rnp.verify(
      input: Rnp::Input.from_path(@encryptedf.path),
      output: output,
    )
    expect(output.string).to eql @plaintext
  end
end
