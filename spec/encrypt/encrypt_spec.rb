# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'tempfile'
require 'securerandom'

require 'spec_helper'

describe Rnp::Encrypt do
  let(:plaintext) { SecureRandom.hex(rand(1..(32_768 * 3))).freeze }

  it 'raises an error when adding a signer without a secret key' do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    enc = rnp.start_encrypt(input: Rnp::Input.from_string(plaintext),
                            output: Rnp::Output.to_null)
    expect(enc.class).to eql Rnp::Encrypt
    user1 = rnp.find_key(userid: 'key0-uid0')
    expect do
      enc.add_signer(user1)
    end.to raise_error(Rnp::NoSuitableKeyError)
  end

  it 'raises an error for a signer that is unable to sign' do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    enc = rnp.start_encrypt(input: Rnp::Input.from_string(plaintext),
                            output: Rnp::Output.to_null)
    expect(enc.class).to eql Rnp::Encrypt
    # this is an encryption-only subkey
    badsigner = rnp.find_key(keyid: '54505A936A4A970E')
    expect do
      enc.add_signer(badsigner)
    end.to raise_error(Rnp::NoSuitableKeyError)
  end

  it 'requests the correct key when adding a signer' do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    enc = rnp.start_encrypt(input: Rnp::Input.from_string(plaintext),
                            output: Rnp::Output.to_null)
    expect(enc.class).to eql Rnp::Encrypt
    keyreqs = []
    rnp.key_provider = lambda do |idtype, id, secret|
      expect(secret).to be true
      keyreqs << [idtype, id]
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    end
    user1 = rnp.find_key(userid: 'key0-uid0')
    # doesn't raise error since we loaded the seckey above
    enc.add_signer(user1)
    expect(keyreqs.size).to eql 1
    # check that the key that was requested in our provider above matches user1
    # (via whichever identifier type rnp used in the provider)
    expect(user1.send(keyreqs[0][0].to_sym)).to eql keyreqs[0][1]
  end

  context 'with public-key + symmetric + signing' do
    before do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      output = Rnp::Output.to_string
      enc = rnp.start_encrypt(input: Rnp::Input.from_string(plaintext),
                              output: output)
      expect(enc.class).to eql Rnp::Encrypt
      enc.options = {
        armored: true,
        compression: { algorithm: 'zlib', level: 9 },
        cipher: 'AES256',
        hash: 'SHA256',
        creation_time: Time.now,
        expiration_time: 60 * 10
      }

      # add symmetric passwords
      enc.add_password('pass1', s2k_hash: 'SM3')
      enc.add_password('pass2', s2k_hash: 'SHA512')

      # add a public-key recipient
      user2 = rnp.find_key(userid: 'key1-uid0')
      enc.add_recipient(user2)

      # load the secring for signing
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
      user1 = rnp.find_key(userid: 'key0-uid0')
      enc.add_signer(user1)

      rnp.password_provider = lambda do |key, _reason|
        expect(key.keyid).to eql user1.keyid
        return 'password'
      end

      enc.execute
      @encrypted = output.string
    end

    it 'can be decrypted with symmetric pass pass1' do
      rnp = Rnp.new
      rnp.password_provider = lambda do |key, _reason|
        return nil if key
        return 'pass1'
      end
      expect(rnp.decrypt(input: Rnp::Input.from_string(@encrypted))).to eql plaintext
    end

    it 'can be decrypted with symmetric pass pass2' do
      rnp = Rnp.new
      rnp.password_provider = lambda do |key, _reason|
        return nil if key
        return 'pass2'
      end
      expect(rnp.decrypt(input: Rnp::Input.from_string(@encrypted))).to eql plaintext
    end

    it 'raises an error when no password is provided' do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp.password_provider = nil
      expect do
        rnp.decrypt(input: Rnp::Input.from_string(@encrypted))
      end.to raise_error(Rnp::BadPasswordError)
    end

    it 'can be decrypted by user2' do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
      rnp.password_provider = lambda do |key, _reason|
        return nil unless key
        # this is one of the encrypting subkeys for user2
        expect(["54505A936A4A970E", "326EF111425D14A5"]).to include(key.keyid)
        return 'password'
      end
      expect(rnp.decrypt(input: Rnp::Input.from_string(@encrypted))).to eql plaintext
    end
  end
end # expert encryption


describe Rnp::Encrypt.instance_method(:flags=),
         skip: !LibRnp::HAVE_RNP_OP_ENCRYPT_SET_FLAGS do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = 'password'
    rnp
  end

  it 'encrypts already-signed data without wrapping it in a literal data packet' do
    key = rnp.find_key(userid: 'key0-uid1')
    signed = rnp.sign(input: Rnp::Input.from_string('data'),
                      signers: [key],
                      armored: false)

    # without NOWRAP the signed message is treated as opaque data and
    # wrapped in a literal data packet
    output = Rnp::Output.to_string
    encrypt = rnp.start_encrypt(input: Rnp::Input.from_string(signed),
                                output: output)
    encrypt.add_recipient(key)
    encrypt.execute
    decrypted = Rnp::Output.to_string
    verify = rnp.start_verify(input: Rnp::Input.from_string(output.string),
                              output: decrypted)
    verify.execute
    expect(decrypted.string).to eql signed
    expect(verify.signatures).to be_empty

    # with NOWRAP the signed message is encrypted as-is, so its signature
    # is verified after decryption
    output = Rnp::Output.to_string
    encrypt = rnp.start_encrypt(input: Rnp::Input.from_string(signed),
                                output: output)
    encrypt.flags = LibRnp::RNP_ENCRYPT_NOWRAP
    encrypt.add_recipient(key)
    encrypt.execute
    decrypted = Rnp::Output.to_string
    verify = rnp.start_verify(input: Rnp::Input.from_string(output.string),
                              output: decrypted)
    verify.execute
    expect(decrypted.string).to eql 'data'
    expect(verify.good?).to be true
  end
end
