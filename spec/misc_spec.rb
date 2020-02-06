# frozen_string_literal: true

# (c) 2018-2020 Ribose Inc.

require 'spec_helper'

describe Rnp.method(:default_homedir) do
  it 'returns the expected value' do
    expect(Rnp.default_homedir).to eql "#{ENV['HOME']}/.rnp"
  end
end

describe Rnp.method(:homedir_info) do
  context 'spec/data/keyrings/gpg' do
    it 'returns the correct info' do
      info = Rnp.homedir_info('spec/data/keyrings/gpg')
      expect(info[:public][:format]). to eql 'GPG'
      expect(info[:public][:path]). to eql 'spec/data/keyrings/gpg/pubring.gpg'
      expect(info[:secret][:format]). to eql 'GPG'
      expect(info[:secret][:path]). to eql 'spec/data/keyrings/gpg/secring.gpg'
    end
  end

  context 'spec/data/keyrings/gpg21' do
    it 'returns the correct info' do
      info = Rnp.homedir_info('spec/data/keyrings/gpg21')
      expect(info[:public][:format]). to eql 'KBX'
      expect(info[:public][:path]). to eql 'spec/data/keyrings/gpg21/pubring.kbx'
      expect(info[:secret][:format]). to eql 'G10'
      expect(info[:secret][:path]). to eql 'spec/data/keyrings/gpg21/private-keys-v1.d'
    end
  end
end

describe Rnp.method(:key_format) do
  context 'GPG' do
    it do
      data = File.read('spec/data/keyrings/gpg/pubring.gpg')
      expect(Rnp.key_format(data)).to eql 'GPG'
    end
  end

  context 'KBX' do
    it do
      data = File.read('spec/data/keyrings/gpg21/pubring.kbx')
      expect(Rnp.key_format(data)).to eql 'KBX'
    end
  end

  context 'G10' do
    it do
      data = File.read('spec/data/keyrings/gpg21/private-keys-v1.d/63E59092E4B1AE9F8E675B2F98AA2B8BD9F4EA59.key')
      expect(Rnp.key_format(data)).to eql 'G10'
    end
  end

  context 'Invalid' do
    it do
      expect(Rnp.key_format('ABC')).to eql nil
    end
  end
end

describe 'enarmor and dearmor', skip: !LibRnp::HAVE_RNP_ENARMOR do
  it 'round-trips a plain message' do
    MESSAGE = 'my test message'
    armored = Rnp.enarmor(input: Rnp::Input.from_string(MESSAGE), type: 'message')
    expect(armored.start_with?("-----BEGIN PGP MESSAGE-----\r\n")).to be true
    expect(armored.end_with?("-----END PGP MESSAGE-----\r\n")).to be true
    dearmored = Rnp.dearmor(input: Rnp::Input.from_string(armored))
    expect(dearmored).to eql MESSAGE
  end

  it 'round-trips a keyring (public)' do
    armored = Rnp.enarmor(input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
    expect(armored.start_with?("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n")).to be true
    expect(armored.end_with?("-----END PGP PUBLIC KEY BLOCK-----\r\n")).to be true
    dearmored = Rnp.dearmor(input: Rnp::Input.from_string(armored))
    expect(dearmored).to eql File.binread('spec/data/keyrings/gpg/pubring.gpg')
  end

  it 'round-trips a keyring (secret)' do
    armored = Rnp.enarmor(input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    expect(armored.start_with?("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n")).to be true
    expect(armored.end_with?("-----END PGP PRIVATE KEY BLOCK-----\r\n")).to be true
    dearmored = Rnp.dearmor(input: Rnp::Input.from_string(armored))
    expect(dearmored).to eql File.binread('spec/data/keyrings/gpg/secring.gpg')
  end
end

describe 'versioning', skip: !LibRnp::HAVE_RNP_VERSION do
  describe Rnp.method(:version_string) do
    it 'returns a string' do
      expect(Rnp.version_string.class).to be String
    end
  end

  describe Rnp.method(:version_string_full) do
    it 'returns a string' do
      expect(Rnp.version_string_full.class).to be String
    end
  end

  describe Rnp.method(:version) do
    it 'returns a number' do
      expect(Rnp.version).to be_kind_of(Integer)
    end

    it 'returns the expected value when taking a string version' do
      expect(Rnp.version('1.23.4')).to be ((1 << 20) | (23 << 10) | (4 << 0))
    end

    it 'returns values equivalent to version_for' do
      expect(Rnp.version('2.35.6')).to be Rnp.version_for(2, 35, 6)
    end
  end

  describe Rnp.method(:version_for) do
    it 'round-trips' do
      VERSION = Rnp.version
      MAJOR = Rnp.version_major(VERSION)
      MINOR = Rnp.version_minor(VERSION)
      PATCH = Rnp.version_patch(VERSION)
      expect(Rnp.version_for(MAJOR, MINOR, PATCH)).to be VERSION
    end
  end

  describe Rnp.method(:version_major) do
    it 'returns a number' do
      expect(Rnp.version_major(Rnp.version)).to be_kind_of(Integer)
    end
  end

  describe Rnp.method(:version_minor) do
    it 'returns a number' do
      expect(Rnp.version_minor(Rnp.version)).to be_kind_of(Integer)
    end
  end

  describe Rnp.method(:version_patch) do
    it 'returns a number' do
      expect(Rnp.version_patch(Rnp.version)).to be_kind_of(Integer)
    end
  end
end

describe Rnp.method(:s2k_iterations),
  skip: !LibRnp::HAVE_RNP_CALCULATE_ITERATIONS do

  it 'raises on an invalid hash' do
    expect{ Rnp.s2k_iterations(hash: 'Fake', msec: 10) }.to raise_error(Rnp::Error)
  end

  it 'returns the correct type' do
    expect(Rnp.s2k_iterations(hash: 'SM3', msec: 1)).to be_kind_of(Integer)
  end

  it 'returns a higher iterations count for MD5 vs SM3' do
    MSEC = 5
    expect(Rnp.s2k_iterations(hash: 'MD5', msec: MSEC)).to be >
      Rnp.s2k_iterations(hash: 'SM3', msec: MSEC)
  end
end

describe Rnp.method(:enable_debug),
  skip: !LibRnp::HAVE_RNP_ENABLE_DEBUG do

  it 'does not raise an error' do
    expect { Rnp.enable_debug }.to_not raise_error
    expect { Rnp.enable_debug('all') }.to_not raise_error
  end
end

describe Rnp.method(:disable_debug),
  skip: !LibRnp::HAVE_RNP_DISABLE_DEBUG do

  it 'does not raise an error' do
    expect { Rnp.disable_debug }.to_not raise_error
  end
end

describe Rnp.method(:guess_contents),
  skip: !LibRnp::HAVE_RNP_GUESS_CONTENTS do

  it 'correctly identifies a public key' do
    expect(Rnp.guess_contents(
      Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg')
    )).to eql 'public key'
  end

  it 'returns unknown on unknown input' do
    expect(Rnp.guess_contents(Rnp::Input.from_string(' '))).to eql 'unknown'
  end
end

describe Rnp.method(:supports?),
  skip: !LibRnp::HAVE_RNP_SUPPORTS_FEATURE do

  it 'returns a boolean' do
    value = Rnp.supports?('hash algorithm', 'SM3')
    expect(!!value == value).to be true
  end

  it 'return false on a fake alg' do
    expect(Rnp.supports?('symmetric algorithm', 'FAKE')).to be false
  end

  it 'raises an error on an invalid type' do
    expect { Rnp.supports?('fake', 'value') }.to raise_error(Rnp::Error)
  end
end

describe Rnp.method(:supported_features),
  skip: !LibRnp::HAVE_RNP_SUPPORTED_FEATURES do

  it 'raises an error on an invalid type' do
    expect { Rnp.supported_features('fake') }.to raise_error(Rnp::Error)
  end

  it 'returns the correct type' do
    expect(Rnp.supported_features('symmetric algorithm').class).to be Array
  end
end
