# frozen_string_literal: true

# (c) 2018 Ribose Inc.

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
