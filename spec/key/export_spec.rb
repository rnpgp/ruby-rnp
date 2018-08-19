# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'json'

require 'spec_helper'

describe Rnp::Key.instance_method(:export), skip: !LibRnp::HAVE_RNP_KEY_EXPORT do
  def load_public_keys(rnp)
    rnp.load_keys(
      format: 'GPG',
      input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'),
      public_keys: true,
      secret_keys: false
    )
  end

  def load_secret_keys(rnp)
    rnp.load_keys(
      format: 'GPG',
      input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'),
      public_keys: false,
      secret_keys: true
    )
  end

  context 'with only public keys loaded' do
    let(:rnp) do
      rnp = Rnp.new
      load_public_keys(rnp)
      rnp
    end
    let(:key) { rnp.find_key(keyid: '7BC6709B15C23A4A') }
    it 'fails to export a secret key' do
      expect { key.export_secret }.to raise_error(Rnp::NoSuitableKeyError)
    end
  end

  context 'with only secret keys loaded' do
    let(:rnp) do
      rnp = Rnp.new
      load_secret_keys(rnp)
      rnp
    end
    let(:key) { rnp.find_key(keyid: '7BC6709B15C23A4A') }
    it 'fails to export a public key' do
      expect { key.export_public }.to raise_error(Rnp::NoSuitableKeyError)
    end
  end

  it 'exports an armored key by default (public)' do
    rnp = Rnp.new
    load_public_keys(rnp)
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    exported = key.export_public
    expect(exported.start_with?("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n")).to be true
    expect(exported.end_with?("-----END PGP PUBLIC KEY BLOCK-----\r\n")).to be true
  end

  it 'exports an armored key by default (secret)' do
    rnp = Rnp.new
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    exported = key.export_secret
    expect(exported.start_with?("-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n")).to be true
    expect(exported.end_with?("-----END PGP PRIVATE KEY BLOCK-----\r\n")).to be true
  end

  def reload_keys(data)
    rnp = Rnp.new
    rnp.load_keys(
      format: 'GPG',
      input: Rnp::Input.from_string(data),
      public_keys: true,
      secret_keys: true
    )
    rnp
  end

  it 'correctly exports a lone primary (public)' do
    rnp = Rnp.new
    load_public_keys(rnp)
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    exported = key.export_public

    rnp = reload_keys(exported)
    expect(rnp.keyids).to eql ['2FCADF05FFA501BB']
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    expect(key.public_key_present?).to be true
    expect(key.secret_key_present?).to be false
  end

  it 'correctly exports a lone primary (secret)' do
    rnp = Rnp.new
    load_public_keys(rnp)
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    exported = key.export_secret

    rnp = reload_keys(exported)
    expect(rnp.keyids).to eql ['2FCADF05FFA501BB']
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    expect(key.secret_key_present?).to be true
  end

  it 'correctly exports primary + subkey set (public)' do
    rnp = Rnp.new
    load_public_keys(rnp)
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    exported = key.export_public(with_subkeys: true)

    rnp = reload_keys(exported)
    expect(rnp.keyids).to eql %w[2FCADF05FFA501BB 54505A936A4A970E 326EF111425D14A5]
    rnp.keyids.each do |keyid|
      key = rnp.find_key(keyid: keyid)
      expect(key.public_key_present?).to be true
      expect(key.secret_key_present?).to be false
    end
  end

  it 'correctly exports primary + subkey set (secret)' do
    rnp = Rnp.new
    load_public_keys(rnp)
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    exported = key.export_secret(with_subkeys: true)

    rnp = reload_keys(exported)
    expect(rnp.keyids).to eql %w[2FCADF05FFA501BB 54505A936A4A970E 326EF111425D14A5]
    rnp.keyids.each do |keyid|
      key = rnp.find_key(keyid: keyid)
      expect(key.secret_key_present?).to be true
    end
  end

  it 'correctly exports a lone subkey (public)' do
    rnp = Rnp.new
    load_public_keys(rnp)
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '54505A936A4A970E')
    exported = key.export_public

    rnp = reload_keys(exported)
    expect(rnp.keyids).to eql %w[2FCADF05FFA501BB 54505A936A4A970E]
    rnp.keyids.each do |keyid|
      key = rnp.find_key(keyid: keyid)
      expect(key.public_key_present?).to be true
      expect(key.secret_key_present?).to be false
    end
  end

  it 'correctly exports a lone subkey (secret)' do
    rnp = Rnp.new
    load_public_keys(rnp)
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '54505A936A4A970E')
    exported = key.export_secret

    rnp = reload_keys(exported)
    expect(rnp.keyids).to eql %w[2FCADF05FFA501BB 54505A936A4A970E]
    rnp.keyids.each do |keyid|
      key = rnp.find_key(keyid: keyid)
      expect(key.secret_key_present?).to be true
    end
  end

  it 'can export unarmored keys' do
    rnp = Rnp.new
    load_public_keys(rnp)
    load_secret_keys(rnp)
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    exported = key.export_public(armored: false)

    expect(exported.start_with?('-----')).to be false

    rnp = reload_keys(exported)
    expect(rnp.keyids).to eql ['2FCADF05FFA501BB']
    key = rnp.find_key(keyid: '2FCADF05FFA501BB')
    expect(key.public_key_present?).to be true
    expect(key.secret_key_present?).to be false

    expect(Rnp.key_format(exported)).to eql 'GPG'
  end
end
