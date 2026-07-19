# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'spec_helper'

describe 'key lifecycle' do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = 'password'
    rnp
  end

  def generate(rnp, userid, usage: nil)
    op = rnp.start_generate(type: 'RSA')
    op.bits = 1024
    op.userid = userid
    op.usage = usage if usage
    op.execute
    op.key
  end

  describe Rnp::Key.instance_method(:revoke) do
    it 'revokes the key with a reason' do
      key = generate(rnp, 'to-revoke')
      key.revoke(code: 'retired', reason: 'no longer used')
      expect(key.revoked?).to be true
      expect(key.retired?).to be true
      expect(key.compromised?).to be false
      expect(key.revocation_reason).to eql 'no longer used'
    end

    it 'revokes with defaults' do
      key = generate(rnp, 'to-revoke-defaults')
      key.revoke
      expect(key.revoked?).to be true
    end
  end

  describe Rnp::Key.instance_method(:set_expiration) do
    it 'sets the expiration time' do
      key = generate(rnp, 'set-expiration')
      key.set_expiration(3600)
      expect(key.valid_till.to_i).to eql(key.creation_time.to_i + 3600)
    end

    it 'clears the expiration time' do
      key = generate(rnp, 'clear-expiration')
      key.set_expiration(3600)
      key.set_expiration(0)
      expect(key.valid_till).to be_nil
    end
  end

  describe Rnp::Key.instance_method(:default_key) do
    let(:key) { rnp.find_key(userid: 'key0-uid1') }

    it 'returns the encryption subkey' do
      default = key.default_key(:encrypt)
      expect(default).to be_a Rnp::Key
      expect(default.keyid).to eql '8A05B89FAD5ADED1'
    end

    it 'returns the primary key for certify' do
      expect(key.default_key(:certify).keyid).to eql key.keyid
    end

    it 'excludes the primary key with subkeys_only' do
      default = key.default_key(:encrypt, subkeys_only: true)
      expect(default.keyid).to eql '8A05B89FAD5ADED1'
      expect(key.default_key(:sign, subkeys_only: true)).to be_nil
    end

    it 'returns nil when no suitable key exists' do
      signonly = generate(rnp, 'sign-only', usage: :sign)
      expect(signonly.default_key(:encrypt)).to be_nil
    end
  end

  describe Rnp::Key.instance_method(:export_autocrypt) do
    let(:key) { rnp.find_key(userid: 'key0-uid1') }

    it 'exports binary packets' do
      exported = key.export_autocrypt(uid: 'key0-uid1')
      expect(exported.encoding).to eql Encoding::BINARY
      expect(Rnp.key_format(exported)).to eql 'GPG'
    end

    it 'exports base64' do
      exported = key.export_autocrypt(uid: 'key0-uid1', base64: true)
      expect(exported).to_not include '-----BEGIN'
      expect(exported).to match(/\A[A-Za-z0-9+\/=\r\n]+\z/)
    end

    it 'raises an error on an ambiguous userid' do
      expect { key.export_autocrypt }.to raise_error(Rnp::Error)
    end
  end

  describe Rnp::Key.instance_method(:export_revocation) do
    it 'exports an armored revocation signature' do
      key = generate(rnp, 'rev-export')
      exported = key.export_revocation(code: 'superseded',
                                       reason: 'testing export')
      expect(exported.start_with?("-----BEGIN PGP PUBLIC KEY BLOCK-----\r\n"))
        .to be true
    end

    it 'exports a binary revocation signature' do
      key = generate(rnp, 'rev-export-bin')
      exported = key.export_revocation(armored: false)
      expect(exported.encoding).to eql Encoding::BINARY
      # a signature packet (old format, tag 2)
      expect(exported.getbyte(0) & 0x3F).to eql 2
    end

    it 'can be imported to revoke the key' do
      key = generate(rnp, 'rev-import')
      exported = key.export_revocation(armored: false)
      other = Rnp.new
      other.load_keys(format: 'GPG',
                      input: Rnp::Input.from_string(key.export_public(armored: false)))
      other.import_signatures(input: Rnp::Input.from_string(exported))
      imported = other.find_key(userid: 'rev-import')
      expect(imported.revoked?).to be true
    end
  end

  describe 'Curve25519 bit tweaking',
           skip: !LibRnp::HAVE_RNP_KEY_25519_BITS_TWEAK do
    it 'reports a generated 25519 key as tweaked' do
      key = rnp.generate_eddsa_25519(userid: 'tweaked-gen', password: nil)
      subkey = key.subkeys[0]
      expect(subkey.curve).to eql 'Curve25519'
      expect(subkey.x25519_bits_tweaked?).to be true
      expect { subkey.x25519_bits_tweak }.to_not raise_error
      subkey.lock
    end

    it 'tweaks a non-tweaked 25519 key' do
      rnp.load_keys(
        format: 'GPG',
        input: Rnp::Input.from_path('spec/data/keys/key-25519-non-tweaked-sec.asc')
      )
      subkey = rnp.find_key(keyid: '950EE0CD34613DBA')
      expect(subkey.x25519_bits_tweaked?).to be false
      subkey.x25519_bits_tweak
      expect(subkey.x25519_bits_tweaked?).to be true
      subkey.lock
    end

    it 'raises an error for a non-25519 key' do
      key = rnp.find_key(userid: 'key0-uid1')
      expect { key.x25519_bits_tweaked? }.to raise_error(Rnp::Error)
      expect { key.x25519_bits_tweak }.to raise_error(Rnp::Error)
    end
  end
end
