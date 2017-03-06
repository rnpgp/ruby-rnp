require 'netpgp'

describe 'encrypting and decrypting' do

  context 'with pubkey_no_pass.asc and seckey_no_pass.asc' do
    let(:pubkeys) { NetPGP::load_keyring(File.read('spec/keys/pubkey_no_pass.asc'), true) }
    let(:seckeys) { NetPGP::load_keyring(File.read('spec/keys/seckey_no_pass.asc'), true) }
    it { expect(pubkeys.size).to eql 2 }
    it { expect(seckeys.size).to eql 2 }

    let(:pubkey) { pubkeys[0] }
    let(:seckey) { seckeys[0] }
    it 'encrypts and decrypts correctly' do
      cleartext = 'This is my cleartext data.'

      # encrypt
      encrypted_data = pubkey.encrypt(cleartext)
      expect(encrypted_data).to_not eql nil
      expect(encrypted_data).to_not eql cleartext

      # decrypt, no passphrase needed for this key
      decrypted_data = seckey.decrypt(encrypted_data)
      expect(decrypted_data).to eql cleartext
    end
  end

  context 'with pubkey_sign_only.asc and seckey_sign_only.asc' do
    let(:pubkeys) { NetPGP::load_keyring(File.read('spec/keys/pubkey_sign_only.asc'), true) }
    let(:seckeys) { NetPGP::load_keyring(File.read('spec/keys/seckey_sign_only.asc'), true) }
    it { expect(pubkeys.size).to eql 1 }
    it { expect(seckeys.size).to eql 1 }

    let(:pubkey) { pubkeys[0] }
    let(:seckey) { seckeys[0] }
    it 'encrypts and decrypts correctly' do
      cleartext = 'This is my cleartext data.'

      # encrypt
      encrypted_data = pubkey.encrypt(cleartext)
      expect(encrypted_data).to_not eql nil
      expect(encrypted_data).to_not eql cleartext

      # decrypt, incorrect passphrase
      seckey.passphrase = 'wrong'
      expect(seckey.decrypt(encrypted_data)).to eql nil

      # decrypt, correct passphrase
      seckey.passphrase = 'password'
      decrypted_data = seckey.decrypt(encrypted_data)
      expect(decrypted_data).to eql cleartext
    end
  end

end

