require 'rnp'

describe 'RNP::PublicKey::export' do

  context 'when generating a new key and subkey' do
    let(:key) {
      RNP::SecretKey.generate('password', {
        key_length: 1024,
        public_key_algorithm: RNP::PublicKeyAlgorithm::RSA,
        algorithm_params: {e: 65537},
        hash_algorithm: RNP::HashAlgorithm::SHA1,
        symmetric_key_algorithm: RNP::SymmetricKeyAlgorithm::CAST5
      })
    }

    let(:subkey) {
      RNP::SecretKey.generate('', {
        key_length: 1024
      })
    }

    it 'can be exported' do
      key.userids.push('Test User1')
      key.add_subkey(subkey)
      keyring = RNP::Keyring.new
      keyring.push(key)
      expect(keyring.export(key)).to_not eql nil
      expect(keyring.export(key.public_key)).to_not eql nil
    end

  end # generate key

  context 'when loading seckey_no_pass.asc and pubkey_no_pass.asc' do
    let(:keyring) {
      RNP::Keyring.load(File.read('spec/keys/seckey_no_pass.asc') + File.read('spec/keys/pubkey_no_pass.asc'))
    }
    let (:public_key) { keyring.public_keys[0] }
    let (:secret_key) { keyring.secret_keys[0] }

    it 'can be exported' do
      expect(keyring.export(public_key)).to_not eql nil
      expect(keyring.export(secret_key)).to_not eql nil
      expect(keyring.export(secret_key.public_key)).to_not eql nil
    end

  end

  context 'when loading seckey_sign_only.asc and pubkey_sign_only.asc' do
    let(:keyring) {
      RNP::Keyring.load(File.read('spec/keys/seckey_sign_only.asc') + File.read('spec/keys/pubkey_sign_only.asc'))
    }
    let(:public_key) { keyring.public_keys[0] }
    let(:secret_key) { keyring.secret_keys[0] }

    it 'can be exported' do
      secret_key.passphrase = 'password'
      expect(keyring.export(public_key)).to_not eql nil
      expect(keyring.export(secret_key)).to_not eql nil
      expect(keyring.export(secret_key.public_key)).to_not eql nil
    end

  end

  context 'when loading seckey_sign_only.asc and pubkey_sign_only.asc with passphrase provider' do
    let(:keyring) {
      RNP::Keyring.load(File.read('spec/keys/seckey_sign_only.asc') + File.read('spec/keys/pubkey_sign_only.asc')) {|seckey|
        'password'
      }
    }
    let(:public_key) { keyring.public_keys[0] }
    let(:secret_key) { keyring.secret_keys[0] }

    it 'can be exported' do
      expect(keyring.export(public_key)).to_not eql nil
      expect(keyring.export(secret_key)).to_not eql nil
      expect(keyring.export(secret_key.public_key)).to_not eql nil
    end

  end

end

