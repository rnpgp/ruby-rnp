require 'netpgp'

describe NetPGP::SecretKey.method(:generate) do

  context 'when generating a new key it' do
    let(:key) {
      NetPGP::SecretKey.generate({
        key_length: 1024,
        public_key_algorithm: NetPGP::PublicKeyAlgorithm::RSA,
        algorithm_params: {e: 65537},
        hash_algorithm: NetPGP::HashAlgorithm::SHA1,
        symmetric_key_algorithm: NetPGP::SymmetricKeyAlgorithm::CAST5
      })
    }

    it 'generates valid properties' do
      expect(key.class).to eql NetPGP::SecretKey
      expect(key.public_key.class).to eql NetPGP::PublicKey

      expect(key.public_key.version).to eql 4
      expect(key.public_key.creation_time.to_i).to be_within(10).of(Time.now.to_i)
      expect(key.public_key.expiration_time).to eql 0
      expect(key.public_key.public_key_algorithm).to eql NetPGP::PublicKeyAlgorithm::RSA
      expect(key.public_key.mpi[:e]).to eql 65537
      expect(key.public_key.mpi[:n]).to_not eql nil
      expect(key.public_key.userids).to eql []
      expect(key.public_key.parent).to eql nil
      expect(key.public_key.subkeys.size).to eql 0
      expect(key.public_key.fingerprint_hex).to_not eql nil
      expect(key.public_key.key_id_hex).to_not eql nil

      expect(key.expiration_time).to eql 0
      expect(key.string_to_key_usage).to eql NetPGP::StringToKeyUsage::ENCRYPTED_AND_HASHED
      expect(key.string_to_key_specifier).to eql NetPGP::StringToKeySpecifier::SALTED
      expect(key.symmetric_key_algorithm).to eql NetPGP::SymmetricKeyAlgorithm::CAST5
      expect(key.hash_algorithm).to eql NetPGP::HashAlgorithm::SHA1
      expect(key.mpi.keys).to eql [:d, :p, :q, :u]
      expect(key.mpi[:d]).to_not eql nil
      expect(key.mpi[:p]).to_not eql nil
      expect(key.mpi[:q]).to_not eql nil
      expect(key.mpi[:u]).to_not eql nil
      expect(key.userids).to eql []
      expect(key.parent).to eql nil
      expect(key.subkeys.size).to eql 0
      expect(key.raw_subpackets.size).to eql 0
      expect(key.encrypted).to eql false
    end

  end # generate key

end

