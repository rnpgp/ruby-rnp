require 'netpgp'

describe NetPGP.method(:load_keyring) do

  context 'when loading seckey_sign_only.asc' do
    let(:keys) { NetPGP::load_keyring(File.read('spec/keys/seckey_sign_only.asc'), true) }
    it { expect(keys.size).to eql 1 }

    context 'keys[0]' do
      let(:key) { keys[0] }
      it 'has expected properties' do
        expect(key.class).to eql NetPGP::SecretKey

        expect(key.public_key.class).to eql NetPGP::PublicKey
        expect(key.public_key.version).to eql 4
        expect(key.public_key.creation_time).to eql Time.at(1488377933)
        expect(key.public_key.expiration_time).to eql(key.public_key.creation_time + (123 * 86400))
        expect(key.public_key.public_key_algorithm).to eql NetPGP::PublicKeyAlgorithm::RSA
        expect(key.public_key.mpi).to eql({
          n: 0xCF9C12FB58586EB5C99E51123315E0E9A7D637568FF9EF5BB0EBC3029A20DBA907CC6BB41F37CF340A7262D5050FA869EA1EF47F625E5F97EB1A31B14DE0C35C5D68280576663FBD5625077A7B85526DE16AAD8DBADF250EDFBE74FF872EA54CF9E89C7E65FA7FD9A1814765D449E380AE7AD944EEDB301B149EF71F9C8DAD05,
          e: 65537
        })
        expect(key.public_key.userids).to eql []
        expect(key.public_key.parent).to eql nil
        expect(key.public_key.subkeys.size).to eql 0
        expect(key.public_key.fingerprint_hex).to eql '4AD79A40B539229D78E9E82686E45E4EE4312240'
        expect(key.public_key.key_id_hex).to eql '86E45E4EE4312240'
 
        expect(key.expiration_time).to eql(key.creation_time + (123 * 86400))
        expect(key.string_to_key_usage).to eql NetPGP::StringToKeyUsage::ENCRYPTED_AND_HASHED
        expect(key.string_to_key_specifier).to eql NetPGP::StringToKeySpecifier::ITERATED_AND_SALTED
        expect(key.symmetric_key_algorithm).to eql NetPGP::SymmetricKeyAlgorithm::CAST5
        expect(key.hash_algorithm).to eql NetPGP::HashAlgorithm::SHA1
        expect(key.mpi).to eql({
          d: nil,
          p: nil,
          q: nil,
          u: nil
        })
        expect(key.userids).to eql ['Test User1', 'Test User2']
        expect(key.parent).to eql nil
        expect(key.subkeys.size).to eql 0
        expect(key.raw_subpackets.size).to eql 5
        expect(key.encrypted).to eql true
       end
    end # key0

   end # seckey_sign_only.asc

end

