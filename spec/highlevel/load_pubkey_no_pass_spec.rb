require 'rnp'

describe RNP.method(:load_keys) do

  context 'when loading pubkey_no_pass.asc' do
    let(:keys) { RNP::load_keys(File.read('spec/keys/pubkey_no_pass.asc'), true) }
    it { expect(keys.size).to eql 2 }

    context 'keys[0]' do
      let(:key) { keys[0] }
      it 'has expected properties' do
        expect(key.class).to eql RNP::PublicKey
        expect(key.version).to eql 4
        expect(key.creation_time).to eql Time.at(1488299695)
        expect(key.expiration_time).to eql(key.creation_time + (9876 * 86400))
        expect(key.public_key_algorithm).to eql RNP::PublicKeyAlgorithm::RSA
        expect(key.mpi).to eql({
          n: 0xC9C8091AFFE483815AD036A686EE026600298523AB527D8C82A39ABDF94E968BD2FF87DFF6EAAD3486E09C497EA1291A7A00085324ACE6DF7378F2C61BB713D24CEF52CD14A9DF54219DF4CFAB2FC2AD570EE945FED2009789035A4A3809CA56FA77027B9E995DC2F326F6DF60797D40558E3CB9CA53869F620A425F3768FAF5,
          e: 65537
        })
        expect(key.userids).to eql ['Test User1']
        expect(key.parent).to eql nil
        expect(key.subkeys.size).to eql 1
        expect(key.fingerprint_hex).to eql '03CFD3CA3EB8F34A713BBFCCBA1C17D5D9EB925B'
        expect(key.key_id_hex).to eql 'BA1C17D5D9EB925B'
      end
    end # key0

    context 'keys[1]' do
      let(:key) { keys[1] }
      it 'has expected properties' do
        expect(key.class).to eql RNP::PublicKey
        expect(key.version).to eql 4
        expect(key.creation_time).to eql Time.at(1488299695)
        expect(key.expiration_time).to eql(key.creation_time + (9876 * 86400))
        expect(key.public_key_algorithm).to eql RNP::PublicKeyAlgorithm::RSA
        expect(key.mpi).to eql({
          n: 0xCAF658CEB064FC4F5982A21C0EE10A7EBF6C802CC554A3E4AA247D444E977B6A1425C6BF8131248ECD08E280B7CEABCBE0E9541E43430E98C358BD36D192188DC82F046A4DB060BB122F1C37BB6881D672BBF5F4BF751C0B59D508BDA4DFE0FFD6B2AB039DFC065A4F71776D31A36D5E0B9E9EE88EAAF9CFEAA3E508BF1147DB,
          e: 65537
        })
        expect(key.userids).to eql ['Test User1']
        expect(key.parent).to_not eql nil
        expect(key.subkeys.size).to eql 0
        expect(key.fingerprint_hex).to eql '1AB1A4BC991E9508FF31AA5AA88B68D6573EA665'
        expect(key.key_id_hex).to eql 'A88B68D6573EA665'
       end
    end # key1
   end # pubkey_no_pass.asc

end

