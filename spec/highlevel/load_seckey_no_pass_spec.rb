require 'netpgp'

describe NetPGP.method(:load_keyring) do

  context 'when loading seckey_no_pass.asc' do
    let(:keys) { NetPGP::load_keyring(File.read('spec/keys/seckey_no_pass.asc'), true) }
    it { expect(keys.size).to eql 2 }

    context 'keys[0]' do
      let(:key) { keys[0] }
      it 'has expected properties' do
        expect(key.class).to eql NetPGP::SecretKey

        expect(key.public_key.class).to eql NetPGP::PublicKey
        expect(key.public_key.version).to eql 4
        expect(key.public_key.creation_time).to eql Time.at(1488299695)
        expect(key.public_key.expiration_time).to eql(key.public_key.creation_time + (9876 * 86400))
        expect(key.public_key.public_key_algorithm).to eql NetPGP::PublicKeyAlgorithm::RSA
        expect(key.public_key.mpi).to eql({
          n: 0xC9C8091AFFE483815AD036A686EE026600298523AB527D8C82A39ABDF94E968BD2FF87DFF6EAAD3486E09C497EA1291A7A00085324ACE6DF7378F2C61BB713D24CEF52CD14A9DF54219DF4CFAB2FC2AD570EE945FED2009789035A4A3809CA56FA77027B9E995DC2F326F6DF60797D40558E3CB9CA53869F620A425F3768FAF5,
          e: 65537
        })
        expect(key.public_key.userids).to eql []
        expect(key.public_key.parent).to eql nil
        expect(key.public_key.subkeys.size).to eql 0
        expect(key.public_key.fingerprint_hex).to eql '03CFD3CA3EB8F34A713BBFCCBA1C17D5D9EB925B'
        expect(key.public_key.key_id_hex).to eql 'BA1C17D5D9EB925B'
 
        expect(key.expiration_time).to eql(key.creation_time + (9876 * 86400))
        expect(key.string_to_key_usage).to eql NetPGP::StringToKeyUsage::NONE
        expect(key.string_to_key_specifier).to eql NetPGP::StringToKeySpecifier::SIMPLE
        expect(key.symmetric_key_algorithm).to eql NetPGP::SymmetricKeyAlgorithm::PLAINTEXT
        expect(key.hash_algorithm).to eql NetPGP::HashAlgorithm::SHA1
        expect(key.mpi).to eql({
          d: 0xB625B4D2829CAD795F99053C5E210C59375C43AB674417C1774C68AB8519C41C8463D72BFDA0EAA9B7F79A1D5E09ED28D168A61B27C84CC0F963FD0388914379C15373FB1EFFAC9A3C7587364B49D489410FBF25E07ADFC6D495C96C02D4D357CC944AF3578B8446916286C9363A4E3A486239C81CA959D40419C9C083CA383,
          p: 0xE2E655B8DEDDAB9EA05026A7560A287CB805EC047B4502F8786EBA44B97D670C883D1466FDD25809813547765E4E849D090582F0064BC62361DF626C8765773B,
          q: 0xE3A9012B879F5B2A4D3472F50D73D6F73C296CE8C1457805EE383424DFDB1DF730B61B53EEFC0186CF2186C980706548ACD26228EFF444BC899C420B9F86138F,
          u: 0x8A35D2BB43479347DB2E6870BBAD8F0205422BE2EC7CF8D81CA6C6A1FF6CB911E64FABC1AE35EAF7D6880260F6CE59507B9C326CACFA3839138E1CAA9BA0F7D2
        })
        expect(key.userids).to eql ['Test User1']
        expect(key.parent).to eql nil
        expect(key.subkeys.size).to eql 1
        expect(key.raw_subpackets.size).to eql 3
        expect(key.encrypted).to eql false
       end
    end # key0

    context 'keys[1]' do
      let(:key) { keys[1] }
      it 'has expected properties' do
        expect(key.class).to eql NetPGP::SecretKey
        expect(key.public_key.class).to eql NetPGP::PublicKey
        expect(key.public_key.version).to eql 4
        expect(key.public_key.creation_time).to eql Time.at(1488299695)
        expect(key.public_key.expiration_time).to eql(key.public_key.creation_time + (9876 * 86400))
        expect(key.public_key.public_key_algorithm).to eql NetPGP::PublicKeyAlgorithm::RSA
        expect(key.public_key.mpi).to eql({
          n: 0xCAF658CEB064FC4F5982A21C0EE10A7EBF6C802CC554A3E4AA247D444E977B6A1425C6BF8131248ECD08E280B7CEABCBE0E9541E43430E98C358BD36D192188DC82F046A4DB060BB122F1C37BB6881D672BBF5F4BF751C0B59D508BDA4DFE0FFD6B2AB039DFC065A4F71776D31A36D5E0B9E9EE88EAAF9CFEAA3E508BF1147DB,
          e: 65537
        })
        expect(key.public_key.userids).to eql []
        expect(key.public_key.parent).to eql nil
        expect(key.public_key.subkeys.size).to eql 0
        expect(key.public_key.fingerprint_hex).to eql '1AB1A4BC991E9508FF31AA5AA88B68D6573EA665'
        expect(key.public_key.key_id_hex).to eql 'A88B68D6573EA665'
 
        expect(key.expiration_time).to eql(key.creation_time + (9876 * 86400))
        expect(key.string_to_key_usage).to eql NetPGP::StringToKeyUsage::NONE
        expect(key.string_to_key_specifier).to eql NetPGP::StringToKeySpecifier::SIMPLE
        expect(key.symmetric_key_algorithm).to eql NetPGP::SymmetricKeyAlgorithm::PLAINTEXT
        expect(key.hash_algorithm).to eql NetPGP::HashAlgorithm::SHA1
        expect(key.mpi).to eql({
          d: 0x13BC92F43E7903841FDB3132734BF4FE505517BDC2CEB1455A3A442831504FC3080488683502F7601F961E988FC73C338E4282589307E1527FA49079D53554C7C078E363167829339505981C8EAE2E91C5C885228204933B5EE2E371471431223EC797AE0B865BD0522DB625172F840ADF06054DD39CED87667570B27055DEE9,
          p: 0xDEFEDB1632B467545CA28105DEE8FEA28A24A28335571B22F6B103C4C5C032FA7529253C5A1FD4655A528B5C0BB51A628CFDC832C2BB4CB38E0D475A7C56C94D,
          q: 0xE900721DD79C2EEAD14C9C64CDF79BF2F0BBD7E190E70AABCE956794DE6C088BA17E5645C020D4C6CD97BD283131B8275B676C634070030F6D77470A3F5781C7,
          u: 0x36604C0166991CFCC63C3EFB711C169B0D0A239D47FEF10C3A241D9E53BD77C3EB0A434C709FE2C6E2935331696ADDCF0D88E0F8D345559672F5E296095819A3
        })
        expect(key.userids).to eql []
        expect(key.parent).to eql keys[0]
        expect(key.subkeys.size).to eql 0
        expect(key.raw_subpackets.size).to eql 2
        expect(key.encrypted).to eql false
       end
    end # key1

   end # seckey_no_pass.asc

end

