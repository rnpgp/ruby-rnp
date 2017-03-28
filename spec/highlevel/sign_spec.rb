require 'rnp'
require 'tempfile'

describe 'SecretKey signing' do

  context 'with seckey_sign_only.asc' do
    let(:pubring) { RNP::Keyring.load(File.read('spec/keys/pubkey_sign_only.asc')) }
    let(:secring) { RNP::Keyring.load(File.read('spec/keys/seckey_sign_only.asc')) }

    it { expect(pubring.size).to eql 1 }
    it { expect(pubring.public_keys.size).to eql 1 }
    it { expect(secring.size).to eql 1 }
    it { expect(secring.secret_keys.size).to eql 1 }

    let(:seckey) { secring[0] }
    let(:pubkey) { pubring[0] }
    it 'signs data correctly' do
      data = 'Here is my data.'

      # incorrect passphrase
      seckey.passphrase = 'wrong'
      signed_data = seckey.sign(data)
      expect(signed_data).to eql nil

      # correct passphrase
      seckey.passphrase = 'password'
      signed_data = seckey.sign(data)
      expect(signed_data).to_not eql nil
      expect(signed_data.class).to eql String
      expect(pubkey.verify(signed_data)).to eql true
      # tamper with the data
      signed_data[signed_data.size / 2] = (signed_data[signed_data.size / 2].ord + 1).chr
      expect(pubkey.verify(signed_data)).to eql false

      # cleartext signature
      signed_data = seckey.sign(data, true, cleartext: true)
      expect(signed_data.include?(data)).to eql true
      expect(pubkey.verify(signed_data)).to eql true

      # cleartext signature (shortcut)
      signed_data = seckey.clearsign(data)
      expect(signed_data.include?(data)).to eql true
      expect(pubkey.verify(signed_data)).to eql true
    end

    it 'creates detached file signatures correctly' do
      inputfile = nil
      begin
        inputfile = Tempfile.new
        inputfile.write('Here is my data.')
        inputfile.close

        # incorrect passphrase
        seckey.passphrase = 'wrong'
        expect(
          seckey.detached_sign(inputfile.path, nil)
        ).to eql false

        # correct passphrase
        seckey.passphrase = 'password'
        expect(
          seckey.detached_sign(inputfile.path, nil)
        ).to eql true
        expect(
          File.exists?(inputfile.path + '.asc')
        ).to eql true 

        # TODO: add verification
      ensure
        if inputfile != nil
          File.unlink(inputfile.path + '.asc')
          inputfile.close
          inputfile.unlink
        end
      end
    end

  end # seckey_sign_only.asc

end

