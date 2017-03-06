require 'netpgp'
require 'tempfile'

describe 'SecretKey signing' do

  context 'with seckey_sign_only.asc' do
    let(:keys) { NetPGP::load_keyring(File.read('spec/keys/seckey_sign_only.asc'), true) }
    it { expect(keys.size).to eql 1 }

    let(:key) { keys[0] }
    it 'signs data correctly' do
      data = 'Here is my data.'

      # incorrect passphrase
      key.passphrase = 'wrong'
      signed_data = key.sign(data)
      expect(signed_data).to eql nil

      # correct passphrase
      key.passphrase = 'password'
      signed_data = key.sign(data)
      expect(signed_data).to_not eql nil
      expect(signed_data.class).to eql String

      signed_data = key.sign(data, true, cleartext: true)
      expect(signed_data.include?(data)).to eql true

      signed_data = key.clearsign(data)
      expect(signed_data.include?(data)).to eql true

      # TODO: add verification
    end

    it 'creates detached file signatures correctly' do
      inputfile = nil
      begin
        inputfile = Tempfile.new
        inputfile.write('Here is my data.')
        inputfile.close

        # incorrect passphrase
        key.passphrase = 'wrong'
        expect(
          key.detached_sign(inputfile.path, nil)
        ).to eql false

        # correct passphrase
        key.passphrase = 'password'
        expect(
          key.detached_sign(inputfile.path, nil)
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

