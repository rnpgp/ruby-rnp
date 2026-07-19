# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'spec_helper'

describe Rnp::Verify do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = 'password'
    rnp
  end
  let(:key) { rnp.find_key(userid: 'key0-uid1') }

  describe Rnp::Verify.instance_method(:format),
           skip: !LibRnp::HAVE_RNP_OP_VERIFY_GET_FORMAT do
    it 'returns the literal data format for a signed message' do
      signature = rnp.sign(input: Rnp::Input.from_string('data'),
                           signers: [key],
                           armored: false)
      verify = rnp.start_verify(input: Rnp::Input.from_string(signature),
                                output: Rnp::Output.to_null)
      verify.execute
      expect(verify.format).to eql 'b'
    end

    it 'returns the literal data format for an encrypted message' do
      encrypted = rnp.encrypt(input: Rnp::Input.from_string('data'),
                              recipients: [key],
                              armored: false)
      verify = rnp.start_verify(input: Rnp::Input.from_string(encrypted),
                                output: Rnp::Output.to_null)
      verify.execute
      expect(verify.format).to eql 'b'
    end
  end

  describe 'recipient enumeration',
           skip: !LibRnp::HAVE_RNP_OP_VERIFY_GET_RECIPIENT_COUNT do
    let(:encrypted) do
      rnp.encrypt(input: Rnp::Input.from_string('data'),
                  recipients: [key],
                  armored: false)
    end

    it 'enumerates the recipients' do
      verify = rnp.start_verify(input: Rnp::Input.from_string(encrypted),
                                output: Rnp::Output.to_null)
      verify.execute
      recipients = verify.recipients
      expect(recipients.size).to be 1
      expect(recipients[0].keyid).to eql '8A05B89FAD5ADED1'
      expect(recipients[0].alg).to eql 'RSA'
    end

    it 'returns the recipient used to decrypt' do
      verify = rnp.start_verify(input: Rnp::Input.from_string(encrypted),
                                output: Rnp::Output.to_null)
      verify.execute
      expect(verify.used_recipient.keyid).to eql '8A05B89FAD5ADED1'
    end

    it 'returns no recipients for a non-encrypted message' do
      signature = rnp.sign(input: Rnp::Input.from_string('data'),
                           signers: [key],
                           armored: false)
      verify = rnp.start_verify(input: Rnp::Input.from_string(signature),
                                output: Rnp::Output.to_null)
      verify.execute
      expect(verify.recipients).to eql []
      expect(verify.used_recipient).to be_nil
    end
  end

  describe 'symenc enumeration',
           skip: !LibRnp::HAVE_RNP_OP_VERIFY_GET_SYMENC_COUNT do
    let(:encrypted) do
      rnp.symmetric_encrypt(input: Rnp::Input.from_string('data'),
                            passwords: %w[pw0 pw1],
                            armored: false)
    end

    it 'enumerates the password-based entries' do
      verify = rnp.start_verify(input: Rnp::Input.from_string(encrypted),
                                output: Rnp::Output.to_null)
      begin
        verify.execute
      rescue Rnp::Error
        # the password provider does not return a matching password
      end
      symencs = verify.symencs
      expect(symencs.size).to be 2
      symencs.each do |symenc|
        expect(symenc.cipher).to eql 'AES256'
        expect(symenc.aead_alg).to eql 'None'
        expect(symenc.hash_alg).to eql 'SHA256'
        expect(symenc.s2k_type).to eql 'Iterated and salted'
        expect(symenc.s2k_iterations).to be > 0
      end
      expect(verify.used_symenc).to be_nil
    end

    context 'when a password matches' do
      let(:rnp) do
        rnp = Rnp.new
        rnp.password_provider = 'pw1'
        rnp
      end

      it 'returns the symenc entry used to decrypt' do
        verify = rnp.start_verify(input: Rnp::Input.from_string(encrypted),
                                  output: Rnp::Output.to_null)
        verify.execute
        expect(verify.symencs.size).to be 2
        expect(verify.used_symenc.cipher).to eql 'AES256'
      end
    end
  end

  describe Rnp::Verify.instance_method(:flags=),
           skip: !LibRnp::HAVE_RNP_OP_VERIFY_SET_FLAGS do
    let(:encrypted_and_signed) do
      # encrypt with a password (so decryption works without any keys)
      # and sign with a key the verifying instance does not have
      output = Rnp::Output.to_string
      encrypt = rnp.start_encrypt(input: Rnp::Input.from_string('data'),
                                  output: output)
      encrypt.add_password('pw')
      encrypt.add_signer(key)
      encrypt.execute
      output.string
    end

    it 'fails verification with an unknown signer key by default' do
      other = Rnp.new
      other.password_provider = 'pw'
      expect do
        other.verify(input: Rnp::Input.from_string(encrypted_and_signed),
                     output: Rnp::Output.to_null)
      end.to raise_error(Rnp::Error)
    end

    it 'decrypts despite an unknown signer with IGNORE_SIGS_ON_DECRYPT' do
      other = Rnp.new
      other.password_provider = 'pw'
      output = Rnp::Output.to_string
      verify = other.start_verify(input: Rnp::Input.from_string(encrypted_and_signed),
                                  output: output)
      verify.flags = LibRnp::RNP_VERIFY_IGNORE_SIGS_ON_DECRYPT
      expect { verify.execute }.to_not raise_error
      expect(output.string).to eql 'data'
    end
  end
end
