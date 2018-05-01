# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'json'

require 'spec_helper'

describe Rnp::Key do
  context '1ED63EE56FADC34D' do
    context 'when loading a protected key' do
      before do
        @rnp = Rnp.new
        @rnp.load_keys(format: 'GPG',
                       input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
        @rnp.load_keys(format: 'GPG',
                       input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
      end
      let(:key) { @rnp.find_key(keyid: '1ED63EE56FADC34D') }

      it 'responds to inspect' do
        expect(key.class.instance_methods(false).include?(:inspect)).to be true
        expect(key.inspect.class).to eql String
        expect(key.inspect.length).to be >= 1
      end

      it 'responds to to_s' do
        expect(key.class.instance_methods(false).include?(:to_s)).to be true
        expect(key.to_s.class).to eql String
        expect(key.to_s.length).to be >= 1
      end

      it 'is protected' do
        expect(key.protected?).to be true
      end

      it 'is locked' do
        expect(key.locked?).to be true
      end

      context 'with no pass provider' do
        it 'fails to unlock' do
          expect { key.unlock }.to raise_error(Rnp::BadPasswordError)
          expect(key.locked?).to be true
        end

        it 'fails to unprotect' do
          expect { key.unprotect }.to raise_error(Rnp::BadPasswordError)
          expect(key.protected?).to be true
        end

        context 'when directly provided a bad pass' do
          it 'fails to unlock' do
            expect { key.unlock('badpass') }.to raise_error(Rnp::BadPasswordError)
            expect(key.locked?).to be true
          end

          it 'fails to unprotect' do
            expect { key.unprotect('badpass') }.to raise_error(Rnp::BadPasswordError)
            expect(key.protected?).to be true
          end
        end # when directly provided a bad password
      end # with no pass provider

      context 'with a bad (string) pass provider' do
        before do
          @rnp.password_provider = 'badpass'
        end

        it 'fails to unlock' do
          expect { key.unlock }.to raise_error(Rnp::BadPasswordError)
          expect(key.locked?).to be true
        end

        it 'fails to unprotect' do
          expect { key.unprotect }.to raise_error(Rnp::BadPasswordError)
          expect(key.protected?).to be true
        end
      end # with a bad (string) pass provider

      context 'with a bad (proc) pass provider' do
        before do
          @rnp.password_provider = proc { next 'badpass' }
        end

        it 'fails to unlock' do
          expect { key.unlock }.to raise_error(Rnp::BadPasswordError)
          expect(key.locked?).to be true
        end

        it 'fails to unprotect' do
          expect { key.unprotect }.to raise_error(Rnp::BadPasswordError)
          expect(key.protected?).to be true
        end

        context 'when directly provided the correct pass' do
          it 'unlocks' do
            key.unlock('password')
            expect(key.locked?).to be false
          end

          it 'remains protected after unlocking' do
            key.unlock('password')
            expect(key.protected?).to be true
          end

          it 'unprotects' do
            key.unprotect('password')
            expect(key.protected?).to be false
          end

          it 'remains locked after unprotecting' do
            key.unprotect('password')
            expect(key.locked?).to be true
          end
        end # when directly provided the correct pass
      end # with a bad (proc) pass provider
    end # when loading a protected key

    context 'when loading an unprotected key' do
      before do
        rnp = Rnp.new
        rnp.load_keys(format: 'GPG',
                      input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
        key = rnp.find_key(keyid: '7BC6709B15C23A4A')
        key.unprotect('password')
        secret_key_data = key.secret_key_data

        @rnp = Rnp.new
        @rnp.load_keys(format: 'GPG', input: Rnp::Input.from_string(secret_key_data))
      end
      let(:key) { @rnp.find_key(keyid: '7BC6709B15C23A4A') }

      it 'is not protected' do
        expect(key.protected?).to be false
      end

      it 'is not locked' do
        expect(key.locked?).to be false
      end

      context 'with no pass provider' do
        it 'can sign' do
          signature = @rnp.sign(signers: key, input: Rnp::Input.from_string('test'))
          output = Rnp::Output.to_string
          @rnp.verify(input: Rnp::Input.from_string(signature), output: output)
          expect(output.string).to eql 'test'
        end
      end # with no pass provider

      it 'can be locked' do
        expect(key.locked?).to be false
        key.lock
        expect(key.locked?).to be true
      end

      it 'can be protected' do
        expect(key.protected?).to be false
        key.protect('newpass')
        expect(key.protected?).to be true
      end
    end # when loading an unprotected key
  end # 1ED63EE56FADC34D
end # Key

