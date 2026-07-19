# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'spec_helper'

describe 'security profile' do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(format: 'GPG',
                  input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))
    rnp.password_provider = 'password'
    rnp
  end

  describe Rnp.instance_method(:security_rule),
           skip: !LibRnp::HAVE_RNP_GET_SECURITY_RULE do
    it 'returns the default rule for a hash algorithm' do
      # SHA1 data signatures are marked insecure since 2019-01-19 by
      # the default security profile
      rule = rnp.security_rule(type: 'hash algorithm', name: 'SHA1',
                               time: 1_700_000_000, usage: :data)
      expect(rule[:level]).to eql LibRnp::RNP_SECURITY_INSECURE
      expect(rule[:from]).to eql 1_547_856_000
    end

    it 'falls back to the default level when there is no matching rule' do
      rule = rnp.security_rule(type: 'hash algorithm', name: 'SHA256',
                               time: 1_700_000_000)
      expect(rule[:level]).to eql LibRnp::RNP_SECURITY_DEFAULT
      expect(rule[:from]).to eql 0
    end

    it 'raises an error on an unknown feature name' do
      expect do
        rnp.security_rule(type: 'hash algorithm', name: 'FAKE')
      end.to raise_error(Rnp::Error)
    end
  end

  describe 'security rule allow/deny roundtrip',
           skip: !LibRnp::HAVE_RNP_ADD_SECURITY_RULE do
    let(:sha1_signature) do
      rnp.detached_sign(input: Rnp::Input.from_string('data'),
                        signers: [rnp.find_key(userid: 'key0-uid1')],
                        hash: 'SHA1',
                        armored: false)
    end

    def verify(signature)
      verify = rnp.start_detached_verify(
        data: Rnp::Input.from_string('data'),
        signature: Rnp::Input.from_string(signature)
      )
      verify.execute
    end

    it 'rejects SHA1 signatures, allows them with an override rule, and rejects again after removal' do
      # the default profile marks SHA1 data signatures as insecure
      expect { verify(sha1_signature) }
        .to raise_error(Rnp::InvalidSignatureError)

      # add an overriding rule, allowing SHA1
      rnp.add_security_rule(type: 'hash algorithm', name: 'SHA1',
                            level: :default, override: true)
      expect { verify(sha1_signature) }.to_not raise_error

      # remove the overriding rule, restoring the default behavior
      removed = rnp.remove_security_rule(type: 'hash algorithm',
                                         name: 'SHA1',
                                         level: :default,
                                         override: true)
      expect(removed).to be 1
      expect { verify(sha1_signature) }
        .to raise_error(Rnp::InvalidSignatureError)
    end

    it 'reports the added rule via security_rule' do
      from = Time.at(1_600_000_000)
      rnp.add_security_rule(type: 'hash algorithm', name: 'SHA512',
                            level: :insecure, from: from)
      rule = rnp.security_rule(type: 'hash algorithm', name: 'SHA512',
                               time: 1_700_000_000)
      expect(rule[:level]).to eql LibRnp::RNP_SECURITY_INSECURE
      expect(rule[:from]).to eql 1_600_000_000
    end

    it 'rejects an invalid level' do
      expect do
        rnp.add_security_rule(type: 'hash algorithm', name: 'SHA1',
                              level: :bogus)
      end.to raise_error(ArgumentError)
    end

    it 'rejects an invalid usage' do
      expect do
        rnp.add_security_rule(type: 'hash algorithm', name: 'SHA1',
                              level: :default, usage: :bogus)
      end.to raise_error(ArgumentError)
    end
  end

  describe Rnp.instance_method(:timestamp=),
           skip: !LibRnp::HAVE_RNP_SET_TIMESTAMP do
    it 'uses the timestamp as the creation time for generated keys' do
      stamp = 1_500_000_000
      rnp.timestamp = stamp
      op = rnp.start_generate(type: 'RSA')
      op.bits = 1024
      op.userid = 'timestamped'
      op.execute
      expect(op.key.creation_time.to_i).to eql stamp
      rnp.timestamp = 0
    end
  end
end
