# frozen_string_literal: true

# (c) 2018,2019 Ribose Inc.

require 'set'

require 'spec_helper'

describe Rnp do
  it 'has a version number' do
    expect(Rnp::VERSION).not_to be nil
  end

  it 'responds to inspect' do
    rnp = Rnp.new
    expect(rnp.class.instance_methods(false).include?(:inspect)).to be true
    expect(rnp.inspect.class).to eql String
    expect(rnp.inspect.length).to be >= 1
  end

  describe Rnp.instance_method(:public_key_count) do
    let(:rnp) { Rnp.new }

    it 'is 0 before loading any keys' do
      expect(rnp.public_key_count).to be 0
    end

    it 'has the expected value after loading keys' do
      rnp.load_keys(
        format: 'GPG',
        input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'),
        public_keys: true,
        secret_keys: false
      )
      expect(rnp.public_key_count).to be 7
    end
  end

  describe Rnp.instance_method(:secret_key_count) do
    let(:rnp) { Rnp.new }

    it 'is 0 before loading any keys' do
      expect(rnp.secret_key_count).to be 0
    end

    it 'has the expected value after loading keys' do
      rnp.load_keys(
        format: 'GPG',
        input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'),
        public_keys: false,
        secret_keys: true
      )
      expect(rnp.secret_key_count).to be 7
    end
  end

  describe Rnp.instance_method(:find_key) do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp
    end

    it 'returns nil for keys that do not exist' do
      expect(rnp.find_key(userid: 'noexist')).to eql nil
    end

    it 'raises an error for invalid search criteria' do
      expect { rnp.find_key(badid: 'noexist') }.to raise_error(Rnp::Error)
    end

    it 'finds keys by userid' do
      expect(rnp.find_key(userid: 'key0-uid2').class).to eql Rnp::Key
    end

    it 'finds keys by keyid' do
      expect(rnp.find_key(keyid: '8A05B89FAD5ADED1').class).to eql Rnp::Key
    end

    it 'finds keys by fingerprint' do
      key = rnp.find_key(
        fingerprint: 'BE1C4AB951F4C2F6B604C7F82FCADF05FFA501BB'
      )
      expect(key.class).to eql Rnp::Key
      expect(key.keyid).to eql '2FCADF05FFA501BB'
    end
  end

  describe Rnp.instance_method(:load_keys) do
    it 'loads only public keys when specified' do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'),
                    public_keys: true, secret_keys: false)
      expect(rnp.keyids.size).to be 7
    end

    it 'loads only secret keys when specified' do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'),
                    public_keys: false, secret_keys: true)
      expect(rnp.keyids.size).to be 0
    end

    it 'loads all keys when specified' do
      rnp = Rnp.new
      # pub
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'),
                    public_keys: true, secret_keys: true)
      expect(rnp.keyids.size).to be 7
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be true
        expect(key.secret_key_present?).to be false
      end
      # sec
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'),
                    public_keys: true, secret_keys: true)
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be true
        expect(key.secret_key_present?).to be true
      end
    end
  end # load_keys

  describe Rnp.instance_method(:unload_keys),
           skip: !LibRnp::HAVE_RNP_UNLOAD_KEYS do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(
        format: "GPG",
        input: Rnp::Input.from_path("spec/data/keyrings/gpg/secring.gpg"),
        public_keys: true, secret_keys: true
      )
      expect(rnp.keyids.size).to be 7
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be true
        expect(key.secret_key_present?).to be true
      end
      rnp
    end

    it "unloads only public keys when specified" do
      rnp.unload_keys(public_keys: true, secret_keys: false)
      expect(rnp.keyids.size).to be 7
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be false
        expect(key.secret_key_present?).to be true
      end
    end

    it "unloads only secret keys when specified" do
      rnp.unload_keys(public_keys: false, secret_keys: true)
      expect(rnp.keyids.size).to be 7
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be true
        expect(key.secret_key_present?).to be false
      end
    end

    it "unloads all keys when specified" do
      rnp.unload_keys
      expect(rnp.keyids.size).to be 0
    end
  end

  describe Rnp.instance_method(:save_keys) do
    it 'saves only public keys when specified' do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))

      output = Rnp::Output.to_string
      rnp.save_keys(format: 'GPG',
                    output: output,
                    public_keys: true, secret_keys: false)
      saved = output.string
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_string(saved),
                    public_keys: true, secret_keys: true)
      expect(rnp.keyids.size).to eql 7
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be true
        expect(key.secret_key_present?).to be false
      end
    end

    it 'saves only secret keys when specified' do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))

      output = Rnp::Output.to_string
      rnp.save_keys(format: 'GPG',
                    output: output,
                    public_keys: false, secret_keys: true)
      saved = output.string
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_string(saved),
                    public_keys: true, secret_keys: true)
      expect(rnp.keyids.size).to eql 7
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be true
        expect(key.secret_key_present?).to be true
      end
    end

    it 'saves all keys when specified' do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/secring.gpg'))

      output = Rnp::Output.to_string
      rnp.save_keys(format: 'GPG',
                    output: output,
                    public_keys: true, secret_keys: true)
      saved = output.string
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_string(saved),
                    public_keys: true, secret_keys: true)
      expect(rnp.keyids.size).to eql 7
      rnp.keyids.each do |keyid|
        key = rnp.find_key(keyid: keyid)
        expect(key.public_key_present?).to be true
        expect(key.secret_key_present?).to be true
      end
    end
  end # save_keys

  describe Rnp.instance_method(:userids) do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp
    end
    let(:expected) do
      Set.new(%w[key0-uid0 key0-uid1 key0-uid2 key1-uid0 key1-uid1 key1-uid2])
    end

    it 'has the expected count' do
      expect(rnp.userids.size).to eql 6
    end

    it 'contains the expected values' do
      expect(Set.new(rnp.userids)).to eql expected
    end

    describe Rnp.instance_method(:each_userid) do
      it 'returns an enumerator if not given a block' do
        expect(rnp.each_userid.class).to eql Enumerator
        expect(Set.new(rnp.each_userid.to_a)).to eql expected
      end

      it 'correctly yields when given a block' do
        uids = Set.new
        rnp.each_userid { |userid| uids << userid }
        expect(uids).to eql expected
      end
    end # each_userid
  end # userids

  describe Rnp.instance_method(:keyids) do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp
    end
    let(:expected) do
      Set.new(%w[7BC6709B15C23A4A 1ED63EE56FADC34D 1D7E8A5393C997A8
                 8A05B89FAD5ADED1 2FCADF05FFA501BB 54505A936A4A970E
                 326EF111425D14A5])
    end

    it 'has the expected count' do
      expect(rnp.keyids.size).to eql 7
    end

    it 'contains the expected values' do
      expect(Set.new(rnp.keyids)).to eql expected
    end

    describe Rnp.instance_method(:each_keyid) do
      it 'returns an enumerator if not given a block' do
        expect(rnp.each_keyid.class).to eql Enumerator
        expect(Set.new(rnp.each_keyid.to_a)).to eql expected
      end

      it 'correctly yields when given a block' do
        keyids = Set.new
        rnp.each_keyid { |keyid| keyids << keyid }
        expect(keyids).to eql expected
      end
    end # each_keyid
  end # keyids

  describe Rnp.instance_method(:fingerprints) do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp
    end
    let(:expected) do
      Set.new(%w[e95a3cbf583aa80a2ccc53aa7bc6709b15c23a4a
                 e332b27caf4742a11baa677f1ed63ee56fadc34d
                 c5b15209940a7816a7af3fb51d7e8a5393c997a8
                 5cd46d2a0bd0b8cfe0b130ae8a05b89fad5aded1
                 be1c4ab951f4c2f6b604c7f82fcadf05ffa501bb
                 a3e94de61a8cb229413d348e54505a936a4a970e
                 57f8ed6e5c197db63c60ffaf326ef111425d14a5].map(&:upcase))
    end

    it 'has the expected count' do
      expect(rnp.fingerprints.size).to eql 7
    end

    it 'contains the expected values' do
      expect(Set.new(rnp.fingerprints)).to eql expected
    end

    describe Rnp.instance_method(:each_fingerprint) do
      it 'returns an enumerator if not given a block' do
        expect(rnp.each_fingerprint.class).to eql Enumerator
        expect(Set.new(rnp.each_fingerprint.to_a)).to eql expected
      end

      it 'correctly yields when given a block' do
        fingerprints = Set.new
        rnp.each_fingerprint { |fpr| fingerprints << fpr }
        expect(fingerprints).to eql expected
      end
    end # each_fingerprint
  end # fingerprints

  describe Rnp.instance_method(:grips) do
    let(:rnp) do
      rnp = Rnp.new
      rnp.load_keys(format: 'GPG',
                    input: Rnp::Input.from_path('spec/data/keyrings/gpg/pubring.gpg'))
      rnp
    end

    it 'has the expected count' do
      expect(rnp.fingerprints.size).to eql 7
    end

    it 'contains the expected values' do
      # TODO: pending RNP #540
    end
  end # grips

  describe Rnp.instance_method(:generate_key) do
    describe 'generating a lone primary' do
      before do
        @rnp = Rnp.new
        @generated = @rnp.generate_key(
          primary: {
            type: 'ECDSA',
            curve: 'NIST P-256',
            userid: 'testuser',
            usage: ['sign']
          }
        )
        @key = @generated[:primary]
        @json = @key.json
      end

      it 'only generated a single key' do
        expect(@generated.size).to be 1
      end

      it 'has the correct type' do
        expect(@json['type']).to eql 'ECDSA'
      end

      it 'has the correct curve' do
        expect(@json['curve']).to eql 'NIST P-256'
      end

      it 'has the correct creation time' do
        expect(Time.now.to_i - @json['creation time']).to be <= 30.0
      end

      it 'has the correct usage' do
        expect(@json['usage']).to eql ['sign']
      end

      it 'has both public and secret parts' do
        expect(@key.public_key_present?).to be true
        expect(@key.secret_key_present?).to be true
      end

      it 'has the correct userid' do
        expect(@key.primary_userid).to eql 'testuser'
      end
    end
  end # generate_key
end

