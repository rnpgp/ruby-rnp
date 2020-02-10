# frozen_string_literal: true

# (c) 2020 Ribose Inc.

require 'set'

require 'spec_helper'

describe Rnp.instance_method(:import_keys),
  skip: !LibRnp::HAVE_RNP_IMPORT_KEYS do
  let(:rnp) { Rnp.new }

  it 'successfully imports keys' do
    imported = rnp.import_keys(
      input: Rnp::Input.from_path('spec/data/keys/ecc-p384-pub.asc')
    )
    keys = imported['keys']
    expect(keys.size).to be 2
    expect(rnp.keyids.size).to eql 2
    expect(keys[0]['public']).to eql 'new'
    expect(keys[0]['secret']).to eql 'none'
    expect(keys[0]['fingerprint']).to eql 'ab25cba042dd924c3acc3ed3242a3aa5ea85f44a'
    expect(keys[1]['public']).to eql 'new'
    expect(keys[1]['secret']).to eql 'none'
    expect(keys[1]['fingerprint']).to eql 'cbc2ac55dcd8e4e34fb2f816e210e3d554a4fad9'
  end
end

describe Rnp.instance_method(:import_signatures),
  skip: !LibRnp::HAVE_RNP_IMPORT_SIGNATURES do
  let(:rnp) do
    rnp = Rnp.new
    rnp.load_keys(
      input: Rnp::Input.from_path('spec/data/keys/alice-pub.asc'),
      format: 'GPG'
    )
    rnp
  end
  let(:key) { rnp.find_key(userid: 'Alice <alice@rnp>') }

  it 'successfully imports signatures' do
    expect(key.signatures.size).to be 0
    imported = rnp.import_signatures(
      input: Rnp::Input.from_path('spec/data/keys/alice-rev.pgp')
    )
    expect(key.signatures.size).to be 1
    expect(imported['sigs'].size).to be 1
    sig = imported['sigs'][0]
    expect(sig['public']).to eql 'new'
    expect(sig['secret']).to eql 'unknown key'
    expect(sig['signer fingerprint']).to eql '73edcc9119afc8e2dbbdcde50451409669ffde3c'
  end
end

