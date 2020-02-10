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

