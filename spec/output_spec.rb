# frozen_string_literal: true

# (c) 2020 Ribose Inc.

require 'json'

require 'spec_helper'

describe Rnp::Output.instance_method(:write),
         skip: !LibRnp::HAVE_RNP_OUTPUT_WRITE do
  let(:output) { Rnp::Output.to_string }

  it 'returns the correct number of bytes' do
    expect(output.write('12345')).to eql 5
  end

  it 'produces the correct output' do
    output.write('12345')
    expect(output.string).to eql '12345'
  end

  it 'accepts multiple args' do
    expect(output.write('12345', '67890', 'abcde')).to eql 15
    expect(output.string).to eql '1234567890abcde'
  end
end
