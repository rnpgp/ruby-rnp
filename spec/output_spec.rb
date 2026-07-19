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

describe Rnp::Output.method(:to_armor),
         skip: !LibRnp::HAVE_RNP_OUTPUT_TO_ARMOR do
  it 'armors the data written to it' do
    base = Rnp::Output.to_string
    armored = Rnp::Output.to_armor(base, 'message')
    armored.write('my data')
    armored.finish
    expect(base.string.start_with?("-----BEGIN PGP MESSAGE-----\r\n")).to be true
    expect(base.string.end_with?("-----END PGP MESSAGE-----\r\n")).to be true
  end

  it 'survives garbage collection in any finalization order' do
    # the armored output must be finalized before its base output
    # (regression test for a use-after-free)
    200.times do
      base = Rnp::Output.to_string
      armored = Rnp::Output.to_armor(base, 'message')
      armored.write('x' * 100)
      armored.finish
    end
    GC.start
  end

  it 'keeps the base output usable after the armored one is finalized' do
    base = Rnp::Output.to_string
    armored = Rnp::Output.to_armor(base, 'message')
    armored.write('my data')
    armored.finish
    text = base.string
    armored = nil
    GC.start
    expect(base.string).to eql text
  end

  describe Rnp::Output.instance_method(:armor_line_length=),
           skip: !LibRnp::HAVE_RNP_OUTPUT_ARMOR_SET_LINE_LENGTH do
    it 'sets the line length' do
      base = Rnp::Output.to_string
      armored = Rnp::Output.to_armor(base, 'message')
      armored.armor_line_length = 24
      armored.write('x' * 100)
      armored.finish
      payload = base.string.lines.reject do |line|
        line.start_with?('-----') || line.strip.empty?
      end
      expect(payload.map { |line| line.chomp.size }.max).to be <= 24
    end

    it 'raises an error for a non-armor output' do
      expect do
        Rnp::Output.to_string.armor_line_length = 24
      end.to raise_error(Rnp::Error)
    end
  end
end
