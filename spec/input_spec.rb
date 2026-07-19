# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'tempfile'

require 'spec_helper'

describe Rnp::Input do
  describe Rnp::Input.method(:from_stdin),
           skip: !LibRnp::HAVE_RNP_INPUT_FROM_STDIN do
    it 'reads from the standard input' do
      Tempfile.create('ruby-rnp-stdin') do |file|
        file.write('stdin data')
        file.flush
        orig = $stdin.dup
        begin
          $stdin.reopen(file.path, 'r')
          input = Rnp::Input.from_stdin
          output = Rnp::Output.to_string
          output.pipe_from(input)
          expect(output.string).to eql 'stdin data'
        ensure
          $stdin.reopen(orig)
          orig.close
        end
      end
    end
  end
end
