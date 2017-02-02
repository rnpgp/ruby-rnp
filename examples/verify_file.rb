#!/usr/bin/env ruby
require 'optparse'
require 'io/console'

require_relative '../lib/netpgp'

options = {keys_armored: false, armored: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <pubkey> <input-file>"
  opts.on('-k', '--keys-armored', 'Pubkey is ASCII armored') do
    options[:keys_armored] = true
  end
  opts.on('-a', '--armored', 'Input file is ASCII armored') do
    options[:armored] = true
  end
  opts.on('-h', '--help', 'Print this help') do
    puts opts
    exit
  end
end
parser.parse!

if ARGV.length != 2
  parser.display
  exit
end

pubkey_filename = ARGV.shift
input_filename = ARGV.shift

# Load keys/keyring
keyring_mem = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
keyring = LibNetPGP::PGPKeyring.new(keyring_mem)
if 1 != LibNetPGP::pgp_keyring_fileread(keyring, options[:keys_armored] ? 1 : 0, pubkey_filename)
  puts 'Errors encountered while loading keyring.'
  exit 1
end

pgpio = LibNetPGP::PGPIO.new
stdout_fp = LibC::fdopen($stdout.to_i, 'w')
stderr_fp = LibC::fdopen($stderr.to_i, 'w')
pgpio[:outs] = stdout_fp
pgpio[:errs] = stderr_fp
pgpio[:res] = stdout_fp

armored = options[:output_armored] ? 1 : 0

validation = LibNetPGP::PGPValidation.new
ret = LibNetPGP::pgp_validate_file(pgpio, validation, input_filename, nil, armored, keyring)
if ret == 1
  puts 'Success'
else
  puts 'Failed!'
end

