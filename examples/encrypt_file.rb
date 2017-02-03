#!/usr/bin/env ruby
require 'optparse'

require_relative '../lib/netpgp'

options = {armored: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <pubkey> <input-file> <output-file>"
  opts.on('-k', '--keys-armored', 'Seckey is ASCII armored') do
    options[:keys_armored] = true
  end
  opts.on('-a', '--armored', 'Output file will be ASCII armored') do |a|
    options[:armored] = a
  end
  opts.on('-h', '--help', 'Print this help') do
    puts opts
    exit
  end
end
parser.parse!

if ARGV.length != 3
  parser.display
  exit
end

pubkey_filename = ARGV.shift
input_filename = ARGV.shift
output_filename = ARGV.shift

# Load keys/keyring
keyring_mem = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
keyring = LibNetPGP::PGPKeyring.new(keyring_mem)
if 1 != LibNetPGP::pgp_keyring_fileread(keyring, options[:keys_armored] ? 1 : 0, pubkey_filename)
  puts 'Errors encountered while loading keyring.'
  exit 1
end
# Find first pubkey
keycount = LibNetPGP::dynarray_count(keyring, 'key')
pubkey = nil
(0..keycount - 1).each {|keyn|
  key = LibNetPGP::dynarray_get_item(keyring, 'key', LibNetPGP::PGPKey, keyn)
  pubkey = key if LibNetPGP::pgp_is_key_secret(key) == 0
  break if pubkey != nil
}
if pubkey == nil
  puts 'No pubkey found'
  exit 1
end

pgpio = LibNetPGP::PGPIO.new
stdout_fp = LibC::fdopen($stdout.to_i, 'w')
stderr_fp = LibC::fdopen($stderr.to_i, 'w')
pgpio[:outs] = stdout_fp
pgpio[:errs] = stderr_fp
pgpio[:res] = stdout_fp

armored = options[:armored] ? 1 : 0
overwrite = 1
# see pgp_str_to_cipher
cipher = 'cast5'
ret = LibNetPGP::pgp_encrypt_file(pgpio, input_filename, output_filename, pubkey, armored, overwrite, cipher)
if ret == 1
  puts 'Success'
else
  puts 'Failed!'
end

