#!/usr/bin/env ruby
require 'optparse'
require 'io/console'

require_relative '../../lib/rnp'

options = {keys_armored: false, cleartext: false, output_armored: false, detached: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <seckey> <input-file> <output-file>"
  opts.on('-k', '--keys-armored', 'Seckey is ASCII armored') do
    options[:keys_armored] = true
  end
  opts.on('-c', '--clear-sign', 'Cleartext signature') do
    options[:cleartext] = true
  end
  opts.on('-a', '--armored', 'Output file will be ASCII armored') do
    options[:output_armored] = true
  end
  opts.on('-d', '--detached', 'Detached signature') do
    options[:detached] = true
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

seckey_filename = ARGV.shift
input_filename = ARGV.shift
output_filename = ARGV.shift

# Load keys/keyring
keyring_mem = LibC::calloc(1, LibRNP::PGPKeyring.size)
keyring = LibRNP::PGPKeyring.new(keyring_mem)
if 1 != LibRNP::pgp_keyring_fileread(keyring, options[:keys_armored] ? 1 : 0, seckey_filename)
  puts 'Errors encountered while loading keyring.'
  exit 1
end
# Find first seckey
keycount = LibRNP::dynarray_count(keyring, 'key')
seckey = nil
(0..keycount - 1).each {|keyn|
  key = LibRNP::dynarray_get_item(keyring, 'key', LibRNP::PGPKey, keyn)
  seckey = key if LibRNP::pgp_is_key_secret(key)
  break if seckey != nil
}
if seckey == nil
  puts 'No seckey found'
  exit 1
end

'''
This is a bit convoluted because pgp_decrypt_seckey expects a FILE*.
It may be cleaner to reimplement the short pgp_decrypt_seckey function
in ruby as it does not do a lot.
'''
rd, wr = IO.pipe
print 'Enter passphrase: '
passphrase = $stdin.noecho(&:gets)
puts ''
wr.write passphrase
wr.close
passfp = LibC::fdopen(rd.to_i, 'r')
seckey = LibRNP::pgp_decrypt_seckey(seckey, passfp)
rd.close
LibC::fclose(passfp)

if seckey == nil
  puts 'Invalid passphrase.'
  exit 1
end
seckey = LibRNP::PGPSecKey.new(seckey)

pgpio = LibRNP::PGPIO.new
stdout_fp = LibC::fdopen($stdout.to_i, 'w')
stderr_fp = LibC::fdopen($stderr.to_i, 'w')
pgpio[:outs] = stdout_fp
pgpio[:errs] = stderr_fp
pgpio[:res] = stdout_fp

overwrite = 1
from = Time.now.to_i
duration = 0
armored = options[:output_armored] ? 1 : 0

# see pgp_str_to_hash_alg
hashname = 'sha1'
if options[:detached]
  ret = LibRNP::pgp_sign_detached(pgpio, input_filename, output_filename, seckey, hashname, from, duration, armored, overwrite)
else
  cleartext = options[:cleartext] ? 1 : 0
  ret = LibRNP::pgp_sign_file(pgpio, input_filename, output_filename, seckey, hashname, from, duration, armored, cleartext, overwrite)
end
if ret == 1
  puts 'Success'
else
  puts 'Failed!'
end
