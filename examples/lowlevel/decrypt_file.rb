#!/usr/bin/env ruby
require 'optparse'
require 'io/console'

require_relative '../../lib/rnp'

options = {armored: false, keys_armored: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <pubkey> <seckey> <input-file> <output-file>"
  opts.on('-k', '--keys-armored', 'Keys are ASCII armored') do
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

if ARGV.length != 4
  parser.display
  exit
end

pubkey_filename = ARGV.shift
seckey_filename = ARGV.shift
input_filename = ARGV.shift
output_filename = ARGV.shift

# Load pubkey/keyring
pubkeyring_mem = LibC::calloc(1, LibRNP::PGPKeyring.size)
pubkeyring = LibRNP::PGPKeyring.new(pubkeyring_mem)
if 1 != LibRNP::pgp_keyring_fileread(pubkeyring, options[:keys_armored] ? 1 : 0, pubkey_filename)
  puts 'Errors encountered while loading public keyring.'
  exit 1
end
# Load seckey/keyring
seckeyring_mem = LibC::calloc(1, LibRNP::PGPKeyring.size)
seckeyring = LibRNP::PGPKeyring.new(seckeyring_mem)
if 1 != LibRNP::pgp_keyring_fileread(seckeyring, options[:keys_armored] ? 1 : 0, seckey_filename)
  puts 'Errors encountered while loading secret keyring.'
  exit 1
end

pgpio = LibRNP::PGPIO.new
stdout_fp = LibC::fdopen($stdout.to_i, 'w')
stderr_fp = LibC::fdopen($stderr.to_i, 'w')
pgpio[:outs] = stdout_fp
pgpio[:errs] = stderr_fp
pgpio[:res] = stdout_fp

rd, wr = IO.pipe
print 'Enter passphrase: '
passphrase = $stdin.noecho(&:gets)
puts ''
wr.write passphrase
wr.close
passfp = LibC::fdopen(rd.to_i, 'r')

armored = options[:armored] ? 1 : 0
overwrite = 1
sshkeys = 0
numtries = 1

ret = LibRNP::pgp_decrypt_file(pgpio, input_filename, output_filename, seckeyring, pubkeyring, armored, overwrite, sshkeys, passfp, numtries, nil)
rd.close
LibC::fclose(passfp)
if ret == 1
  puts 'Success'
else
  puts 'Failed!'
end

