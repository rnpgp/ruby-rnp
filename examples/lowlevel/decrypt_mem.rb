#!/usr/bin/env ruby
require 'optparse'
require 'io/console'

require_relative '../../lib/netpgp'

options = {armored: false, keys_armored: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <pubkey> <seckey> <passphrase>"
  opts.on('-k', '--keys-armored', 'Keys are ASCII armored') do
    options[:keys_armored] = true
  end
  opts.on('-a', '--armored', 'Input is ASCII armored') do
    options[:armored] = true
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
seckey_filename = ARGV.shift
passphrase = ARGV.shift + "\n"

# Load pubkey/keyring
pubkeyring_mem = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
pubkeyring = LibNetPGP::PGPKeyring.new(pubkeyring_mem)
if 1 != LibNetPGP::pgp_keyring_fileread(pubkeyring, options[:keys_armored] ? 1 : 0, pubkey_filename)
  puts 'Errors encountered while loading public keyring.'
  exit 1
end
# Load seckey/keyring
seckeyring_mem = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
seckeyring = LibNetPGP::PGPKeyring.new(seckeyring_mem)
if 1 != LibNetPGP::pgp_keyring_fileread(seckeyring, options[:keys_armored] ? 1 : 0, seckey_filename)
  puts 'Errors encountered while loading secret keyring.'
  exit 1
end

pgpio = LibNetPGP::PGPIO.new
stderr_fp = LibC::fdopen($stderr.to_i, 'w')
# send all to stderr
pgpio[:outs] = stderr_fp
pgpio[:errs] = stderr_fp
pgpio[:res] = stderr_fp

rd, wr = IO.pipe
wr.write passphrase
wr.close
passfp = LibC::fdopen(rd.to_i, 'r')

armored = options[:armored] ? 1 : 0
sshkeys = 0
numtries = 1

$stdin.binmode
data = $stdin.read
data_buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
data_buf.put_bytes(0, data)
memory_ptr = LibNetPGP::pgp_decrypt_buf(pgpio, data_buf, data_buf.size, seckeyring, pubkeyring, armored, sshkeys, passfp, numtries, nil)
rd.close
LibC::fclose(passfp)

memory = LibNetPGP::PGPMemory.new(memory_ptr)
if not memory.null?
  $stdout.binmode
  $stdout.puts memory[:buf].read_bytes(memory[:length])
  LibNetPGP::pgp_memory_free(memory)
  $stderr.puts 'Success'
else
  $stderr.puts 'Failed!'
end

