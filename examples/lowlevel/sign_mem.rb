#!/usr/bin/env ruby
require 'optparse'
require 'io/console'

require_relative '../../lib/netpgp'

options = {armored: false, keys_armored: false, cleartext: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <seckey> <passphrase>"
  opts.on('-k', '--keys-armored', 'Keys are ASCII armored') do
    options[:keys_armored] = true
  end
  opts.on('-a', '--armored', 'Input is ASCII armored') do
    options[:armored] = true
  end
  opts.on('-c', '--clear-sign', 'Cleartext signature') do
    options[:cleartext] = true
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

seckey_filename = ARGV.shift
passphrase = ARGV.shift + "\n"

# Load seckey/keyring
seckeyring_mem = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
seckeyring = LibNetPGP::PGPKeyring.new(seckeyring_mem)
if 1 != LibNetPGP::pgp_keyring_fileread(seckeyring, options[:keys_armored] ? 1 : 0, seckey_filename)
  puts 'Errors encountered while loading secret keyring.'
  exit 1
end
# Find first seckey
keycount = LibNetPGP::dynarray_count(seckeyring, 'key')
seckey = nil
(0..keycount - 1).each {|keyn|
  key = LibNetPGP::dynarray_get_item(seckeyring, 'key', LibNetPGP::PGPKey, keyn)
  seckey = key if LibNetPGP::pgp_is_key_secret(key)
  break if seckey != nil
}
if seckey == nil
  puts 'No seckey found'
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
seckey = LibNetPGP::pgp_decrypt_seckey(seckey, passfp)
rd.close
LibC::fclose(passfp)

if seckey == nil
  puts 'Invalid passphrase.'
  exit 1
end
seckey = LibNetPGP::PGPSecKey.new(seckey)

armored = options[:armored] ? 1 : 0
cleartext = options[:cleartext] ? 1 : 0
from = Time.now.to_i
duration = 0
# see pgp_str_to_hash_alg
hashname = 'sha1'

$stdin.binmode
data = $stdin.read
data_buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
data_buf.put_bytes(0, data)
memory_ptr = LibNetPGP::pgp_sign_buf(pgpio, data_buf, data_buf.size, seckey, from, duration, hashname, armored, cleartext)
if not memory_ptr.null?
  memory = LibNetPGP::PGPMemory.new(memory_ptr)
  $stdout.binmode
  $stdout.puts memory[:buf].read_bytes(memory[:length])
  LibNetPGP::pgp_memory_free(memory)
  $stderr.puts 'Success'
else
  $stderr.puts 'Failed!'
end

