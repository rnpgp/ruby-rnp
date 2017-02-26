#!/usr/bin/env ruby
require 'optparse'
require 'io/console'

require_relative '../../lib/netpgp'

options = {armored: false, keys_armored: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <seckey> <passphrase>"
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

if ARGV.length != 2
  parser.display
  exit
end

seckey_filename = ARGV.shift
passphrase = ARGV.shift + "\n"

secring = NetPGP::load_keyring(File.binread(seckey_filename), options[:keys_armored])

$stdin.binmode
data = $stdin.read

seckey = secring[0]
decrypted_data = seckey.decrypt(data, passphrase, options[:armored])
if decrypted_data
  $stderr.puts 'Decryption succeeded'
  $stdout.puts decrypted_data
else
  $stderr.puts 'Decryption failed!'
end

