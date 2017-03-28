#!/usr/bin/env ruby
require 'optparse'

require_relative '../../lib/rnp'

options = {armored: false, keys_armored: false}
parser = OptionParser.new do |opts|
  opts.banner = "Usage: #{$0} [options] <pubkey>"
  opts.on('-k', '--keys-armored', 'Seckey is ASCII armored') do
    options[:keys_armored] = true
  end
  opts.on('-a', '--armored', 'Output will be ASCII armored') do
    options[:armored] = true
  end
  opts.on('-h', '--help', 'Print this help') do
    puts opts
    exit
  end
end
parser.parse!

if ARGV.length != 1
  parser.display
  exit
end

pubkey_filename = ARGV.shift

keyring = RNP::load_keyring(File.binread(pubkey_filename), options[:keys_armored])

pubkey = keyring[0]

$stdin.binmode
data = $stdin.read

encrypted_data = pubkey.encrypt(data, options[:armored])

$stdout.binmode
$stdout.puts encrypted_data

if encrypted_data != nil
  $stderr.puts 'Encryption succeeded'
else
  $stderr.puts 'Encryption failed!'
end

