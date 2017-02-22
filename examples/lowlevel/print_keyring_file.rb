#!/usr/bin/env ruby
require_relative '../../lib/netpgp'

def usage
  puts "Usage: #{$0} <file>"
  exit 1
end

def print_pubkey(pubkey, indent=0)
    puts "#{' ' * indent}Version: #{pubkey[:version]}"
    puts "#{' ' * indent}Creation Time: #{Time.at(pubkey[:birthtime])}"
    puts "#{' ' * indent}Algorithm: #{pubkey[:alg]}"
    case pubkey[:alg]
    when :PGP_PKA_RSA
      n = LibNetPGP::bn2hex(pubkey[:key][:rsa][:n])
      e = LibNetPGP::bn2hex(pubkey[:key][:rsa][:e])
      puts "#{' ' * indent}n: 0x#{n}"
      puts "#{' ' * indent}e: 0x#{e}"
    end
end

def print_seckey(seckey, indent=0)
  puts "#{' ' * (indent+2)}[Public Key]"
  print_pubkey(seckey[:pubkey], indent + 2)
  puts "#{' ' * indent}string-to-key usage: #{seckey[:s2k_usage]}"
  puts "#{' ' * indent}string-to-key specifier: #{seckey[:s2k_specifier]}"
  puts "#{' ' * indent}Symmetric algorithm: #{seckey[:alg]}"
  puts "#{' ' * indent}Hash algorithm: #{seckey[:hash_alg]}"
end

usage if ARGV.length != 1
armored = ARGV[0].downcase.end_with?('.asc') ? 1 : 0

keyring_mem = LibC::calloc(1, LibNetPGP::PGPKeyring.size)
keyring = LibNetPGP::PGPKeyring.new(keyring_mem)
if 1 != LibNetPGP::pgp_keyring_fileread(keyring, armored, ARGV[0])
  puts 'Failed to load keyring'
  exit 1
end
keycount = LibNetPGP::dynarray_count(keyring, 'key')
puts "Loaded #{keycount} key(s)"

(0..keycount - 1).each {|keyn|
  key = LibNetPGP::dynarray_get_item(keyring, 'key', LibNetPGP::PGPKey, keyn)
  puts "[Key ##{keyn}]"
  uidcount = LibNetPGP::dynarray_count(key, 'uid')
  print "User ids: "
  puts LibNetPGP::dynarray_get_item(key, 'uid', :string, 0)
  (1..uidcount - 1).each {|uidn|
    print '          '
    puts LibNetPGP::dynarray_get_item(key, 'uid', :string, uidn)
  }
  puts "Subpackets:  #{LibNetPGP::dynarray_count(key, 'packet')}"
  puts "Subkeys:     #{LibNetPGP::dynarray_count(key, 'subsig')}"
  puts "Revocations: #{LibNetPGP::dynarray_count(key, 'revoke')}"
  case key[:type]
  when :PGP_PTAG_CT_PUBLIC_KEY
    puts '  [Public Key]'
    pubkey = key[:key][:pubkey]
    print_pubkey(pubkey, 2)
  when :PGP_PTAG_CT_SECRET_KEY
    puts '  [Secret Key]'
    seckey = key[:key][:seckey]
    print_seckey(seckey, 2)
  end
  puts ''
}

