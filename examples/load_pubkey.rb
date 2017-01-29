#!/usr/bin/env ruby
require_relative '../lib/netpgp'

def bignum_byte_count(bn)
  bn.to_s(16).length / 2
end

class PublicKey
  attr_accessor :version,
                :creation_time,
                :expiration_time,
                :public_key_algorithm,
                :mpi,
                :userids

  def initialize
    @version = nil
    @creation_time = nil
    @expiration_time = nil
    @public_key_algorithm = nil
    @mpi = {}

    @userids = []
  end
  
  def bitcount
    case @public_key_algorithm
    when :PGP_PKA_RSA, :PGP_PKA_RSA_ENCRYPT_ONLY, :PGP_PKA_RSA_SIGN_ONLY
      return NetPGP::bignum_byte_count(@n) * 8
    when :PGP_PKA_DSA
      case NetPGP::bignum_byte_count(@q)
      when 20
        1024
      when 28
        2048
      when 32
        3072
      end
    when :PGP_PKA_ELGAMAL
      NetPGP::bignum_byte_count(@y) * 8
    end
    0
  end

end

PARSE_PUBLIC_KEY = Proc.new do |results, pkt, data|
  case pkt[:tag]
  when :PGP_PARSER_PTAG

  when :PGP_PARSER_PACKET_END
  when :PGP_PTAG_CT_PUBLIC_KEY, :PGP_PTAG_CT_PUBLIC_SUBKEY
    pk = pkt[:u][:pubkey]
    pubkey = PublicKey.new
    case pk[:alg]
    when :PGP_PKA_RSA, :PGP_PKA_RSA_ENCRYPT_ONLY, :PGP_PKA_RSA_SIGN_ONLY
      rsa = pk[:key][:rsa]
      pubkey.mpi[:n] = LibNetPGP::bn2hex(rsa[:n]).hex
      pubkey.mpi[:e] = LibNetPGP::bn2hex(rsa[:e]).hex
    when :PGP_PKA_DSA
      dsa = pk[:key][:dsa]
      pubkey.mpi[:p] = LibNetPGP::bn2hex(dsa[:p]).hex
      pubkey.mpi[:q] = LibNetPGP::bn2hex(dsa[:q]).hex
      pubkey.mpi[:g] = LibNetPGP::bn2hex(dsa[:g]).hex
      pubkey.mpi[:y] = LibNetPGP::bn2hex(dsa[:y]).hex
   when :PGP_PKA_ELGAMAL
      elg = pk[:key][:elgamal]
      pubkey.mpi[:p] = LibNetPGP::bn2hex(rsa[:p]).hex
      pubkey.mpi[:g] = LibNetPGP::bn2hex(rsa[:g]).hex
      pubkey.mpi[:y] = LibNetPGP::bn2hex(rsa[:y]).hex
    else
      next :PGP_RELEASE_MEMORY     
    end
    pubkey.version = pk[:version]
    pubkey.creation_time = Time.at(pk[:birthtime])
    pubkey.public_key_algorithm = pk[:alg]
    results.push(pubkey)
  when :PGP_PTAG_SS_KEY_EXPIRY
    pubkey = results.last
    pubkey.expiration_time = Time.at(results.last.creation_time.to_i + pkt[:u][:ss_time])
  when :PGP_PTAG_CT_USER_ID
    pubkey = results.last
    pubkey.userids.push(pkt[:u][:userid].force_encoding('utf-8'))
  end
  next :PGP_RELEASE_MEMORY
end

def load_pubkey(data, armored=false, print_errors=true)
  stream_mem = LibC::calloc(1, LibNetPGP::PGPStream.size)
  # This will free the above memory (PGPStream is a ManagedStruct)
  stream = LibNetPGP::PGPStream.new(stream_mem)
  stream[:readinfo][:accumulate] = 1
  LibNetPGP::pgp_parse_options(stream, :PGP_PTAG_SS_ALL, :PGP_PARSE_PARSED)

  # This memory will be GC'd
  mem = FFI::MemoryPointer.new(:uint8, data.bytesize)
  mem.put_bytes(0, data)

  LibNetPGP::pgp_reader_set_memory(stream, mem, mem.size)
  results = []
  callback = PARSE_PUBLIC_KEY.curry[results]
  LibNetPGP::pgp_set_callback(stream, callback, nil)
  LibNetPGP::pgp_reader_push_dearmour(stream) if armored
  LibNetPGP::pgp_parse(stream, print_errors ? 1 : 0)
  LibNetPGP::pgp_reader_pop_dearmour(stream) if armored
  results[0]
end

def usage
  puts "Usage: #{$0} <file>"
  exit 1
end

usage if ARGV.length != 1
armored = ARGV[0].downcase.end_with?('.asc')
pubkey = load_pubkey(File.binread(ARGV[0]), armored)
puts pubkey.inspect

