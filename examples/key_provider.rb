# frozen_string_literal: true

require 'rnp'

rnp = Rnp.new

# This key provider simply loads keys from the keys/ directory, which
# have the key information in the filename.
rnp.key_provider = lambda do |identifier_type, identifier, secret|
  puts "Key requested: #{identifier_type}: #{identifier} (secret: #{secret})"

  # we only support the keyid identifier type
  return unless identifier_type == 'keyid'

  keyid = identifier
  key_type = secret ? 'secret' : 'public'
  # construct a path to the key (such as: keys/76D0C79B6D0FAE1C.public.gpg)
  filename = "#{keyid}.#{key_type}.gpg"
  path = File.join(__dir__, 'keys', filename)

  # bail if we don't have that key
  return unless File.exist?(path)

  # load the key
  rnp.load_keys(input: Rnp::Input.from_io(File.open(path, 'rb')),
                format: 'GPG')
  puts "Key provider loading file: #{filename}"
end

msg = <<~'EOF'
  -----BEGIN PGP MESSAGE-----
  Version: rnp 0.8.0~

  wYwD5VjkVI6IdhwBBAC+7yeuf1hU2m/TrI3vha5v9VQo51/V2hIZBXmNzYQOUMPiKUUSwpXwGyo4
  q33gZCRlSW1FnDf6xn3gcXVKd4JepkFTFUYZRDh4I7lxdjlQsAmUOwGpUeVuFV1JICDCp2iHJAA9
  cCgUuwwv7PbzSLKLiEjsmbgggzT2WxUTFQqSfdJOAVYogrPtotWesNzhvqgJMkDVSg1ghHEHLTYk
  VDUbjuNwI/Sz1Wb4UtCunlsY2xljdz302OT7GKEUKCid90RdP35B/lBMcWQDmljueqQ4
  =Uo4h
  -----END PGP MESSAGE-----
EOF

# password used to unlock our secret key
rnp.password_provider = 'password'

puts rnp.decrypt(input: Rnp::Input.from_string(msg))

