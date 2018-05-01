# frozen_string_literal: true

require 'pp'

require 'rnp'

rnp = Rnp.new

# generate both a primary key and a subkey
generated = rnp.generate_key(
  primary: {
    type: 'RSA',
    length: 1024,
    userid: 'Example User',
    usage: [:sign]
  },
  sub: {
    type: 'RSA',
    length: 1024,
    usage: [:encrypt]
  }
)

primary = generated[:primary]
sub1 = generated[:sub]

# generate another subkey
generated = rnp.generate_key(
  sub: {
    type: 'RSA',
    length: 1024,
    usage: [:encrypt],
    primary: { keyid: primary.keyid }
  }
)

sub2 = generated[:sub]

pp primary.json
pp sub1.json
pp sub2.json

# don't forget to protect & lock the keys before saving to keep them secure
[primary, sub1, sub2].each do |key|
  key.protect('password')
  key.lock
end

