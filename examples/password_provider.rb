# frozen_string_literal: true

require 'rnp'

rnp = Rnp.new

rnp.password_provider = lambda do |key, reason|
  desc = if key.nil?
           # This password is probably being requested for decrypting
           # symmetic/password-only data (not public-key encrypted).
           "to #{reason}"
         else
           "for key #{key.keyid} (to #{reason})"
         end
  print "Enter password #{desc}: "
  $stdin.gets.chomp
end

puts
puts "Hint: the password is 'password'!"

# load a key for signing
path = File.join(__dir__, 'keys', '76D0C79B6D0FAE1C.secret.gpg')
rnp.load_keys(format: 'GPG',
              input: Rnp::Input.from_path(path))

# find the loaded key
signer = rnp.find_key(keyid: '76D0C79B6D0FAE1C')

# sign
signed_message = rnp.sign(input: Rnp::Input.from_string('my data to sign'),
                          signers: signer,
                          armored: true)
puts "\nSigned message:\n#{signed_message}\n"

encrypted_data = rnp.symmetric_encrypt(
  input: Rnp::Input.from_string('some secret data'),
  passwords: %w[pass1 pass2]
)

puts "Hint: either password of 'pass1' or 'pass2' will work!"
decrypted_data = rnp.decrypt(input: Rnp::Input.from_string(encrypted_data))
puts "\nDecrypted data:\n#{decrypted_data}"

# another approach is to provide a password directly
rnp.password_provider = 'pass1'
rnp.decrypt(input: Rnp::Input.from_string(encrypted_data))

