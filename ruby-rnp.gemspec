Gem::Specification.new do |s|
  s.name        = 'ruby-rnp'
  s.version     = '0.0.1'
  s.licenses    = ['']
  s.summary     = 'An interface to librnp.so'
  s.description = 'Uses ruby-ffi to support PGP/GnuPG functionality. Requires librnp.so.'
  s.authors     = ['Ribose']
  s.files       = Dir['lib/**/*']
  s.platform    = Gem::Platform::RUBY

  s.add_development_dependency 'rspec', '3.5.0'
end

