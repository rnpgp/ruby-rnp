# frozen_string_literal: true

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'rnp/version'

Gem::Specification.new do |spec|
  spec.name          = 'rnp'
  spec.version       = Rnp::VERSION
  spec.authors       = ['Ribose Inc.']
  spec.email         = ['open.source@ribose.com']

  spec.summary       = 'Ruby bindings for the rnp OpenPGP library'
  spec.description   = "Support rnp's OpenPGP functionality via ruby-ffi. Requires librnp.so."
  spec.homepage      = 'https://www.ribose.com'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").grep(%r{^(lib)/})
  spec.extra_rdoc_files = %w[README.adoc CHANGELOG.adoc LICENSE.txt]
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.7.0'

  spec.metadata['yard.run'] = 'yard'

  spec.add_development_dependency 'asciidoctor', '~> 2.0'
  spec.add_development_dependency 'bundler', '>= 1.14', '< 3'
  spec.add_development_dependency 'codecov', '~> 0.1'
  spec.add_development_dependency 'rake', '>= 10', '< 14'
  spec.add_development_dependency 'redcarpet', '~> 3.4'
  spec.add_development_dependency 'rspec', '~> 3.5'
  spec.add_development_dependency 'rubocop', '~> 0.75.0'
  spec.add_development_dependency 'simplecov', '~> 0.14'
  spec.add_development_dependency 'yard', '~> 0.9.12'

  spec.add_runtime_dependency 'ffi', '~> 1.9'
end
