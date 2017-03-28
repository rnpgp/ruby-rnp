# coding: utf-8
lib = File.expand_path("../lib", __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name        = "rnp"
  spec.version     = "0.1.0"
  spec.authors     = ["Ribose Inc."]
  spec.email       = ["packaging@ribose.com"]

  spec.summary     = "The Ruby interface for rnp."
  spec.description = "Support rnp's OpenPGP functionality via ruby-ffi. Requires librnp.so."
  spec.homepage    = "https://www.ribose.com"

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency 'rspec', '3.5.0'
end

