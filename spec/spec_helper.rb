# frozen_string_literal: true

# (c) 2018 Ribose Inc.

if ENV["COVERAGE"] == "true"
  require "simplecov"
  require "codecov"

  SimpleCov.start
  SimpleCov.formatter = SimpleCov::Formatter::Codecov
end

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "rnp"
