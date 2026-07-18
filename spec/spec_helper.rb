# frozen_string_literal: true

# (c) 2018 Ribose Inc.

if ENV["COVERAGE"] == "true"
  require "simplecov"
  require "simplecov-json"

  SimpleCov.start do
    formatter SimpleCov::Formatter::MultiFormatter.new(
      [
        SimpleCov::Formatter::HTMLFormatter,
        SimpleCov::Formatter::JSONFormatter
      ]
    )
  end
end

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "rnp"
