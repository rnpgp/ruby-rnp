# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'rnp/ffi/librnp'

class Rnp
  class Error < ::StandardError
    attr_reader :rc

    def initialize(msg, rc = nil)
      @rc = rc
      if rc
        desc = LibRnp.rnp_result_to_string(rc)
        msg = "#{msg} - (rc: 0x#{rc.to_s(16)}): #{desc}"
      end
      super(msg)
    end
  end

  class FeatureNotAvailableError < Error
    def initialize(feature)
      super("#{feature} is not available in your version of rnp.")
    end
  end

  class BadPasswordError < Error; end
  class InvalidSignatureError < Error; end
  class BadFormatError < Error; end
  class NoSuitableKeyError < Error; end

  # @api private
  def self.raise_error(msg, rc = nil)
    klass = ERRORS_MAP.fetch(rc, Error)
    raise klass.new(msg, rc)
  end

  # @api private
  ERRORS_MAP = {
    LibRnp::RNP_ERROR_BAD_PASSWORD => BadPasswordError,
    LibRnp::RNP_ERROR_SIGNATURE_INVALID => InvalidSignatureError,
    LibRnp::RNP_ERROR_BAD_FORMAT => BadFormatError,
    LibRnp::RNP_ERROR_NO_SUITABLE_KEY => NoSuitableKeyError
  }.freeze
end # class

