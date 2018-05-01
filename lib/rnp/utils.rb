# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'

class Rnp
  # @api private
  #
  # Calls the LibRnp FFI function indicated.
  # If the return code is <0, an error will be raised.
  #
  # @param fn [Symbol] the name of the function to call
  # @param args the arguments to pass to the FFI function
  # @return [void]
  def self.call_ffi(fn, *args)
    rc = LibRnp.method(fn).call(*args)
    Rnp.raise_error("#{fn} failed", rc) unless rc.zero?
    nil
  end

  # @api private
  def self.inspect_ptr(myself)
    ptr_format = "0x%0#{FFI::Pointer.size * 2}x"
    ptr_s = format(ptr_format, myself.instance_variable_get(:@ptr).address)
    class_name = myself.class.to_s
    "#<#{class_name}:#{ptr_s}>"
  end

  unless FFI::MemoryPointer.respond_to?(:from_data)
    # @api private
    class << FFI::MemoryPointer
      def from_data(data)
        buf = FFI::MemoryPointer.new(:uint8, data.bytesize)
        buf.write_bytes(data)
        buf
      end
    end
  end
end # class

