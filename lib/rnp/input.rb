# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'English'

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Class used to feed data into RNP.
  #
  # @note When dealing with very large data sources, prefer {from_path} which
  #   should be the most efficient. {from_io} is likely to have more overhead.
  #
  # @example input from a string
  #   Rnp::Input.from_string('my data')
  #
  # @example input from a file
  #   Rnp::Input.from_path('/path/to/my/file')
  #
  # @example input from a Ruby IO object
  #   Rnp::Input.from_io(File.open('/path/to/file', 'rb'))
  class Input
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr, reader = nil)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      @reader = reader
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_input_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    # Create an Input to read from a string.
    #
    # @param data [String] the string data
    # @return [Input]
    def self.from_string(data)
      pptr = FFI::MemoryPointer.new(:pointer)
      buf = FFI::MemoryPointer.from_data(data)
      Rnp.call_ffi(:rnp_input_from_memory, pptr, buf, buf.size, true)
      Input.new(pptr.read_pointer)
    end

    # Create an Input to read from a path.
    #
    # @param path [String] the path
    # @return [Input]
    def self.from_path(path)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_input_from_path, pptr, path)
      Input.new(pptr.read_pointer)
    end

    # Create an Input to read from an IO object.
    #
    # @param io [IO, #read] the IO object
    # @return [Input]
    def self.from_io(io)
      from_callback(io.method(:read))
    end

    # @api private
    READER = lambda do |reader, _ctx, buf, buf_len|
      begin
        data = reader.call(buf_len)
        return 0 unless data
        raise Rnp::Error, 'Read exceeded buffer size' if data.size > buf_len
        buf.write_bytes(data)
        return data.size
      rescue
        puts $ERROR_INFO
        return -1
      end
    end

    # @api private
    def self.from_callback(reader)
      pptr = FFI::MemoryPointer.new(:pointer)
      readercb = READER.curry[reader]
      Rnp.call_ffi(:rnp_input_from_callback, pptr, readercb, nil, nil)
      Input.new(pptr.read_pointer, readercb)
    end
  end # class
end # class

