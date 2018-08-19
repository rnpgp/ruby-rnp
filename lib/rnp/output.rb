# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'English'

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Class used to feed data out of RNP.
  #
  # @note When dealing with very large data, prefer {to_path} which should
  #   be the most efficient. {to_io} is likely to have more overhead.
  #
  # @example output to a string
  #   output = Rnp::Input.to_string('my data')
  #   # ... after performing operations
  #   output.string
  #
  # @example output to a file
  #   Rnp::Input.to_path('/path/to/my/file')
  #
  # @example output to a Ruby IO object
  #   Rnp::Input.to_io(File.open('/path/to/file', 'wb'))
  class Output
    # @api private
    attr_reader :ptr

    # @api private
    def initialize(ptr, writer = nil)
      raise Rnp::Error, 'NULL pointer' if ptr.null?
      @ptr = FFI::AutoPointer.new(ptr, self.class.method(:destroy))
      @writer = writer
    end

    # @api private
    def self.destroy(ptr)
      LibRnp.rnp_output_destroy(ptr)
    end

    def inspect
      Rnp.inspect_ptr(self)
    end

    # Create an Output to write to a string.
    #
    # The resulting string can later be retrieved with {#string}.
    #
    # @param max_alloc [Integer] the maximum amount of memory to allocate,
    #   or 0 for unlimited
    # @return [Output]
    def self.to_string(max_alloc = 0)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_output_to_memory, pptr, max_alloc)
      Output.new(pptr.read_pointer)
    end

    # Create an Output to write to a path.
    #
    # @param path [String] the path
    # @return [Output]
    def self.to_path(path)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_output_to_path, pptr, path)
      Output.new(pptr.read_pointer)
    end

    # Create an Output to discard all writes.
    #
    # @return [Output]
    def self.to_null
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_output_to_null, pptr)
      Output.new(pptr.read_pointer)
    end

    # Create an Output to write to an IO object.
    #
    # @param io [IO, #write] the IO object
    # @return [Output]
    def self.to_io(io)
      to_callback(io.method(:write))
    end

    # Retrieve the data written. Only valid for #{to_string}.
    #
    # @return [String, nil]
    def string
      pptr = FFI::MemoryPointer.new(:pointer)
      len = FFI::MemoryPointer.new(:size_t)
      Rnp.call_ffi(:rnp_output_memory_get_buf, @ptr, pptr, len, false)
      buf = pptr.read_pointer
      buf.read_bytes(len.read(:size_t)) unless buf.null?
    end

    # @api private
    WRITER = lambda do |writer, _ctx, buf, buf_len|
      begin
        data = buf.read_bytes(buf_len)
        written = writer.call(data)
        return written == data.bytesize
      rescue
        puts $ERROR_INFO
        return false
      end
    end

    # @api private
    def self.to_callback(writer)
      pptr = FFI::MemoryPointer.new(:pointer)
      writercb = WRITER.curry[writer]
      Rnp.call_ffi(:rnp_output_to_callback, pptr, writercb, nil, nil)
      Output.new(pptr.read_pointer, writercb)
    end

    # @api private
    def self.default(output)
      to_str = output.nil?
      output = Output.to_string if to_str
      yield output
      output.string if to_str
    end
  end # class
end # class

