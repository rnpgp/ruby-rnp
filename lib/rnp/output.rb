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

    # Create an Output that ASCII-armors data, writing the armored stream
    # to another output.
    #
    # @param base [Output] the output the armored data will be written to.
    #   It is retained by the returned output, as the armored stream
    #   references it internally.
    # @param type [String] the armor type ('message', 'public key',
    #   'secret key', 'signature', 'cleartext')
    # @return [Output]
    def self.to_armor(base, type)
      pptr = FFI::MemoryPointer.new(:pointer)
      Rnp.call_ffi(:rnp_output_to_armor, base.ptr, pptr, type)
      base_ptr = base.instance_variable_get(:@ptr)
      # The armored output references the base output internally, and
      # librnp accesses the base output when the armored output is
      # destroyed (see rnp_output_destroy()). The armored output must
      # therefore always be destroyed before the base output, regardless
      # of the order in which the garbage collector finalizes the two
      # objects. The finalizers below coordinate this via a shared state.
      state = { armored: pptr.read_pointer }
      base_ptr.autorelease = false
      base.instance_variable_set(
        :@ptr,
        FFI::AutoPointer.new(FFI::Pointer.new(base_ptr.address),
                             base_finalizer(state))
      )
      output = allocate
      output.instance_variable_set(
        :@ptr, FFI::AutoPointer.new(state[:armored], armored_finalizer(state))
      )
      output.instance_variable_set(:@writer, base)
      output
    end

    # @api private
    # Finalizer for an armored output created via {.to_armor}: destroys
    # the armored output (once).
    def self.armored_finalizer(state)
      lambda do |ptr|
        if state[:armored]
          LibRnp.rnp_output_destroy(ptr)
          state[:armored] = nil
        end
      end
    end

    # @api private
    # Finalizer for the base output of an armored output created via
    # {.to_armor}: destroys the armored output first (if it still
    # exists), then the base output.
    def self.base_finalizer(state)
      lambda do |ptr|
        if state[:armored]
          LibRnp.rnp_output_destroy(state[:armored])
          state[:armored] = nil
        end
        LibRnp.rnp_output_destroy(ptr)
      end
    end

    # Write to the output.
    #
    # @param strings [String]
    # @return [Integer] the number of bytes written
    def write(*strings)
      total_written = 0
      pwritten = FFI::MemoryPointer.new(:size_t)
      strings.each do |string|
        Rnp.call_ffi(:rnp_output_write, @ptr, string, string.size, pwritten)
        total_written += pwritten.read(:size_t)
      end
      total_written
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

    # Set the line length for armored output written to this output.
    #
    # @note This is only valid for outputs created via {.to_armor}.
    #
    # @param llen [Integer] the line length in characters (16..76)
    # @return [void]
    def armor_line_length=(llen)
      Rnp.call_ffi(:rnp_output_armor_set_line_length, @ptr, llen)
    end

    # Finish writing to the output.
    #
    # @note For most output types this is not needed (destruction of the
    #   output finishes it implicitly). It is useful to deterministically
    #   finalize an output without destroying it, e.g. to write out the
    #   trailer of an armored output created via {.to_armor}.
    #
    # @return [void]
    def finish
      Rnp.call_ffi(:rnp_output_finish, @ptr)
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

