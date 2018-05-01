# frozen_string_literal: true

# (c) 2018 Ribose Inc.

require 'ffi'

require 'rnp/utils'
require 'rnp/ffi/librnp'

class Rnp
  # Get the default homedir for RNP.
  #
  # @return [String]
  def self.default_homedir
    pptr = FFI::MemoryPointer.new(:pointer)
    Rnp.call_ffi(:rnp_get_default_homedir, pptr)
    begin
      phomedir = pptr.read_pointer
      phomedir.read_string unless phomedir.null?
    ensure
      LibRnp.rnp_buffer_destroy(phomedir)
    end
  end

  # Attempt to detect information about a homedir.
  #
  # @param homedir [String] the homedir
  # @return [Hash<Symbol>]
  #   * :public [Hash<Symbol>]
  #     * :format [String]
  #     * :path [String]
  #   * :secret [Hash<Symbol>]
  #     * :format [String]
  #     * :path [String]
  def self.homedir_info(homedir)
    pptrs = FFI::MemoryPointer.new(:pointer, 4)
    Rnp.call_ffi(:rnp_detect_homedir_info, homedir, pptrs[0], pptrs[1],
                 pptrs[2], pptrs[3])
    ptrs = (0..3).collect { |i| pptrs[i] }.map(&:read_pointer)
    return if ptrs.all?(&:null?)
    {
      public: {
        format: ptrs[0].read_string,
        path: ptrs[1].read_string
      },
      secret: {
        format: ptrs[2].read_string,
        path: ptrs[3].read_string
      }
    }
  ensure
    ptrs&.each { |ptr| LibRnp.rnp_buffer_destroy(ptr) }
  end

  # Attempt to detect the format of a key.
  #
  # @param key_data [String] the key data
  # @return [String]
  def self.key_format(key_data)
    pptr = FFI::MemoryPointer.new(:pointer)
    data = FFI::MemoryPointer.from_data(key_data)
    Rnp.call_ffi(:rnp_detect_key_format, data, data.size, pptr)
    begin
      pformat = pptr.read_pointer
      pformat.read_string unless pformat.null?
    ensure
      LibRnp.rnp_buffer_destroy(pformat)
    end
  end
end # class

