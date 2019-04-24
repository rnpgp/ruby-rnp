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

  # Add ASCII Armor to data.
  #
  # @param input [Input] the input to read data from
  # @param output [Output] the output to write the armored
  #   data to. If nil, the result will be returned directly
  #   as a String.
  # @return [nil, String]
  def self.enarmor(input:, output: nil, type: nil)
    Output.default(output) do |output_|
      Rnp.call_ffi(:rnp_enarmor, input.ptr, output_.ptr, type)
    end
  end

  # Remove ASCII Armor from data.
  #
  # @param input [Input] the input to read the ASCII-Armored data from
  # @param output [Output] the output to write the dearmored data to. If
  #   nil, the result will be returned directly as a String.
  # @return [nil, String]
  def self.dearmor(input:, output: nil)
    Output.default(output) do |output_|
      Rnp.call_ffi(:rnp_dearmor, input.ptr, output_.ptr)
    end
  end

  # Get the version of the rnp library as a string.
  #
  # @return [String]
  def self.version_string
    LibRnp.rnp_version_string
  end

  # Get the detailed version of the rnp library as a string.
  #
  # @return [String]
  def self.version_string_full
    LibRnp.rnp_version_string_full
  end

  # Get the version stamp of the rnp library as an unsigned
  # 32-bit integer. This number can be compared against other
  # stamps generated with {version_for}.
  #
  # @return [Integer]
  def self.version(str = nil)
    if str.nil?
      LibRnp.rnp_version
    else
      LibRnp.rnp_version_for(*str.split('.').map(&:to_i))
    end
  end

  # Encode the given major, minor, and patch numbers into a version
  # stamp.
  #
  # @return [Integer]
  def self.version_for(major, minor, patch)
    LibRnp.rnp_version_for(major, minor, patch)
  end

  # Extract the major version component from the given version stamp.
  #
  # @return [Integer]
  def self.version_major(version)
    LibRnp.rnp_version_major(version)
  end

  # Extract the minor version component from the given version stamp.
  #
  # @return [Integer]
  def self.version_minor(version)
    LibRnp.rnp_version_minor(version)
  end

  # Extract the patch version component from the given version stamp.
  #
  # @return [Integer]
  def self.version_patch(version)
    LibRnp.rnp_version_patch(version)
  end

  # Retrieve the commit time of the latest commit.
  #
  # This will return 0 for release/non-master builds.
  #
  # @return [Integer]
  def self.commit_time
    LibRnp.rnp_version_commit_timestamp
  end

  FEATURES = {
    # Support for setting hash, creation, and expiration time for individual
    # signatures in a sign operation. Older versions of rnp returned a
    # "not implemented" error.
    "per-signature-opts" => Rnp.version > Rnp.version("0.11.0") || Rnp.commit_time >= 1546035818,
    # Correct grip calculation for Elgamal/DSA keys. This was actually before the
    # commit timestamp API was added, so this isn't accurate in one case.
    "dsa-elg-grip-calc" => Rnp.version > Rnp.version("0.11.0") || Rnp.commit_time >= 1538219020,
  }.freeze

  def self.has?(feature)
    raise ArgumentError unless FEATURES.include?(feature)
    FEATURES[feature]
  end
end # class

