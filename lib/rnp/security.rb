# frozen_string_literal: true

# (c) 2026 Ribose Inc.

require 'ffi'

require 'rnp/error'
require 'rnp/ffi/librnp'
require 'rnp/utils'

class Rnp
  # Security rule levels, as accepted by {#add_security_rule}.
  SECURITY_RULE_LEVELS = {
    prohibited: LibRnp::RNP_SECURITY_PROHIBITED,
    insecure: LibRnp::RNP_SECURITY_INSECURE,
    default: LibRnp::RNP_SECURITY_DEFAULT
  }.freeze

  # Add a security rule, overriding the default algorithm security
  # settings.
  #
  # @note Key signature validation status is cached, so rules should be
  #   changed before keyrings are loaded (or the keyring should be
  #   reloaded after updating rules).
  #
  # @param type [String] the feature type. Currently only
  #   'hash algorithm' is supported.
  # @param name [String] the feature name ('SHA1', 'MD5', etc). The same
  #   values are used as in {Rnp.supports?}.
  # @param level [Symbol, Integer] the security level: :prohibited (the
  #   feature is completely disabled), :insecure (valid signatures
  #   produced after `from` are marked as invalid) or :default (the
  #   feature is secure enough). The LibRnp::RNP_SECURITY_* level
  #   constants are also accepted.
  # @param from [Time, Integer] the timestamp from which the rule is
  #   active. Objects that have a creation time (like signatures) are
  #   matched with the closest rule from the past, unless there is a rule
  #   with the override flag.
  # @param override [Boolean] whether the rule overrides all other rules
  #   for the specified feature. May be used to temporarily enable or
  #   disable some feature value, reverting the change later via
  #   {#remove_security_rule}.
  # @param usage [Symbol, nil] :key to limit the rule to key signature
  #   verification, :data to limit it to data signature verification, or
  #   nil to apply it to all usages.
  # @return [void]
  def add_security_rule(type:, name:, level:, from: 0, override: false,
                        usage: nil)
    flags = 0
    flags |= LibRnp::RNP_SECURITY_OVERRIDE if override
    flags |= security_rule_usage(usage)
    Rnp.call_ffi(:rnp_add_security_rule, @ptr, type, name, flags,
                 security_rule_time(from), security_rule_level(level))
  end

  # Get the security rule applicable for the given feature value and
  # timestamp.
  #
  # @note If there is no matching rule, this falls back to the default
  #   security level with empty flags and `from`.
  #
  # @param type (see #add_security_rule)
  # @param name (see #add_security_rule)
  # @param time [Time, Integer] the timestamp for which the feature
  #   should be checked
  # @param usage (see #add_security_rule)
  # @return [Hash<Symbol, Integer>] a hash with :flags, :from and :level
  #   keys. :level is one of the LibRnp::RNP_SECURITY_* level constants
  #   (RNP_SECURITY_PROHIBITED, RNP_SECURITY_INSECURE,
  #   RNP_SECURITY_DEFAULT).
  def security_rule(type:, name:, time: 0, usage: nil)
    pflags = FFI::MemoryPointer.new(:uint32)
    pflags.write(:uint32, security_rule_usage(usage))
    pfrom = FFI::MemoryPointer.new(:uint64)
    plevel = FFI::MemoryPointer.new(:uint32)
    Rnp.call_ffi(:rnp_get_security_rule, @ptr, type, name,
                 security_rule_time(time), pflags, pfrom, plevel)
    {
      flags: pflags.read(:uint32),
      from: pfrom.read(:uint64),
      level: plevel.read(:uint32)
    }
  end

  # Remove security rule(s) matching the parameters.
  #
  # @note Use this with caution: this may also clear the default security
  #   rules, so all affected features would be considered of the default
  #   security level.
  #
  # @param type [String, nil] the feature type. If nil, all rules will be
  #   cleared.
  # @param name [String, nil] the feature name. If nil, all rules of the
  #   type will be cleared.
  # @param level (see #add_security_rule)
  # @param override [Boolean] match only rules with the override flag
  # @param usage (see #add_security_rule)
  # @param all [Boolean] remove all rules for the type and name
  # @param from [Time, Integer] the timestamp for which the rule should
  #   be removed. Ignored when `all` is true.
  # @return [Integer] the number of removed rules
  def remove_security_rule(type:, name:, level: :default, override: false,
                           usage: nil, all: false, from: 0)
    flags = 0
    flags |= LibRnp::RNP_SECURITY_OVERRIDE if override
    flags |= security_rule_usage(usage)
    flags |= LibRnp::RNP_SECURITY_REMOVE_ALL if all
    premoved = FFI::MemoryPointer.new(:size_t)
    Rnp.call_ffi(:rnp_remove_security_rule, @ptr, type, name,
                 security_rule_level(level), flags,
                 security_rule_time(from), premoved)
    premoved.read(:size_t)
  end

  # Set the timestamp used in all operations instead of the system time.
  # This includes key/signature generation (used as the creation date)
  # and verification of keys and signatures (used as the current time).
  #
  # @param time [Time, Integer] the timestamp to use. A value of 0
  #   restores the original behavior (the system time is used).
  # @return [void]
  def timestamp=(time)
    Rnp.call_ffi(:rnp_set_timestamp, @ptr, security_rule_time(time))
  end

  private

  def security_rule_level(level)
    return level if level.is_a?(Integer)
    SECURITY_RULE_LEVELS.fetch(level) do
      raise ArgumentError, "invalid security rule level: #{level.inspect}"
    end
  end

  def security_rule_usage(usage)
    case usage
    when nil then 0
    when :key then LibRnp::RNP_SECURITY_VERIFY_KEY
    when :data then LibRnp::RNP_SECURITY_VERIFY_DATA
    else raise ArgumentError, "invalid security rule usage: #{usage.inspect}"
    end
  end

  def security_rule_time(time)
    time.is_a?(::Time) ? time.to_i : time
  end
end
