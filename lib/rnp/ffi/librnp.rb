# frozen_string_literal: true

# (c) 2018-2020 Ribose Inc.

require 'ffi'

require 'rnp/error'

# @api private
module LibRnp
  extend FFI::Library

  LOCAL_LIBRNP = File.join(File.dirname(__FILE__), FFI.map_library_name("rnp"))

  ffi_lib [LOCAL_LIBRNP, "rnp-0", "rnp"]

  # some newer APIs that may not be present
  {
    # key export
    rnp_key_export: [%i[pointer pointer uint32], :uint32],
    # enarmor/dearmor
    rnp_enarmor: [%i[pointer pointer pointer], :uint32],
    rnp_dearmor: [%i[pointer pointer], :uint32],
    # versioning
    rnp_version_string: [%i[], :string],
    rnp_version_string_full: [%i[], :string],
    rnp_version: [%i[], :uint32],
    rnp_version_for: [%i[uint32 uint32 uint32], :uint32],
    rnp_version_major: [%i[uint32], :uint32],
    rnp_version_minor: [%i[uint32], :uint32],
    rnp_version_patch: [%i[uint32], :uint32],
    # unload keys
    rnp_unload_keys: [%i[pointer uint32], :uint32],
    # remove key
    rnp_key_remove: [%i[pointer uint32], :uint32],
    # key properties
    rnp_key_get_subkey_count: [%i[pointer pointer], :uint32],
    rnp_key_get_subkey_at: [%i[pointer int pointer], :uint32],
    rnp_key_get_alg: [%i[pointer pointer], :uint32],
    rnp_key_get_bits: [%i[pointer pointer], :uint32],
    rnp_key_get_dsa_qbits: [%i[pointer pointer], :uint32],
    rnp_key_get_curve: [%i[pointer pointer], :uint32],
    rnp_key_allows_usage: [%i[pointer string pointer], :uint32],
    # packet dumping
    rnp_key_packets_to_json: [%i[pointer bool uint32 pointer], :uint32],
    rnp_dump_packets_to_json: [%i[pointer uint32 pointer], :uint32],
    # aead
    rnp_op_encrypt_set_aead: [%i[pointer string], :uint32],
    # key generation (op)
    rnp_op_generate_create: [%i[pointer pointer string], :uint32],
    rnp_op_generate_subkey_create: [%i[pointer pointer pointer string],
                                    :uint32],
    rnp_op_generate_set_bits: [%i[pointer uint32], :uint32],
    rnp_op_generate_set_hash: [%i[pointer string], :uint32],
    rnp_op_generate_set_dsa_qbits: [%i[pointer uint32], :uint32],
    rnp_op_generate_set_curve: [%i[pointer string], :uint32],
    rnp_op_generate_set_protection_password: [%i[pointer string], :uint32],
    rnp_op_generate_set_protection_cipher: [%i[pointer string], :uint32],
    rnp_op_generate_set_protection_hash: [%i[pointer string], :uint32],
    rnp_op_generate_set_protection_mode: [%i[pointer string], :uint32],
    rnp_op_generate_set_protection_iterations: [%i[pointer uint32], :uint32],
    rnp_op_generate_add_usage: [%i[pointer string], :uint32],
    rnp_op_generate_clear_usage: [%i[pointer], :uint32],
    rnp_op_generate_set_userid: [%i[pointer string], :uint32],
    rnp_op_generate_set_expiration: [%i[pointer uint32], :uint32],
    rnp_op_generate_add_pref_hash: [%i[pointer string], :uint32],
    rnp_op_generate_clear_pref_hashes: [%i[pointer], :uint32],
    rnp_op_generate_add_pref_compression: [%i[pointer string], :uint32],
    rnp_op_generate_clear_pref_compression: [%i[pointer], :uint32],
    rnp_op_generate_add_pref_cipher: [%i[pointer string], :uint32],
    rnp_op_generate_clear_pref_ciphers: [%i[pointer], :uint32],
    rnp_op_generate_set_pref_keyserver: [%i[pointer pointer], :uint32],
    rnp_op_generate_execute: [%i[pointer], :uint32],
    rnp_op_generate_get_key: [%i[pointer pointer], :uint32],
    rnp_op_generate_destroy: [%i[pointer], :uint32],
    # key generation (shortcuts)
    rnp_generate_key_rsa: [%i[pointer uint32 uint32 string string pointer],
                           :uint32],
    rnp_generate_key_dsa_eg: [%i[pointer uint32 uint32 string string pointer],
                              :uint32],
    rnp_generate_key_ec: [%i[pointer string string string pointer], :uint32],
    rnp_generate_key_25519: [%i[pointer string string pointer], :uint32],
    rnp_generate_key_sm2: [%i[pointer string string pointer], :uint32],
    rnp_generate_key_ex: [%i[pointer string string uint32 uint32 string string
                             string string pointer], :uint32],
    rnp_calculate_iterations: [%i[string size_t pointer], :uint32],
    # debugging
    rnp_enable_debug: [%i[pointer], :uint32],
    rnp_disable_debug: [%i[], :uint32],
    # guess contents
    rnp_guess_contents: [%i[pointer pointer], :uint32],
    # features
    rnp_supports_feature: [%i[string string pointer], :uint32],
    rnp_supported_features: [%i[string pointer], :uint32],
    # key revocation
    rnp_key_is_revoked: [%i[pointer pointer], :uint32],
    rnp_key_is_compromised: [%i[pointer pointer], :uint32],
    rnp_key_is_retired: [%i[pointer pointer], :uint32],
    rnp_key_is_superseded: [%i[pointer pointer], :uint32],
    rnp_key_get_revocation_reason: [%i[pointer pointer], :uint32],
    # signatures
    rnp_key_get_signature_count: [%i[pointer pointer], :uint32],
    rnp_key_get_signature_at: [%i[pointer size_t pointer], :uint32],
    rnp_signature_get_alg: [%i[pointer pointer], :uint32],
    rnp_signature_get_hash_alg: [%i[pointer pointer], :uint32],
    rnp_signature_get_creation: [%i[pointer pointer], :uint32],
    rnp_signature_get_keyid: [%i[pointer pointer], :uint32],
    rnp_signature_get_signer: [%i[pointer pointer], :uint32],
    rnp_signature_packet_to_json: [%i[pointer uint32 pointer], :uint32],
    rnp_signature_handle_destroy: [%i[pointer], :uint32],
    rnp_op_verify_signature_get_handle: [%i[pointer pointer], :uint32],
    # key uids
    rnp_key_get_uid_handle_at: [%i[pointer size_t pointer], :uint32],
    rnp_uid_is_revoked: [%i[pointer pointer], :uint32],
    rnp_uid_handle_destroy: [%i[pointer], :uint32],
    rnp_uid_get_signature_count: [%i[pointer pointer], :uint32],
    rnp_uid_get_signature_at: [%i[pointer size_t pointer], :uint32],
    # key properties
    rnp_key_get_creation: [%i[pointer pointer], :uint32],
    rnp_key_get_expiration: [%i[pointer pointer], :uint32],
    rnp_key_get_primary_grip: [%i[pointer pointer], :uint32],
    # output
    rnp_output_write: [%i[pointer pointer size_t pointer], :uint32],
    # import
    rnp_import_keys: [%i[pointer pointer uint32 pointer], :uint32],
    rnp_import_signatures: [%i[pointer pointer uint32 pointer], :uint32],
  }.each do |name, signature|
    present = !ffi_libraries[0].find_function(name.to_s).nil?
    if !present
      class_eval do
        define_singleton_method(name) do |*|
          raise Rnp::FeatureNotAvailableError, name
        end
      end
    else
      attach_function name, signature[0], signature[1]
    end
    class_eval do
      const_set("HAVE_#{name.upcase}", present)
    end
  end

  if ffi_libraries[0].find_function('rnp_version_commit_timestamp')
    attach_function :rnp_version_commit_timestamp, [], :uint64
  else
    def self.rnp_version_commit_timestamp
      0
    end
  end

  if HAVE_RNP_VERSION && (rnp_version >= rnp_version_for(0, 14, 0) ||
                         rnp_version_commit_timestamp >= 1585833163)
    callback        :rnp_input_reader_t,
                    %i[pointer pointer size_t pointer],
                    :bool
  else
    callback        :rnp_input_reader_t,
                    %i[pointer pointer size_t],
                    :ssize_t
  end


  callback        :rnp_get_key_cb,
                  %i[pointer pointer string string bool],
                  :void
  callback        :rnp_password_cb,
                  %i[pointer pointer pointer string pointer size_t],
                  :bool
  callback        :rnp_output_writer_t,
                  %i[pointer pointer size_t],
                  :bool

  attach_function :rnp_result_to_string,
                  %i[uint32],
                  :string
  attach_function :rnp_ffi_create,
                  %i[pointer string string],
                  :uint32
  attach_function :rnp_ffi_destroy,
                  %i[pointer],
                  :uint32
  attach_function :rnp_ffi_set_log_fd,
                  %i[pointer int],
                  :uint32
  attach_function :rnp_ffi_set_key_provider,
                  %i[pointer rnp_get_key_cb pointer],
                  :uint32
  attach_function :rnp_ffi_set_pass_provider,
                  %i[pointer rnp_password_cb pointer],
                  :uint32
  attach_function :rnp_get_default_homedir,
                  %i[pointer],
                  :uint32
  attach_function :rnp_detect_homedir_info,
                  %i[string pointer pointer pointer pointer],
                  :uint32
  attach_function :rnp_detect_key_format,
                  %i[pointer size_t pointer],
                  :uint32
  attach_function :rnp_load_keys,
                  %i[pointer string pointer uint32],
                  :uint32
  attach_function :rnp_save_keys,
                  %i[pointer string pointer uint32],
                  :uint32
  attach_function :rnp_get_public_key_count,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_get_secret_key_count,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_locate_key,
                  %i[pointer string string pointer],
                  :uint32
  attach_function :rnp_key_handle_destroy,
                  %i[pointer],
                  :uint32
  attach_function :rnp_generate_key_json,
                  %i[pointer string pointer],
                  :uint32
  attach_function :rnp_key_get_primary_uid,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_get_uid_count,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_get_uid_at,
                  %i[pointer size_t pointer],
                  :uint32
  attach_function :rnp_key_add_uid,
                  %i[pointer string string uint32 uint8 bool],
                  :uint32
  attach_function :rnp_key_get_fprint,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_get_keyid,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_get_grip,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_is_locked,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_lock,
                  %i[pointer],
                  :uint32
  attach_function :rnp_key_unlock,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_is_protected,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_protect,
                  %i[pointer string string string string size_t],
                  :uint32
  attach_function :rnp_key_unprotect,
                  %i[pointer string],
                  :uint32
  attach_function :rnp_key_is_primary,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_is_sub,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_have_secret,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_key_have_public,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_op_sign_create,
                  %i[pointer pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_sign_cleartext_create,
                  %i[pointer pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_sign_detached_create,
                  %i[pointer pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_sign_add_signature,
                  %i[pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_sign_signature_set_hash,
                  %i[pointer string],
                  :uint32
  attach_function :rnp_op_sign_signature_set_creation_time,
                  %i[pointer uint32],
                  :uint32
  attach_function :rnp_op_sign_signature_set_expiration_time,
                  %i[pointer uint32],
                  :uint32
  attach_function :rnp_op_sign_set_compression,
                  %i[pointer string int],
                  :uint32
  attach_function :rnp_op_sign_set_armor,
                  %i[pointer bool],
                  :uint32
  attach_function :rnp_op_sign_set_hash,
                  %i[pointer string],
                  :uint32
  attach_function :rnp_op_sign_set_creation_time,
                  %i[pointer uint32],
                  :uint32
  attach_function :rnp_op_sign_set_expiration_time,
                  %i[pointer uint32],
                  :uint32
  attach_function :rnp_op_sign_execute,
                  %i[pointer],
                  :uint32
  attach_function :rnp_op_sign_destroy,
                  %i[pointer],
                  :uint32
  attach_function :rnp_op_verify_create,
                  %i[pointer pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_verify_detached_create,
                  %i[pointer pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_verify_execute,
                  %i[pointer],
                  :uint32
  attach_function :rnp_op_verify_get_signature_count,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_op_verify_get_signature_at,
                  %i[pointer size_t pointer],
                  :uint32
  attach_function :rnp_op_verify_get_file_info,
                  %i[pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_verify_destroy,
                  %i[pointer],
                  :uint32
  attach_function :rnp_op_verify_signature_get_status,
                  %i[pointer],
                  :uint32
  attach_function :rnp_op_verify_signature_get_hash,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_op_verify_signature_get_key,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_op_verify_signature_get_times,
                  %i[pointer pointer pointer],
                  :uint32
  attach_function :rnp_buffer_destroy,
                  %i[pointer],
                  :void
  attach_function :rnp_input_from_path,
                  %i[pointer string],
                  :uint32
  attach_function :rnp_input_from_memory,
                  %i[pointer pointer size_t bool],
                  :uint32
  attach_function :rnp_input_from_callback,
                  %i[pointer rnp_input_reader_t pointer pointer],
                  :uint32
  attach_function :rnp_input_destroy,
                  %i[pointer],
                  :uint32
  attach_function :rnp_output_to_path,
                  %i[pointer string],
                  :uint32
  attach_function :rnp_output_to_memory,
                  %i[pointer size_t],
                  :uint32
  attach_function :rnp_output_memory_get_buf,
                  %i[pointer pointer pointer bool],
                  :uint32
  attach_function :rnp_output_to_callback,
                  %i[pointer rnp_output_writer_t pointer pointer],
                  :uint32
  attach_function :rnp_output_to_null,
                  %i[pointer],
                  :uint32
  attach_function :rnp_output_destroy,
                  %i[pointer],
                  :uint32
  attach_function :rnp_op_encrypt_create,
                  %i[pointer pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_encrypt_add_recipient,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_op_encrypt_add_signature,
                  %i[pointer pointer pointer],
                  :uint32
  attach_function :rnp_op_encrypt_set_hash,
                  %i[pointer string],
                  :uint32
  attach_function :rnp_op_encrypt_set_creation_time,
                  %i[pointer uint32],
                  :uint32
  attach_function :rnp_op_encrypt_set_expiration_time,
                  %i[pointer uint32],
                  :uint32
  attach_function :rnp_op_encrypt_add_password,
                  %i[pointer string string size_t string],
                  :uint32
  attach_function :rnp_op_encrypt_set_armor,
                  %i[pointer bool],
                  :uint32
  attach_function :rnp_op_encrypt_set_cipher,
                  %i[pointer string],
                  :uint32
  attach_function :rnp_op_encrypt_set_compression,
                  %i[pointer string int],
                  :uint32
  attach_function :rnp_op_encrypt_execute,
                  %i[pointer],
                  :uint32
  attach_function :rnp_op_encrypt_destroy,
                  %i[pointer],
                  :uint32
  attach_function :rnp_decrypt,
                  %i[pointer pointer pointer],
                  :uint32
  attach_function :rnp_get_public_key_data,
                  %i[pointer pointer pointer],
                  :uint32
  attach_function :rnp_get_secret_key_data,
                  %i[pointer pointer pointer],
                  :uint32
  attach_function :rnp_key_to_json,
                  %i[pointer uint32 pointer],
                  :uint32
  attach_function :rnp_identifier_iterator_create,
                  %i[pointer pointer string],
                  :uint32
  attach_function :rnp_identifier_iterator_next,
                  %i[pointer pointer],
                  :uint32
  attach_function :rnp_identifier_iterator_destroy,
                  %i[pointer],
                  :uint32

  RNP_KEY_EXPORT_ARMORED = (1 << 0)
  RNP_KEY_EXPORT_PUBLIC =  (1 << 1)
  RNP_KEY_EXPORT_SECRET =  (1 << 2)
  RNP_KEY_EXPORT_SUBKEYS = (1 << 3)

  RNP_LOAD_SAVE_PUBLIC_KEYS = (1 << 0)
  RNP_LOAD_SAVE_SECRET_KEYS = (1 << 1)

  RNP_KEY_UNLOAD_PUBLIC = (1 << 0)
  RNP_KEY_UNLOAD_SECRET = (1 << 1)

  RNP_KEY_REMOVE_PUBLIC = (1 << 0)
  RNP_KEY_REMOVE_SECRET = (1 << 1)

  RNP_JSON_PUBLIC_MPIS = (1 << 0)
  RNP_JSON_SECRET_MPIS = (1 << 1)
  RNP_JSON_SIGNATURES = (1 << 2)
  RNP_JSON_SIGNATURE_MPIS = (1 << 3)

  RNP_JSON_DUMP_MPI = (1 << 0)
  RNP_JSON_DUMP_RAW = (1 << 1)
  RNP_JSON_DUMP_GRIP = (1 << 2)

  RNP_SUCCESS = 0
  RNP_ERROR_BAD_FORMAT =        0x10000001
  RNP_ERROR_SIGNATURE_INVALID = 0x12000002
  RNP_ERROR_BAD_PASSWORD =      0x12000004
  RNP_ERROR_NO_SUITABLE_KEY =   0x12000006
  RNP_ERROR_SIGNATURE_EXPIRED = 0x1200000B
end # module

