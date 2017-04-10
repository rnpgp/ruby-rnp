require 'ffi'

require_relative 'enums'
require_relative 'structs'

module LibRNP
  extend FFI::Library
  ffi_lib ['rnp']

  attach_function :pgp_parse_options,
                  [PGPStream.by_ref, :pgp_content_enum, :pgp_parse_type_t],
                  :void
  attach_function :pgp_reader_set_fd,
                  [PGPStream.by_ref, :int],
                  :void
  attach_function :pgp_reader_set_memory,
                  [PGPStream.by_ref, :pointer, :size_t],
                  :void
  attach_function :pgp_set_callback,
                  [PGPStream.by_ref, :pgp_cbfunc_t, :pointer],
                  :void
  attach_function :pgp_reader_push_dearmour,
                  [PGPStream.by_ref],
                  :void
  attach_function :pgp_reader_pop_dearmour,
                  [PGPStream.by_ref],
                  :void
  attach_function :pgp_parse_and_accumulate,
                  [PGPKeyring.by_ref, PGPStream.by_ref],
                  :int
  attach_function :pgp_callback_push,
                  [PGPStream.by_ref, :pgp_cbfunc_t, :pointer],
                  :void
  attach_function :pgp_parse,
                  [PGPStream.by_ref, :int],
                  :int

  attach_function :pgp_rsa_new_selfsign_key,
                  [:int, :ulong, :string, :string, :string],
                  PGPKey.by_ref
  attach_function :pgp_rsa_new_key,
                  [:int, :ulong, :string, :string],
                  PGPKey.by_ref
  attach_function :pgp_keydata_free,
                  [:pointer],
                  :void

  attach_function :pgp_add_userid,
                  [PGPKey.by_ref, :string],
                  :strptr

  attach_function :pgp_add_selfsigned_userid,
                  [PGPKey.by_ref, :string],
                  :uint

  attach_function :pgp_keyring_free,
                  [:pointer],
                  :void
  attach_function :pgp_pubkey_free,
                  [:pointer],
                  :void
  attach_function :pgp_seckey_free,
                  [:pointer],
                  :void

  attach_function :pgp_keyring_fileread,
                  [PGPKeyring.by_ref, :uint, :string],
                  :uint
  attach_function :pgp_keyring_read_from_mem,
                  [PGPIO.by_ref, PGPKeyring.by_ref, :uint, PGPMemory.by_ref],
                  :uint

  attach_function :pgp_sign_file,
                  [PGPIO.by_ref, :string, :string, PGPSecKey.by_ref, :string, :int64, :uint64, :uint, :uint, :uint],
                  :uint
  attach_function :pgp_sign_detached,
                  [PGPIO.by_ref, :string, :string, PGPSecKey.by_ref, :string, :int64, :uint64, :uint, :uint],
                  :int
  attach_function :pgp_sign_buf,
                  [PGPIO.by_ref, :pointer, :size_t, PGPSecKey.by_ref, :int64, :uint64, :string, :uint, :uint],
                  :pointer
  attach_function :pgp_validate_file,
                  [PGPIO.by_ref, PGPValidation.by_ref, :string, :string, :int, PGPKeyring.by_ref],
                  :uint
  attach_function :pgp_validate_mem,
                  [PGPIO.by_ref, PGPValidation.by_ref, PGPMemory.by_ref, :pointer, :int, PGPKeyring.by_ref],
                  :uint

  attach_function :pgp_encrypt_file,
                  [PGPIO.by_ref, :string, :string, PGPKey.by_ref, :uint, :uint, :string],
                  :uint
  attach_function :pgp_encrypt_buf,
                  [PGPIO.by_ref, :pointer, :size_t, PGPKey.by_ref, :uint, :string],
                  :pointer
  attach_function :pgp_decrypt_file,
                  [PGPIO.by_ref, :string, :string, PGPKeyring.by_ref, PGPKeyring.by_ref, :uint, :uint, :uint, :pointer, :int, :pgp_cbfunc_t],
                  :uint
  attach_function :pgp_decrypt_buf,
                  [PGPIO.by_ref, :pointer, :size_t, PGPKeyring.by_ref, PGPKeyring.by_ref, :uint, :uint, :pointer, :int, :pgp_cbfunc_t],
                  :pointer

  attach_function :pgp_export_key,
                  [PGPIO.by_ref, PGPKey.by_ref, :string],
                  :string

  attach_function :pgp_memory_new,
                  [],
                  PGPMemory.by_ref
  attach_function :pgp_memory_free,
                  [PGPMemory.by_ref],
                  :void
  attach_function :pgp_memory_init,
                  [PGPMemory.by_ref, :size_t],
                  :void
  attach_function :pgp_memory_pad,
                  [PGPMemory.by_ref, :size_t],
                  :void
  attach_function :pgp_memory_add,
                  [PGPMemory.by_ref, :pointer, :size_t],
                  :void
  attach_function :pgp_memory_place_int,
                  [PGPMemory.by_ref, :uint, :uint, :size_t],
                  :void
  attach_function :pgp_memory_make_packet,
                  [PGPMemory.by_ref, :pgp_content_enum],
                  :void
  attach_function :pgp_memory_clear,
                  [PGPMemory.by_ref],
                  :void
  attach_function :pgp_memory_release,
                  [PGPMemory.by_ref],
                  :void
  attach_function :pgp_mem_len,
                  [PGPMemory.by_ref],
                  :size_t
  attach_function :pgp_mem_data,
                  [PGPMemory.by_ref],
                  :pointer
  attach_function :pgp_mem_readfile,
                  [PGPMemory.by_ref, :string],
                  :int

  attach_function :pgp_is_key_secret,
                  [PGPKey.by_ref],
                  :uint
  attach_function :pgp_get_seckey,
                  [PGPKey.by_ref],
                  :pointer
  attach_function :pgp_decrypt_seckey,
                  [PGPKey.by_ref, :pointer],
                  :pointer

  attach_function :pgp_stream_delete,
                  [:pointer],
                  :void

  attach_function :pgp_setup_memory_write,
                  [:pointer, :pointer, :size_t],
                  :void
  attach_function :pgp_teardown_memory_write,
                  [PGPOutput.by_ref, PGPMemory.by_ref],
                  :void
  attach_function :pgp_write_xfer_pubkey,
                  [PGPOutput.by_ref, PGPKey.by_ref, :pointer, :uint],
                  :uint
  attach_function :pgp_write_xfer_seckey,
                  [PGPOutput.by_ref, PGPKey.by_ref, :pointer, :size_t, :pointer, :uint],
                  :uint

  attach_function :pgp_create_sig_new,
                  [],
                  :pointer
  attach_function :pgp_create_sig_delete,
                  [:pointer],
                  :void
  attach_function :pgp_sig_start_key_sig,
                  [:pointer, PGPPubKey.by_ref, :string, :pgp_sig_type_t],
                  :void
  attach_function :pgp_sig_start_subkey_sig,
                  [:pointer, PGPPubKey.by_ref, PGPPubKey.by_ref, :pgp_sig_type_t],
                  :void
  attach_function :pgp_write_sig,
                  [PGPOutput.by_ref, :pointer, PGPPubKey.by_ref, PGPSecKey.by_ref],
                  :uint
  attach_function :pgp_add_time,
                  [:pointer, :int64, :string],
                  :uint
  attach_function :pgp_add_issuer_keyid,
                  [:pointer, :pointer],
                  :uint
  attach_function :pgp_end_hashed_subpkts,
                  [:pointer],
                  :uint

  attach_function :pgp_add_subpacket,
                  [PGPKey.by_ref, PGPSubPacket.by_ref],
                  :pointer

  attach_function :pgp_fingerprint,
                  [PGPFingerprint.by_ref, PGPPubKey.by_ref, :pgp_hash_alg_t],
                  :int
  attach_function :pgp_keyid,
                  [:pointer, :size_t, PGPPubKey.by_ref, :pgp_hash_alg_t],
                  :int

  attach_function :pgp_writer_close,
                  [PGPOutput.by_ref],
                  :uint
  attach_function :pgp_output_delete,
                  [PGPOutput.by_ref],
                  :void
end

