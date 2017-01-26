require 'ffi'

require_relative 'enums'
require_relative 'structs'

module LibNetPGP
  extend FFI::Library
  ffi_lib ['libnetpgp.so.3.0', 'libnetpgp.so.3', 'libnetpgp.so']

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
  attach_function :pgp_keydata_free,
                  [:pointer],
                  :void

  attach_function :pgp_add_userid,
                  [PGPKey.by_ref, :string],
                  :strptr

  attach_function :pgp_add_selfsigned_userid,
                  [PGPKey.by_ref, :string],
                  :uint
end

