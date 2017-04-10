require 'ffi'

module LibOpenSSL
  extend FFI::Library
  ffi_lib ['ssl']

  # Caller must free result with OPENSSL_free aka (usually) LIBC free 
  attach_function :BN_bn2hex,
                  [:pointer],
                  :strptr
  attach_function :BN_hex2bn,
                  [:pointer, :string],
                  :int
end

