require 'ffi'

module LibOpenSSL
  extend FFI::Library
  ffi_lib ['libssl.so.10.6', 'libssl.so.10', 'libssl.so']

  # Caller must free result with OPENSSL_free aka (usually) LIBC free 
  attach_function :BN_bn2hex,
                  [:pointer],
                  :strptr
end

