require 'ffi'

module LibC
  extend FFI::Library
  ffi_lib FFI::Library::LIBC

  attach_function :free,
                  [:pointer],
                  :void
end

