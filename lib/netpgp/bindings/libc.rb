require 'ffi'

module LibC
  extend FFI::Library
  ffi_lib FFI::Library::LIBC

  attach_function :calloc,
                  [:size_t, :size_t],
                  :pointer
  attach_function :free,
                  [:pointer],
                  :void

  attach_function :fdopen,
                  [:int, :string],
                  :pointer
  attach_function :fclose,
                  [:pointer],
                  :int
end

