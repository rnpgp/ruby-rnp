require 'ffi'

module LibNetPGP

  def self.dynarray_count(struct, field)
    struct[(field + 'c').to_sym]
  end

  def self.dynarray_vsize(struct, field)
    struct[(field + 'vsize').to_sym]
  end

  def self.dynarray_items(struct, field)
    struct[(field + 's').to_sym]
  end

  def self.dynarray_get_item(struct, field, type, index)
    count = dynarray_count(struct, field)
    if index >= count
      return nil
    end

    items = dynarray_items(struct, field)
    case type
    when :pointer
      ptrs = items.read_array_of_pointer(count)
      ptrs[index]
    when :string
      ptrs = items.read_array_of_pointer(count)
      ptrs[index].read_string
    else
      ptrs = FFI::Pointer.new(type, items)
      type.new(ptrs[index])
    end
  end

  # Appends an item to a DYNARRAY, expanding the array as needed.
  #
  # @param struct [FFI::Struct] Structure where the DYNARRAY is held.
  # @param field [String] The name of the DYNARRAY within the structure.
  #   For example, this would be 'uid' if the array were declared natively
  #   with something like DYNARRAY(uint8_t*, uid);
  # @param type [FFI::Struct, :pointer, :string] The type (class) of the
  #   elements in the DYNARRAY, or the special values :pointer or :string.
  # @param value [FFI::Struct, FFI::Pointer, String] The value to append. When 
  #   type is an FFI::Struct class, the bytes will be copied from the struct,
  #   directly to the DYNARRAY memory.
  #   When type is :pointer, the pointer (not data) is copied to the DYNARRAY.
  #   When type is :string, the string data will be allocated and a pointer will
  #   be copied in to the DYNARRAY.
  def self.dynarray_append_item(struct, field, type, value)
    dynarray_expand(struct, field, type)

    count = dynarray_count(struct, field)
    items = dynarray_items(struct, field)
    case type
    when :pointer
      ptrs = items.read_array_of_pointer(count + 1)
      ptrs[count] = value
      items.write_array_of_pointer(ptrs)
    when :string
      ptrs = items.read_array_of_pointer(count + 1)
      mem = LibC::calloc(1, value.size + 1)
      mem.write_bytes(value)
      ptrs[count] = mem
      items.write_array_of_pointer(ptrs)
    else
      ptrs = FFI::Pointer.new(type, items)
      bytes = value.pointer.read_bytes(type.size)
      ptrs[count].write_bytes(bytes)
    end
    struct[(field + 'c').to_sym] = count + 1
  end

  def self.dynarray_expand(struct, field, type)
    count = dynarray_count(struct, field)
    vsize = dynarray_vsize(struct, field)
    # return if expansion is not necessary
    return if count != vsize

    newvsize = (vsize * 2) + 10
    mem = dynarray_items(struct, field)
    case type
    when :pointer, :string
      itemsize = FFI::Pointer.size
    else
      itemsize = type.size
    end
    newarr = LibC::realloc(mem, newvsize * itemsize)
    LibC::memset(newarr + (vsize * itemsize), 0, (newvsize - vsize) * itemsize)
    struct[(field + 'vsize').to_sym] = newvsize
    struct[(field + 's').to_sym] = newarr
  end
end

