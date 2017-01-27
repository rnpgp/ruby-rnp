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

end

