require 'netpgp.rb'

describe 'dynarray utils' do
  it 'expands correctly' do
    key = LibNetPGP::PGPKey.new
    expect(
      LibNetPGP::dynarray_count(key, 'uid')
    ).to eql 0
    expect(
      LibNetPGP::dynarray_vsize(key, 'uid')
    ).to eql 0

    LibNetPGP::dynarray_expand(key, 'uid', :string)

    expect(
      LibNetPGP::dynarray_count(key, 'uid')
    ).to eql 0
    expect(
      LibNetPGP::dynarray_vsize(key, 'uid')
    ).to_not eql 0
 
    count = 0
    while LibNetPGP::dynarray_count(key, 'uid') != LibNetPGP::dynarray_vsize(key, 'uid') do
      LibNetPGP::dynarray_append_item(key, 'uid', :string, 'Test')
      count += 1
    end
    expect(
      LibNetPGP::dynarray_count(key, 'uid')
    ).to eql count

    LibNetPGP::dynarray_append_item(key, 'uid', :string, 'Test')
    expect(
      LibNetPGP::dynarray_vsize(key, 'uid')
    ).to be >= count
  end

  it 'appends/retrieves strings correctly' do
    key = LibNetPGP::PGPKey.new
    (0..3).each {|n|
      LibNetPGP::dynarray_append_item(key, 'uid', :string, "Test#{n}")
    }
    (0..3).each {|n|
      item = LibNetPGP::dynarray_get_item(key, 'uid', :string, n)
      expect(item).to eql "Test#{n}"
      expect(item.class).to eql String
    }
  end

  it 'appends/retrieves pointers correctly' do
    key = LibNetPGP::PGPKey.new
    str_ptrs = []
    (0..3).each {|n|
      str = "Test#{n}"
      # we let these leak
      str_ptr = LibC::calloc(1, str.bytesize + 1)
      str_ptr.write_string(str)
      str_ptrs.push(str_ptr)
      LibNetPGP::dynarray_append_item(key, 'uid', :pointer, str_ptr)
    }
    (0..3).each {|n|
      item = LibNetPGP::dynarray_get_item(key, 'uid', :pointer, n)
      expect(item.address).to eql str_ptrs[n].address
      expect(item.read_string).to eql "Test#{n}"
      expect(item.class).to eql FFI::Pointer
    }
   end

  it 'appends/retrieves structures correctly' do
    key = LibNetPGP::PGPKey.new
    str_ptrs = []
    (0..3).each {|n|
      revoke_ptr = LibC::calloc(1, LibNetPGP::PGPRevoke.size)
      revoke = LibNetPGP::PGPRevoke.new(revoke_ptr)
      revoke[:uid] = n
      revoke[:code] = n
      str = "Test#{n}"
      str_ptr = LibC::calloc(1, str.bytesize + 1)
      str_ptr.write_string(str)
      str_ptrs.push(str_ptr)
      # Normally you can't set a :string field in an FFI::Struct.
      # So we workaround this for the sake of the spec.
      revoke.pointer.put_pointer(revoke.offset_of(:reason), str_ptr)

      LibNetPGP::dynarray_append_item(key, 'revoke', LibNetPGP::PGPRevoke, revoke)
    }
    (0..3).each {|n|
      revoke = LibNetPGP::dynarray_get_item(key, 'revoke', LibNetPGP::PGPRevoke, n)
      expect(revoke[:uid]).to eql n
      expect(revoke[:code]).to eql n
      expect(revoke[:reason]).to eql "Test#{n}"
      expect(
        revoke.pointer.get_pointer(revoke.offset_of(:reason)).address
      ).to eql str_ptrs[n].address
    }
  end

end

