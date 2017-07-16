#pragma once

#include "mstl_image_dir.hpp"

using import_t  = std::pair<Address, hash_t>;
using imports_t = std::vector<import_t>;

class IAT : public IMAGE_DIR<IMAGE_DIRECTORY_ENTRY_IMPORT> {
private:
    imports_t m_imports;

public:
    // c/dtor
    __forceinline  IAT() : IMAGE_DIR{}, m_imports{} {}
    __forceinline ~IAT() {}

    // only ever constructed with a ptr to a PE image
    IAT(Address image_base) :
        IMAGE_DIR<IMAGE_DIRECTORY_ENTRY_IMPORT>(image_base) {

        // sometimes there are no imports or exports for a module.. 
        if (m_ptr)
            init(image_base);
    }

    __forceinline void init(uintptr_t image_base) {
        IMAGE_IMPORT_DESCRIPTOR *id{};
        IMAGE_IMPORT_BY_NAME    *import{};
        IMAGE_THUNK_DATA        *thunk_data{};
        size_t                   functions = 0;

        id = as<IMAGE_IMPORT_DESCRIPTOR*>();
        
        if (id == nullptr)
            return;

        for (; id->Name; ++id) {
            thunk_data = RVA<IMAGE_THUNK_DATA*>(image_base, id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk);
            
            while (thunk_data->u1.AddressOfData) {
                import = RVA<IMAGE_IMPORT_BY_NAME*>(image_base, thunk_data->u1.AddressOfData);

                // only push imports by name
                if (thunk_data->u1.AddressOfData < IMAGE_ORDINAL_FLAG && import->Name[0]) {
                    m_imports.push_back(
                        import_t{
                        id->FirstThunk ? id->FirstThunk + functions : thunk_data->u1.AddressOfData - image_base,
                        hash::djb2(import->Name)
                    });
                }

                thunk_data++;
                functions += sizeof(Address);
            }
        }
    }

    __forceinline imports_t& get_imports() {
        return m_imports;
    }

    __forceinline bool get_import(hash_t import_hash, import_t& out) {
        auto needle = std::find_if(
            m_imports.begin(),
            m_imports.end(),
            [ & ](const import_t& it) {
            return it.second == import_hash;
        });

        if (needle >= m_imports.end())
            return false;

        out = *needle;
        return true;
    }

    __forceinline void hook_method(hash_t method_hash, Address hook) {
        import_t ret;

        if (!get_import(method_hash, ret))
            return;

        return ret.first.set(hook);
    }

    template<typename _T = Address>
    __forceinline _T get_method(hash_t method_hash) {
        import_t ret;

        if (!get_import(method_hash, ret))
            return _T{};

        return ret.first.as<_T>();
    }
};
