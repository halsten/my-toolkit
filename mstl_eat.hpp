#pragma once

#include "mstl_image_dir.hpp"

/*  
    @Address     - pointer to function pointer
    @hash_t      - djb2 hash of name
*/

using export_t  = std::pair<Address, hash_t>;
using exports_t = std::vector<export_t>;

class EAT : public IMAGE_DIR<IMAGE_DIRECTORY_ENTRY_EXPORT> {
private:
    exports_t m_exports;

public:
    __forceinline  EAT() : IMAGE_DIR{}, m_exports{} {}
    __forceinline ~EAT() {}

    EAT(Address image_base):
        IMAGE_DIR<IMAGE_DIRECTORY_ENTRY_EXPORT>(image_base) {

        // sometimes there are no imports or exports for a module.. 
        if(m_ptr)
            init(image_base);
    }

    __forceinline void init(uintptr_t image_base) {
        IMAGE_EXPORT_DIRECTORY *ed;
        uint32_t               *names, *fn_ptrs;
        uint16_t               *name_ordinals;

        // get export directory
        ed = as<IMAGE_EXPORT_DIRECTORY*>();

        // first see if there are any exports
        if (ed->NumberOfFunctions == 0 || ed->NumberOfNames == 0)
            return;

        // get arrays from rva
        names         = RVA<uint32_t*>(image_base, ed->AddressOfNames);
        fn_ptrs       = RVA<uint32_t*>(image_base, ed->AddressOfFunctions);
        name_ordinals = RVA<uint16_t*>(image_base, ed->AddressOfNameOrdinals);

        // check
        if (   names == nullptr 
            || fn_ptrs == nullptr
            || name_ordinals == nullptr)
            return;

        // stuff
        for (size_t i{}; i < ed->NumberOfNames; ++i) {
            m_exports.push_back(
                export_t{
                    RVA(image_base, fn_ptrs[name_ordinals[i]]),
                    hash::djb2(RVA<const char*>(image_base, names[i]))
            });
        }
    }

    __forceinline exports_t& get_exports() {
        return m_exports;
    }

    __forceinline bool get_export(hash_t export_hash, export_t& out) {
        auto needle = std::find_if(
            m_exports.begin(),
            m_exports.end(),
            [ & ](const export_t& it) {
            return it.second == export_hash;
        });

        if (needle >= m_exports.end())
            return false;

        out = *needle;
        return true;
    }

    __forceinline void hook_method(hash_t method_hash, Address hook) {
        export_t ret;

        if (!get_export(method_hash, ret))
            return;

        return ret.first.set(hook);
    }

    template<typename _T = Address>
    __forceinline _T get_method(hash_t method_hash) {
        export_t ret;

        if (!get_export(method_hash, ret))
            return _T{};

        return ret.first.as<_T>();
    }
};