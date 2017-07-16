#pragma once

#include "mstl_module.hpp"

class PEB : public Address, public Singleton<PEB> {
protected:
    std::vector<Module> m_modules;

public:

    // c/dtor
    ~PEB() {}
    PEB() :
        Address{util::get_peb()},
        m_modules{} {
    
        // basically an init
        update();
    }

    // empty and refill module vector
    __forceinline void update() {
        _PEB        *peb = as<_PEB*>();
        LIST_ENTRY *le = peb->Ldr->InLoadOrderModuleList.Flink;

        // check that the image loader is even valid
        if (le == nullptr)
            return;

        m_modules.clear();

        while (le != &peb->Ldr->InLoadOrderModuleList && le != nullptr) {
            m_modules.push_back(
                Module(CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks))
            );

            le = le->Flink;
        }
    }

    // try 2 get module
    __forceinline bool get_module(const hash_t module_hash, Module& out) {
        auto needle = std::find_if(
            m_modules.begin(),
            m_modules.end(),
            [ & ](const Module& it) {
            return it.get_hash() == module_hash;
        });
        
        if (needle >= m_modules.end()) {
            return false;
        }

        out = *needle;
        return true;
    }


    // small helper methods
    __forceinline Address get_base(const hash_t module_hash) {
        Address ret{};
        Module  out;

        if (!get_module(module_hash, out))
            return ret;

        ret = out.as();

        return ret;
    }
    __forceinline size_t get_size(const hash_t module_hash) {
        size_t  ret{};
        Module  out;

        if (!get_module(module_hash, out))
            return ret;

        ret = out.get_img_size();

        return ret;
    }
};