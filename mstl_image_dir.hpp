#pragma once

#include "mstl_address.hpp"

template<size_t data_directory>
class IMAGE_DIR : public Address {
public:
    __forceinline  IMAGE_DIR() : Address{} {}
    __forceinline ~IMAGE_DIR() {}

    IMAGE_DIR(Address image_base) :
        Address{image_base} {

        init();
    }

    __forceinline void init() {
        IMAGE_DATA_DIRECTORY *dir;
        IMAGE_DOS_HEADER     *dos;
        IMAGE_NT_HEADERS     *nt;

        // init dos header from as (image base)
        dos = as<IMAGE_DOS_HEADER*>();

        // sanity check image really quick
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return;

        // init nt header
        nt = RVA<IMAGE_NT_HEADERS*>(as(), dos->e_lfanew);

        // sanity check nt header rl quick
        if (nt == nullptr || nt->Signature != IMAGE_NT_SIGNATURE)
            return;

        // get RVA of our desired directory
        dir = &nt->OptionalHeader.DataDirectory[data_directory];

        // set and finish
        m_ptr = RVA(as(), dir->VirtualAddress);
    }

    // get the dir we're fkn with
    constexpr size_t get_directory() const {
        return data_directory;
    };
};