#pragma once

#include "mstl_hash.hpp"
#include "mstl_util.hpp"
#include "mstl_iat.hpp"
#include "mstl_eat.hpp"
#include "mstl_xor.hpp"

enum class nt_static_module : size_t {
    base,
    nt,
    kernel32,
    kernelbase
};

class Module : public Address {
protected:
    std::string  m_name;
    hash_t       m_hash;
    size_t       m_image_size;

    IAT          m_iat;
    EAT          m_eat;

public:

    // d/ctor
    __forceinline Module() :
        Address{},
        m_image_size{},
        m_name{},
        m_hash{},
        m_iat{},
        m_eat{} {};

    ~Module() {}

    // ctor by static index
    Module(nt_static_module static_module) {
        init_by_entry(
            get_image_entry(std::underlying_type<nt_static_module>::type(static_module))
        );
    }

    // ctor by image base addr
    __forceinline Module(Address image_base) :
        Address{image_base} {

        // init iat/eat
        m_iat = IAT(m_ptr);
        m_eat = EAT(m_ptr);
    }

    // ctor assuming all info is already found
    __forceinline Module(const std::string& name, uintptr_t image_base, size_t image_size) :
        Address{image_base},
        m_image_size{image_size},
        m_name{name},
        m_hash{hash::djb2(name)} {

        // init iat/eat
        m_iat = IAT(m_ptr);
        m_eat = EAT(m_ptr);
    }

    // init by entry
    __forceinline Module(LDR_DATA_TABLE_ENTRY* image_entry) {
        init_by_entry(image_entry);
    }

    __forceinline void init_by_entry(LDR_DATA_TABLE_ENTRY* image_entry) {
        // get base and size of image
        m_ptr = image_entry->DllBase;
        m_image_size = image_entry->SizeOfImage;

        // save name and djb2 hash of name
        m_name = util::wide_to_multibyte(image_entry->BaseDllName.Buffer);
        m_hash = hash::djb2(m_name);

        io::print("%s %d\n", m_name.c_str(), m_hash);

        // init the iat and eat helper classes
        m_iat = IAT(m_ptr);
        m_eat = EAT(m_ptr);
    }

    __forceinline LDR_DATA_TABLE_ENTRY* get_image_entry(size_t index) {
        LIST_ENTRY           *le;
        LDR_DATA_TABLE_ENTRY *cur;
        _PEB                  *peb = util::get_peb();

        le = peb->Ldr->InLoadOrderModuleList.Flink;

        while (index-- && le != &peb->Ldr->InLoadOrderModuleList && le != nullptr)
            le = le->Flink;

        cur = CONTAINING_RECORD(le, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        return cur;
    }

    __forceinline std::string get_name() {
        return m_name;
    }
    __forceinline hash_t get_hash() const {
        return m_hash;
    }
    __forceinline size_t get_img_size() const {
        return m_image_size;
    }
    __forceinline IAT& get_iat() {
        return m_iat;
    }
    __forceinline EAT& get_eat() {
        return m_eat;
    }
};

// this was cute before syscalls
namespace util {
    using NtCreateThreadEx_t = long(__stdcall*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, LPTHREAD_START_ROUTINE, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PVOID);
    using DisableThreadLibraryCalls_t = long(__stdcall*)(HMODULE);
    using CloseHandle_t = long(__stdcall*)(HANDLE);
    using GetCurrentProcess_t = HANDLE(__stdcall*)(void);


    // all our static modules
    static Module& get_kernel32() {
        static Module kernel32_dll{};

        if (!kernel32_dll)
            kernel32_dll = Module(nt_static_module::kernel32);

        return kernel32_dll;
    }
    static Module& get_nt() {
        static Module nt_dll{};

        if (!nt_dll)
            nt_dll = Module(nt_static_module::nt);

        return nt_dll;
    }
    static Module& get_kernelbase() {
        static Module kernelbase_dll{};

        if (!kernelbase_dll)
            kernelbase_dll = Module(nt_static_module::kernelbase);

        return kernelbase_dll;
    }


    __forceinline static HANDLE get_current_process() {
        static GetCurrentProcess_t get_cur_process{};

        if (get_cur_process == nullptr)
            get_cur_process = get_kernel32().get_eat().get_method<GetCurrentProcess_t>(HASH("GetCurrentProcess"));

        if (get_cur_process != nullptr)
            return get_cur_process();

        return INVALID_HANDLE_VALUE;
    }

    // sneaky way of closing a handle
    __forceinline static bool close_handle(HANDLE handle) {
        static CloseHandle_t close_handle{};

        if (close_handle == nullptr)
            close_handle = get_kernel32().get_eat().get_method<CloseHandle_t>(HASH("CloseHandle"));

        if (close_handle != nullptr)
            return !!close_handle(handle);

        return false;
    }

    // sneaky way of invoking ntcreatethreadex in DllMain
    __forceinline static HANDLE create_thread(LPTHREAD_START_ROUTINE routine) {
        static NtCreateThreadEx_t create_thread_ex = nullptr;

        HANDLE                    out = INVALID_HANDLE_VALUE;

        if (create_thread_ex == nullptr)
            create_thread_ex = get_nt().get_eat().get_method<NtCreateThreadEx_t>(HASH("NtCreateThreadEx"));

        if (create_thread_ex != nullptr) {
            create_thread_ex(
                &out,
                THREAD_ALL_ACCESS,
                0,
                get_current_process(),
                routine,
                0,
                0x4,
                0,
                0,
                0,
                0
            );
        }

        return out;
    }

    // sneaky way of disabling thread lib calls in dllmain
    __forceinline static bool disable_thread_lib_calls(HMODULE inst) {
        static DisableThreadLibraryCalls_t disable_calls{};

        if (disable_calls == nullptr)
            disable_calls = get_kernel32().get_eat().get_method<DisableThreadLibraryCalls_t>(HASH("DisableThreadLibraryCalls"));

        if (disable_calls != nullptr)
            return !!disable_calls(inst);

        return false;
    }
};