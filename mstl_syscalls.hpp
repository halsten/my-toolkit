#pragma once

class Syscalls {
protected:
    std::unordered_map< hash_t, uint16_t > m_syscalls;

    // 0x30 is very arbitrary... but whatever
    __forceinline size_t syscall_wrapper_size(uint8_t* funptr) {
        for (size_t offset{}; offset < 0x30; offset++) {
            if (funptr[offset] == x86::instruction::retn || funptr[offset] == x86::instruction::retn_imm16)
                return offset + 1;
        }
        return 0;
    }

    __forceinline bool is_syscall(uint8_t* funptr, size_t func_size) {
        const uint32_t encoded_opcode = x86::encode_mov_imm32(x86::reg::eax);

        if (is86 ? funptr[0] != encoded_opcode : !(funptr[0] == 0x4c && funptr[1] == 0x8b && funptr[2] == 0xd1))
            return false;

        for (size_t offset{}; offset < func_size; offset++) {
            if (is86) {
                if ((funptr[offset] == x86::instruction::fs    && // win7
                     funptr[offset + 1] == x86::instruction::call) ||

                     (funptr[offset] == x86::instruction::call &&  // win10
                      funptr[offset + 1] == 0xd2 /*call edx*/))

                    return true;

            }

            else {
                if (funptr[offset] == 0x0f && // win7 + win10 
                    funptr[offset + 1] == 0x05)
                    return true;
            }
        }

        return false;
    }

    __forceinline uint16_t get_syscall_index(Address func_addr, std::ptrdiff_t *stub_offset = nullptr) {
        uint8_t *ubp_addr = func_addr.as<uint8_t*>();
        size_t   wrapper_size = syscall_wrapper_size(ubp_addr);

        wrapper_size = (wrapper_size) ? wrapper_size : 16;

        if (is_syscall(ubp_addr, wrapper_size)) {
            // mov eax, imm32
            const uint32_t encoded_opcode = x86::encode_mov_imm32(x86::reg::eax);

            for (size_t offset{}; offset < wrapper_size; offset++) {
                if (func_addr.at<uint8_t>(offset) == encoded_opcode) {
                    if (stub_offset)
                        *stub_offset = offset;

                    return func_addr.at<uint16_t>(offset + 1);
                }
            }
        }

        return 0;
    }

    std::pair< uint8_t*, size_t > m_shellcode_stub;
    void *m_call_table;
public:

    __forceinline ~Syscalls() {
        if (m_call_table)
            VirtualFree(m_call_table, 0x100000, MEM_FREE);

        if (m_shellcode_stub.first)
            delete[] m_shellcode_stub.first;
    }

    __forceinline Syscalls() :
        m_syscalls{}, m_shellcode_stub{} {

        init();

        // b1gr0fl
        m_call_table = VirtualAlloc(0, 0x100000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        util::set(m_call_table, 0xC3, 0x100000); // maybe 0x90 instead?

        if (is86) {
            for (auto& syscall : m_syscalls) {
                void *stub_addr = (void *) (uintptr_t(m_call_table) + (syscall.second * m_shellcode_stub.second));

                util::copy(stub_addr, m_shellcode_stub.first, m_shellcode_stub.second);

                std::ptrdiff_t index_offset{};
                get_syscall_index(stub_addr, &index_offset);

                auto stub_return = (uint8_t *) (uintptr_t(stub_addr) + m_shellcode_stub.second - 1);

                *stub_return = 0xC3;
                *(uint32_t *) (uintptr_t(stub_addr) + index_offset + 1) = syscall.second;
            }
        }
    }

    __forceinline void init() {
        uint32_t index;

        for (const auto& exp : util::get_nt().get_eat().get_exports()) {
            index = get_syscall_index(exp.second);

            if (index) {
                m_syscalls[exp.first] = index;

                if (!m_shellcode_stub.first) {
                    m_shellcode_stub.second = syscall_wrapper_size(exp.second.as< uint8_t * >());
                    m_shellcode_stub.first = new uint8_t[m_shellcode_stub.second];

                    util::copy(m_shellcode_stub.first, exp.second.as< void* >(), m_shellcode_stub.second);
                }
            }
        }
    }

    template< typename T = void* >
    __forceinline T get_syscall_func(hash_t hash) {
        return (T) ((uintptr_t(m_call_table) + (get_syscall(hash) * m_shellcode_stub.second)));
    }

    // get by hash
    __forceinline uint16_t get_syscall(hash_t hash) {
        return m_syscalls[hash];
    }

    // getters
    __forceinline auto& get_syscalls() {
        return m_syscalls;
    }
};