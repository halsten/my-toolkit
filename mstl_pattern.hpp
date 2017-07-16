#pragma once

namespace pattern {
    __forceinline Address find(const std::string& pat, Address start, size_t len) {
        std::vector< uint8_t >						data{};
        std::vector< std::pair< uint8_t, bool > >	pattern{};
        std::istringstream							stream{pat};
        std::string									w;

        // construct vectored pattern.
        while (stream >> w) {
            // check for wildcards.
            if (w.data()[0] == '?')
                pattern.push_back({0, true});

            // valid hex byte.
            else if (w.length() == 2 && std::isxdigit(w.data()[0]) && std::isxdigit(w.data()[1]))
                pattern.push_back({util::string_to_uint8(w), false});

            // bad pattern.
            else
                return nullptr;
        }

        // store bytes.
        for (uintptr_t i{}; i < len; ++i)
            data.push_back(*(uint8_t*) (start + i));

        // find match.
        auto result = std::search(data.begin(), data.end(), pattern.begin(), pattern.end(),
                                  [ & ](uint8_t b, std::pair< uint8_t, bool > p) {
            // matches or is a wildcard
            return b == p.first || p.second;
        });

        // we have a match.
        if (result != data.end())
            return start + std::distance(data.begin(), result);

        return nullptr;
    }

    inline Address find(hash_t module, const std::string& pat, size_t len = 0) {
        auto mod = g_peb.get_module(module);
        if (!mod)
            return nullptr;

        if (!len)
            len = mod.get_img_size();

        return find(pat, mod, len);
    }

    inline Address find(Module mod, const std::string& pat, size_t len = 0) {
        if (!mod)
            return nullptr;

        if (!len)
            len = mod.get_img_size();

        return find(pat, mod, len);
    }
};