/*
 * ShadowStrike - Enterprise NGAV/EDR Platform
 * Copyright (C) 2026 ShadowStrike Security
 *
 * PhantomCLI entry point.
 *
 * Usage:
 *   ShadowStrikePhantomCLI.exe               — interactive REPL
 *   ShadowStrikePhantomCLI.exe status         — single command, then exit
 *   ShadowStrikePhantomCLI.exe scan C:\temp   — single command, then exit
 */

#include "PhantomCLI.hpp"
#include <cstring>

int wmain(int argc, wchar_t* wargv[]) {
    // Convert wide argv to narrow UTF-8 for the CLI.
    // Simple approach: use WideCharToMultiByte for each arg.
    std::vector<std::string> args_storage;
    std::vector<char*>       argv_narrow;
    args_storage.reserve(static_cast<size_t>(argc));

    for (int i = 0; i < argc; ++i) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string s(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, s.data(), len, nullptr, nullptr);
        if (!s.empty() && s.back() == '\0') s.pop_back();
        args_storage.push_back(std::move(s));
    }
    for (auto& s : args_storage) argv_narrow.push_back(s.data());
    argv_narrow.push_back(nullptr);

    ShadowStrike::PhantomCLI cli;
    if (argc <= 1) return cli.RunInteractive();
    return cli.RunCommand(argc, argv_narrow.data());
}
