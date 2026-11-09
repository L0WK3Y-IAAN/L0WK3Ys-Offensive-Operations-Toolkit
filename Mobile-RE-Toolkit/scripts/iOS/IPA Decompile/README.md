# IPA Decompile

Lists `.ipa` files found under the toolkit root, `src/`, `src/ipa/` (where
imported IPAs land), and `src/output/pulled_ipas/` (same scan convention as
Open In Jadx's APK picker), lets you pick one by number or fuzzy name, then:

1. Unzips the IPA and locates the `.app` bundle's main executable via its `Info.plist`.
2. Warns if the binary is still FairPlay-encrypted (`cryptid=1`) - every
   dumper fails on those; you need a decrypted dump (frida-ios-dump, bagbak,
   flexdecrypt) from a jailbroken device.
3. Detects the binary's likely source language (Swift, Objective-C, mixed)
   from Mach-O sections and defined symbols. Advisory label only.
4. For the main binary (and, when it's a metadata-free stub, for each
   embedded Mach-O that has Swift/ObjC metadata) writes:
   - `ipsw class-dump --headers` - Objective-C `.h` interfaces (in `objc_headers/`).
   - `ipsw swift-dump` (mangled and `--demangle`) - Swift type/method declarations.
   - `<binary>-strings.txt` - every printable string (URLs, query templates, constants).
   - `<binary>-symbols.txt` - `nm` symbol table with addresses (the map for the disassembly).
   - `<binary>-disassembly.asm` - `otool -tV` disassembly (skipped above 64 MB).
   - If `ipsw` isn't installed, falls back to `class-dump` for Objective-C and
     `nm` + `xcrun swift demangle` (symbol names only) for Swift.
   - Always: a dumped `Info.plist`.
   Note: the ipsw dumps are declarations reconstructed from metadata - method
   bodies don't survive that way. The strings/symbols/disassembly files are
   where the actual logic shows up.
5. Writes everything to `src/output/decompiled_ipas/<AppName>_<timestamp>/`,
   then offers to open it in a text editor (`code`/`cursor`/`subl`) or the
   system file browser.

macOS only - relies on `otool`/`nm`/`xcrun` from Xcode's command line tools.
