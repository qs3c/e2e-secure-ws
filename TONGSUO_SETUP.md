# Tongsuo setup (cgo)

This project uses Tongsuo via cgo. The cgo include/library paths point to:
  third_party/tongsuo-install

Submodule (source)

Tongsuo source is tracked as a git submodule (8.3-stable):
  git submodule update --init --recursive

Build prerequisites (from Tongsuo README)

- make
- Perl 5 and the Text::Template module
- C compiler
- C library

Build (per platform)

The scripts below follow the README build steps and install into
third_party/tongsuo-install by default:
- Linux:  ./scripts/build_tongsuo_linux.sh
- macOS:  ./scripts/build_tongsuo_macos.sh
- Windows:
  .\scripts\build_tongsuo_windows.ps1

On Windows, the script will try to locate VsDevCmd.bat and re-run itself inside a
Developer Command Prompt if needed.

Note: The scripts refuse to install into the source directory to avoid
overwriting headers.

Optional build knobs (env vars)

- TONGSUO_PREFIX: install prefix (default: third_party/tongsuo-install)
- TONGSUO_BUILD_DIR: build directory (default: third_party/tongsuo-build)
- TONGSUO_CONFIG_OPTS: extra Configure options (e.g. enable-ntls, no-rsa)
- TONGSUO_INSTALL_TARGETS: make install targets (default: install)
- TONGSUO_TARGET: Windows Configure target (default: VC-WIN64A)
- TONGSUO_OPENSSLDIR: OpenSSL dir (default: <prefix>\ssl)

README notes

- Windows build uses: perl Configure enable-ntls; nmake; nmake install (script adds VC-WIN64A by default unless a target is provided)
- You can run tests with: make test
- Install variants: make install_runtime_libs, make install_dev, make install_programs
- Configure options use enable-xxx / no-xxx

Runtime

Windows (PowerShell):
  .\scripts\set_tongsuo_env.ps1

Linux/macOS (bash, must be sourced to affect current shell):
  source ./scripts/set_tongsuo_env.sh

Per-OS runtime helpers:
- Linux:  scripts/set_tongsuo_env_linux.sh
- macOS:  scripts/set_tongsuo_env_macos.sh

Linux: sets LD_LIBRARY_PATH to include third_party/tongsuo-install/lib
macOS: sets DYLD_LIBRARY_PATH to include third_party/tongsuo-install/lib

Notes
- Windows/amd64 binaries do not work on Linux/macOS or ARM.
- If you do not use the SM2 key exchange features, -lkeyexchange may be omitted.

SM2 + ML-KEM hybrid mode

The legacy SM2 path continues to use:
  third_party/tongsuo-install

The hybrid SM2 + ML-KEM wrapper uses the newer Tongsuo tree separately:
  source:  third_party/Tongsuo-master
  build:   third_party/tongsuo-pq-build
  install: third_party/tongsuo-pq-install

Windows quick build:
  .\scripts\build_tongsuo_pq_windows.ps1

During local development, if the full install has not been completed yet, tests
can use the provider and libcrypto from the build tree:
  $env:PATH = "$PWD\crypto\sm2mlkem;$env:PATH"
  $env:TONGSUO_PQ_PROVIDER_PATH = "$PWD\third_party\tongsuo-pq-build\providers"
  go test -tags sm2mlkem ./crypto/sm2mlkem ./e2ewebsocket

Generate key store files:
  go run ./cmd/genkeys -out ./static_key -ids 1111111111,2222222222

Generate key store files with SM2 + ML-KEM keys:
  go run -tags sm2mlkem ./cmd/genkeys -out ./static_key -ids 1111111111,2222222222 -sm2mlkem

This writes:
  private_key.pem
  public_key.pem
  sm2mlkem_private.bin
  sm2mlkem_public.bin

Runtime opt-in:
  cfg := &e2ewebsocket.Config{
      KeyStorePath: "./static_key",
      EnableSM2MLKEM: true,
  }

If CipherSuites is set explicitly, that list is honored as-is.
