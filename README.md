# librespotclib

A Windows C++20 static library that implements an unofficial Spotify Connect
audio receiver. It exposes decoded interleaved S16 PCM or raw Vorbis packets,
track metadata and artwork, playback events, queue/history control, volume,
ReplayGain, and a small local equalizer through a host callback API.

This is an archival, unmaintained release. Spotify can change its private
protocol or service behavior without notice. A Spotify Premium account is
required. The project is not affiliated with or endorsed by Spotify AB.

## Build

Requirements: Windows 10/11 and Visual Studio 2022 with the v143 C++ toolset
and Windows SDK.

```powershell
msbuild librespotclib.sln /m /p:Configuration=Release /p:Platform=x64
```

This produces `bin/librespotc.lib` and `bin/harness.exe`. Run
`bin/harness.exe --help` for the standalone receiver options. The harness uses
Spotify Connect Zeroconf pairing when no cached credentials are available.
Treat any configured credential cache as sensitive account data and never add
it to source control.

The stable host surface is `include/librespotc/librespotc.h`; consumers are not
expected to depend on the mod that originally used this library.

## License

MIT. See `LICENSE` and `THIRD_PARTY_NOTICES.md` for upstream attributions.

Copyright (c) 2026 matkhl.
