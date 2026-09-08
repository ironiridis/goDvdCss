## goDvdCss

This is a port of [VideoLAN's libdvdcss library at version 1.4.3][1]

The initial objectives for this port:

* Remove implicit local filesystem behavior (ie key caching)
    * Replace with with opt-in explicit caching
* Remove all environment variable behavior-modifying logic
    * Replace with explicit library interfaces for selecting behavior
* Rework logging to be compatible with Go's [defacto logging library slog][2]
* Implement generic (ie ioctl-less) read/decryption
* Later implement Linux ioctl support

[1]: <https://code.videolan.org/videolan/libdvdcss/-/tree/23d8e2097648708708ef6e413fc892405461549a/> "libdvdcss 1.4.3"
[2]: <https://pkg.go.dev/log/slog> "log/slog"

### License

Upstream libdvdcss is licensed GPL 2+, and consequently this library is too.
