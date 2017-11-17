# Glorytun

Small, Simple and Stupid VPN over [mud](https://github.com/angt/mud).

### Build and Install

Glorytun depends on [libsodium](https://github.com/jedisct1/libsodium) version >= 1.0.4.

Grab the latest release from github:

    $ git clone https://github.com/angt/glorytun --recursive
    $ cd glorytun

To build and install the latest version with [meson](http://mesonbuild.com):

    $ meson build
    $ cd build
    $ ninja
    # ninja install

Or with the more classical autotools suite:

    $ ./autogen.sh
    $ ./configure
    $ make
    # make install

For feature requests and bug reports, please create an [issue](https://github.com/angt/glorytun/issues).
