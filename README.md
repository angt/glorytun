# π₁(Glorytun)=ℤ²

Small, Simple and Stupid VPN over [mud](https://github.com/angt/mud).

#### Work In Progress

This code will probably format your harddisk!

#### Build and Install

Glorytun depends on [libsodium](https://github.com/jedisct1/libsodium) version >= 1.0.4
and needs an AES-NI capable CPU.

To build and install the latest version:

    $ git clone https://github.com/angt/glorytun --recursive --branch mud
    $ cd glorytun
    $ ./autogen.sh
    $ ./configure
    $ make
    # make install

For feature requests and bug reports, please create an [issue](https://github.com/angt/glorytun/issues).
