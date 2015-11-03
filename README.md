# glorytun

glorytun depends on [libsodium](https://github.com/jedisct1/libsodium) version >= 1.0.4
and needs an AES-NI capable CPU.

To build and install the latest version:

    $ git clone https://github.com/angt/glorytun
    $ cd glorytun
    $ ./autogen.sh
    $ ./configure
    $ make
    # make install
