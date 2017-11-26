# Glorytun

Small, Simple and Stupid VPN over [mud](https://github.com/angt/mud).

### Build and Install

Glorytun depends on [libsodium](https://github.com/jedisct1/libsodium) version >= 1.0.4.

On Ubuntu, the following command should be sufficient:

    $ sudo apt-get install meson libsodium-dev pkg-config

Grab the latest release from github:

    $ git clone https://github.com/angt/glorytun --recursive
    $ cd glorytun

To build and install the latest version with [meson](http://mesonbuild.com):

    $ meson build
    $ sudo ninja -C build install

The more classical autotools suite is also available.

### Easy setup with systemd

Just call `glorytun-setup` and follow the instructions.

First, setup the server:

    $ sudo glorytun-setup
    Config filename (tun0):
    Server ip (enter for server conf):
    Server key (enter to generate a new one):
    Your new key: NEW_KEY
    Start glorytun now ? (enter to skip): y

Copy the new generated key and use it when configuring the client:

    $ sudo glorytun-setup
    Config filename (tun0):
    Server ip (enter for server conf): SERVER_IP
    Server key (enter to generate a new one): NEW_KEY
    Start glorytun now ? (enter to skip): y

You can check easily if it works by looking at your public ip.
To stop the service:

    $ sudo systemctl stop glorytun@tun0

---

For feature requests and bug reports, please create an [issue](https://github.com/angt/glorytun/issues).
