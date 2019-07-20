# Glorytun

Glorytun is a small, simple and secure VPN over [mud](https://github.com/angt/mud).

## Compatibility

Glorytun only depends on [libsodium](https://github.com/jedisct1/libsodium) version >= 1.0.4.
Which can be installed on a wide variety of systems.

Linux is the platform of choice but the code is standard so it should be easily ported on other posix systems.
It was successfully tested on OpenBSD, FreeBSD and MacOS.

IPv4 and IPv6 are supported.

## Features

The key features of Glorytun come directly from mud:

 * **Fast and highly secure**

   The use of UDP and [libsodium](https://github.com/jedisct1/libsodium) allows you to secure
   your communications without impacting performance.
   Glorytun uses AES only if AES-NI is available otherwise ChaCha20 is used.
   If you are not cpu bounded, you can force the use of ChaCha20 for higher security.
   All messages are encrypted, authenticated and marked with a timestamp.
   Perfect forward secrecy is also implemented with ECDH over Curve25519.

 * **Multipath and active failover**

   This is the main feature of Glorytun that allows to build an SD-WAN like service.
   This allows a TCP connection to explore and exploit multiple links without being disconnected.
   Aggregation should work on all conventional links, only very high latency (+500ms) links are not recommended for now.

 * **Traffic shaping**

   Shaping is very important in network, it allows to keep a low latency without sacrificing the bandwidth.
   It also helps the multipath scheduler to make better decisions.
   Currently it must be configured by hand, but soon Glorytun will do it for you.

 * **Path MTU discovery without ICMP**

   Bad MTU configuration is a very common problem in the world of VPN.
   As it is critical, Glorytun will try to setup it correctly by guessing its value.
   It doesn't rely on ICMP Next-hop MTU to avoid black holes.
   In asymmetric situations the minimum MTU is selected.

## Caveats

Glorytun is strongly secure by default and protects against replay attacks,
the clock between the client and the server must be synchronized.
By default, an offset of 10min is accepted.

## Build and Install

You will need `git`, `make`, `gcc` and `libsodium`:

    $ sudo apt install git make gcc libsodium-dev    # debian based
    $ sudo yum install git make gcc libsodium-devel  # redhat based

To build and install the latest release from github:

    $ git clone https://github.com/angt/glorytun --recursive
    $ cd glorytun
    $ sudo make install

This will install the binary in `/usr/bin` by default.

The more classical autotools suite is also available.

## Usage

Just run `glorytun` with no arguments to view the list of available commands:

```
$ glorytun
available commands:

  show     show tunnel info
  bench    start a crypto bench
  bind     start a new tunnel
  set      change tunnel properties
  keygen   generate a new secret key
  path     manage paths
  version  show version

```

Use the keyword `help` after a command to show its usage.

## Mini HowTo

Glorytun does not touch the configuration of its network interface (except for the MTU),
It is up to the user to do it according to the tools available
on his system (systemd-networkd, netifd, ...).
This also allows a wide variety of configurations.

To start a server:

    # (umask 066; glorytun keygen > my_secret_key)
    # glorytun bind 0.0.0.0 keyfile my_secret_key &

You should now have an unconfigured network interface (let's say `tun0`).
For example, the simplest setup with `ifconfig`:

    # ifconfig tun0 10.0.1.1 pointopoint 10.0.1.2 up

To check if the server is running, simply call `glorytun show`.
It will show you all of the running tunnels.

To start a new client, you need to get the secret key generated for the server.
Then simply call:

    # glorytun bind 0.0.0.0 to SERVER_IP keyfile my_secret_key &
    # ifconfig tun0 10.0.1.2 pointopoint 10.0.1.1 up

Now you have to setup your path, let's say you have an ADSL link that can do 1Mbit upload and 20Mbit download then call:

    # glorytun path up LOCAL_IPADDR rate tx 1mbit rx 20mbit

Again, to check if your path is working, you can watch its status with `glorytun path`.
You should now be able to ping your server with `ping 10.0.1.1`.

If you use systemd-networkd, you can easily setup your tunnels with the helper program `glorytun-setup`.

## Thanks

 * @jedisct1 for all his help and the code for MacOS/BSD.
 * The team OTB (@bessa, @gregdel, @pouulet, @sduponch and @simon) for all tests and discussions.
 * OVH to support this soft :)

---

For feature requests and bug reports, please create an [issue](https://github.com/angt/glorytun/issues).
