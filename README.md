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

The more classical autotools suite is also available but not recommended.

### Usage

Just run `glorytun` with no arguments to view the list of available commands:

```
$ glorytun
available commands:

  show     show all running tunnels
  bench    start a crypto bench
  bind     start a new tunnel
  set      change tunnel properties
  keygen   generate a new secret key
  path     manage paths
  version  show version

```

### Mini HowTo

Glorytun does not touch network configuration of its interface,
It only tries to set the MTU when it receives packets,
it doesn't rely on ICMP Next-hop MTU to avoid black holes.
It is up to the user to do it according to the tools available
on his system (systemd-networkd, netifd, ...).
This also allows a wide variety of configurations.

To start a server:

    # (umask 066; glorytun keygen > my_secret_key)
    # glorytun bind 0.0.0.0 keyfile my_secret_key &

You should now have a virgin `tun0` interface as mentioned earlier.
I let you choose your favorite tool :)
For exemple, the simplest setup with `ifconfig`:

    # ifconfig tun0 10.0.1.1 pointopoint 10.0.1.2 up

To check if the server is running, simply call `glorytun show`.
It will show you all the running tunnels.

To start a new client, you need to get the secret key (somehow..).
Then simply call:

    # glorytun bind 0.0.0.0 to SERVER_IP keyfile my_secret_key &
    # ifconfig tun0 10.0.1.2 pointopoint 10.0.1.1 up

Here the tricky part... You need to specify your paths or glorytun will not send anything, it's easy:

    # glorytun path LOCAL_IPADDR up

Again, to check if your path is working, you can watch its status with `glorytun path`.
You should now be able to ping your server with `ping 10.0.1.1`.

### Easy setup with systemd

Just call `glorytun-setup` and follow the instructions.

First, setup the server:

    $ sudo glorytun-setup
    Config filename (tun0):
    Server ip (enter for server conf):
    Bind to port (5000):
    Server key (enter to generate a new one):
    Your new key: NEW_KEY
    Start glorytun now ? (enter to skip): y

Copy the new generated key and use it when configuring the client:

    $ sudo glorytun-setup
    Config filename (tun0):
    Server ip (enter for server conf): SERVER_IP
    Server port (5000):
    Server key (enter to generate a new one): NEW_KEY
    Start glorytun now ? (enter to skip): y

To stop the service:

    $ sudo systemctl stop glorytun@tun0

---

For feature requests and bug reports, please create an [issue](https://github.com/angt/glorytun/issues).
