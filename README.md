# pkdns

![GitHub Release](https://img.shields.io/github/v/release/severinalexb/pkdns)


DNS server resolving [pkarr](https://github.com/nuhvi/pkarr) self-sovereign domains on the [mainline DHT](https://en.wikipedia.org/wiki/Mainline_DHT).

## Getting Started

### Hosted DNS

Use one of the [hosted DNS servers](./servers.txt) to try out pkarr quickly.

- [Verify](#verify-pkdns-is-working) the server is working.
- [Configure](#change-your-system-dns) your system dns.
- [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


### Pre-Built Binaries

1. Download the [latest release](https://github.com/SeverinAlexB/pkdns/releases/latest/) for your plattform.
2. Extract the tar file. Should be something like `tar -xvf tarfile.tar.gz`.
3. Run `pkdns -f 8.8.8.8`.
4. [Verify](#verify-pkdns-is-working) the server is working. Your server ip is `127.0.0.1`.
5. [Configure](#change-your-system-dns) your system dns.
6. [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


### Build It Yourself

Make sure you have the [Rust toolchain](https://rustup.rs/) installed.

1. Clone repository `git clone https://github.com/SeverinAlexB/pkdns.git`.
2. Switch directory `cd pkdns`.
3. Run `cargo run -- -f 8.8.8.8`.
4. [Verify](#verify-pkdns-is-working) the server is working. Your server ip is `127.0.0.1`.
6. [Configure](#change-your-system-dns) your system dns.
7. [Browse](#browse-the-self-sovereign-web) the self-sovereign web.


## Guides

### Change your System DNS

Follow one of the guides to change your DNS server on your system:
- [MacOS guide](https://support.apple.com/en-gb/guide/mac-help/mh14127)
- [Ubuntu guide](https://www.ionos.com/digitalguide/server/configuration/change-dns-server-on-ubuntu/)
- [Windows guide](https://www.windowscentral.com/how-change-your-pcs-dns-settings-windows-10)


Verify your server with this domain [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).

### Verify pkdns is working

#### Pkarr Domains
Verify the server resolves pkarr domains. Replace `PKDNS_SERVER_IP` with your pkdns server IP address.

```bash 
nslookup 7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy PKDNS_SERVER_IP
```

> *Troubleshooting* If this does not work then the pkdns server is likely not running.


#### ICANN Domains

Verify it resolves regular ICANN domains. Replace `PKDNS_SERVER_IP` with your pkdns server IP address.

```bash
nslookup example.com PKDNS_SERVER_IP
```

> *Troubleshooting* If this does not work then you need to change your ICANN fallback server with
> `pkdns -f REGULAR_DNS_SERVER_IP`. Or use the Google DNS server: `pkdns -f 8.8.8.8`.

### Browse the Self-Sovereign Web

Here are some example pkarr domains:

- [http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).
- [http://pknames.p2p.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/](http://pknames.p2p.7fmjpcuuzf54hw18bsgi3zihzyh4awseeuq5tmojefaezjbd64cy/).

Hint: Always add a `/` to the end of a pkarr domain. Otherwise browsers will search instead of resolve the website.

### Address already in use

Other services might occupy the port 53 already. For example, [Docker Desktop](https://github.com/docker/for-mac/issues/7008) uses the port 53 on MacOS. Make sure to free those.

## Options

```
Usage: pkdns [OPTIONS]

Options:
  -f, --forward <forward>      ICANN fallback DNS server. IP:Port [default: 192.168.1.1:53]
  -s, --socket <socket>        Socket the server should listen on. IP:Port [default: 0.0.0.0:53]
  -v, --verbose                Show verbose output.
      --cache-ttl <cache-ttl>  Pkarr packet cache ttl in seconds.
      --threads <threads>      Number of threads to process dns queries. [default: 4]
  -d, --directory <directory>  pknames source directory. [default: ~/.pknames]
  -h, --help                   Print help
  -V, --version                Print version
```

## Limitations

Lookups on pkarr DNS records are limited. These two approach are supported:

EASY - All in pkarr:
- Direct record resolution (A, AAAA, TXT, ...).
- CNAME pointing directly to another record in the same pkarr.
- No recursion.

ADVANCED - Fully featured:
- Delegate your zone to a fully fledged name server ([bind9](https://ubuntu.com/server/docs/service-domain-name-service-dns)).
- pkdns will forward the request the name server.


---

May the power ⚡ be with you.