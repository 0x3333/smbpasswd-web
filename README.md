# smbpasswd-web

## What is it?

***smbpasswd-web*** is a simple web interface to smbpasswd.

The only purpose is to allow a user to change its samba password using a webbrowser, no user adding, no machine account, nothing, plain simple changing a password. By default, we use `smbpasswd`, but has been added support to use `samba-tool` instead `smbpasswd`, initial PR by [@svenseeberg](https://github.com/svenseeberg).

## Sneak peek

![smbpasswd-web screenshot](https://github.com/0x3333/smbpasswd-web/blob/master/.github/smbpasswd-main.png)
![smbpasswd-web screenshot ok](https://github.com/0x3333/smbpasswd-web/blob/master/.github/smbpasswd-ok.png)

## How it works?

When a user needs to change his password, sysadmin will create a token, the token will generate a URL that the user will access to change its password. Done.

## Securing

You _MUST_ use this app over a SSL connection, otherwise, your user's password can be sniffed. You can run the embedded webserver using SSL, you just need to provide the certificate file(`--ssl-cert CERT_FILE`) and private key(`--ssl-key KEY_FILE`) with the flag `--ssl`.

## Usage

```
$ ./app.py --help
usage: app.py [-h] {server,gen-token} ...

Web interface to change samba user's password

positional arguments:
  {server,gen-token}  Commands available
    server            Start then webserver
    gen-token         Generate a token to a username

optional arguments:
  -h, --help          show this help message and exit
```

Note: `smbpasswd` must be in `$PATH`, same for `sudo` if in use.

Note 2: ~~Currently, the generated URL is sort of invalid, you must adapt the output to send to your user. Soon will fix this using a configuration file.~~. Fixed, you can provide `--fqdn` to `gen-token` command.

### Server Mode

```
$ ./app.py server --help
usage: app.py server [-h] [-a ADDRESS] [-p PORT] [-v] [--sudo] [--samba-tool]
                     [--ssl] [--ssl-cert SSL_CERT] [--ssl-key SSL_KEY]

optional arguments:
  -h, --help            show this help message and exit
  -a ADDRESS, --address ADDRESS
                        Address to bind (default: localhost)
  -p PORT, --port PORT  Port number to bind. (default: If SSL, 8443, otherwise 8080)
  -v, --verbose         Log HTTP requests
  --sudo                Use sudo to call smbpasswd/samba-tool
  --samba-tool          Use samba-tool instead smbpasswd
  --ssl                 Start webserver using SSL
  --ssl-cert SSL_CERT   SSL certificate to use (default: res/fullchain.pem)
  --ssl-key SSL_KEY     SSL certificate private key (default: res/privkey.pem)
```

### Token generation Mode

```
$ ./app.py gen-token --help
usage: app.py gen-token [-h] [--ssl] [--fqdn FQDN] USERNAME

positional arguments:
  USERNAME     Username

optional arguments:
  -h, --help   show this help message and exit
  --ssl        Use https protocol on the generated URL
  --fqdn FQDN  Use this FQDN instead the default one
```

### Examples

First, clone the repo:

```bash
git clone git@github.com:0x3333/smbpasswd-web
cd smbpasswd-web
```

Create a user token:
```bash
./app.py gen-token USERNAME
Token generated:

http://yourhostname.local/?8b6ef13b556f189afa302ba74ead80f29a30448a2a50df03918f4c790955f2c8
```
Send this URL to your user(See note 2 in `Usage`).

* Start the web server in SSL mode(Cert and Key in default location):
```bash
./app.py server --ssl
```

By default ***smbpasswd-web***  will bind to localhost:8443 when in SSL mode or localhost:8080 otherwise. Using a `nginx`(or alike) as a proxy is good advice. Also you can expose it in port 80 or 443 so the URL gets cleaner.

### TODO

PR are welcome! :)

- [X] ~~Add support for custom hostname in the generated URL.~~ Fixed on commit [#c925c12385](https://github.com/0x3333/smbpasswd-web/commit/c925c123853ce6aaeb9a2c54e7b5b9f690c01b87).
- [ ] Add a systemd unit file to be used as a service
- [ ] Add an expiration date/time to the token, so unused tokens can be invalidated automatically.
- [ ] Add some kind of i18n.

## License

 *smbpasswd-web* is released under the MIT license. See LICENSE.
