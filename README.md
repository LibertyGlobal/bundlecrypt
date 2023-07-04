## BundleCrypt

BundleCrypt (DAC bundle images generator) - a tool to convert an RDK DAC bundle into encrypted image.

## Repository structure

* `bundlecrypt/`: Python package with BundleCrypt implementation
* `demos/`: BundleCrypt demos
* `docker/`: files related to BundleCrypt Docker Image
* `test/`: automated tests for BundleCrypt
    * `unit/`: unit tests written using [pytest](https://pytest.org)
    * `interoperability/`: a test to validate that a protected DAC bundle image produced by BundleCrypt can be
      extracted/decrypted/signature-verified, just using a different implementation for JOSE operations -
      [go-jose](https://github.com/square/go-jose)
* `requirements.in` / `requirements.txt` / `dev-requirements.in` / `dev-requirements.txt`: project dependencies managed
  by [pip-tools](https://github.com/jazzband/pip-tools).

### Installation

1. Clone the repository
    ```sh
    git clone <repository-path>
    cd bundlecrypt
    ```
2. Installation

   - On RPM-based Linux distribution (tested on Fedora 37)

      - Compiling and installing dmcrypt-rdk tool

        ```sh
        sudo dnf install -y gcc cmake
        cd dmcrypt-rdk
        mkdir .build
        cd .build
        cmake -DCPACK_GENERATOR=RPM -DCMAKE_INSTALL_PREFIX:PATH=/usr -DVERSION=1.8 ..
        cmake --build . --target package
        sudo dnf install -y ./*.rpm
        ```

      - Installing bundlecrypt tool

        ```sh
        sudo dnf install python3-click python3-coloredlogs python3-cryptography python3-jsonschema python3-jose tar squashfs-tools openssl veritysetup coreutils cryptsetup
        sudo python3 setup.py install
        ```

    - On Debian-based Linux distribution (tested on Ubuntu 22.04.2 LTS)

      - Compiling and installing dmcrypt-rdk tool

        ```sh
        DEBIAN_FRONTEND=noninteractive sudo --preserve-env=DEBIAN_FRONTEND sudo apt-get install -y build-essential cmake
        cd dmcrypt-rdk
        mkdir .build
        cd .build
        cmake -DCPACK_GENERATOR=DEB -DCMAKE_INSTALL_PREFIX:PATH=/usr -DVERSION=1.8 ..
        cmake --build . --target package
        DEBIAN_FRONTEND=noninteractive sudo --preserve-env=DEBIAN_FRONTEND apt-get install -y ./*.deb
        ```

      - Installing bundlecrypt tool

        ```sh
        DEBIAN_FRONTEND=noninteractive sudo --preserve-env=DEBIAN_FRONTEND apt-get install -y python3-click python3-coloredlogs python3-cryptography python3-jsonschema python3-jose tar squashfs-tools openssl coreutils
        sudo python3 setup.py install
        ```

## Usage

### Getting help

```sh
$ bundlecrypt --help
$ bundlecrypt crypt --help
$ bundlecrypt decrypt --help
```

### Protecting a DAC bundle

First tell BundleCrypt where the keys are stored:

```sh
$ export BUNDLECRYPT_KEYSDIR=examples/keys
```

Then invoke BundleCrypt:

```sh
$ bundlecrypt crypt \
    --config examples/config.json \
    --id test \
    examples/bundle.tgz \
    protected-bundle.tar
```

Note that `--verbose` flag enables additional logging.

### Taking the protection off

If needed the process of protecting a DAC bundle can be reverted:

```sh
$ bundlecrypt decrypt \
    --config examples/config.json \
    protected-bundle.tar \
    unprotected-bundle.tar
```

While decrypting the bundle's rootfs BundleCrypt may ask for sudo password. That's because BundleCrypt needs to invoke
`cryptsetup-reencrypt --decrypt` with `sudo` to gain the required root privileges.

### Environment variables

The following environment variables can be used to tweak some parts of BundleCrypt:
* `BUNDLECRYPT_KEYSDIR`: the path to a folder with cryptographic keys; the entries in the BundleCrypt's config `keys`
  section are relative to this location; set to `/keys` by default
* `BUNDLECRYPT_TMPDIR`: the path to a folder which BundleCrypt should use as its temporary storage; set to `/tmp` by
  default
* `NO_COLOR`: if set to any value then colors will not be used in BundleCrypt logs; not set by default which means
  colors are used; see `coloredlogs` package [documentation](https://coloredlogs.readthedocs.io/en/latest/api.html#environment-variables)
  for additional ways of configuring BundleCrypt logs using environment variables

### Using a Docker Image

First build BundleCrypt Docker Image:

```sh
$ make image
```

Then run BundleCrypt in a Docker container:

```sh
$ docker run -it --rm bundlecrypt bundlecrypt --help
```

Or run one of the existing helpers:

```sh
$ make test-encrypt
$ make test-decrypt
```

One of the things that can be customized when using the above helpers is the BundleCrypt configuration ID:

```sh
$ make test-encrypt CONFIG_ID=test-ec
```

## Demos

### local file / inotify -based with result exposed via NGINX

The idea is that:
* a script runs `inotifywait` which in turn runs `bundlecrypt crypt` when a DAC bundle is put into an input folder
* `bundlecrypt crypt` does its magic and stores the protected DAC bundle in an output folder
* NGINX exposes the output file/folder over HTTP

The demo uses the BundleCrypt Docker Image and Docker Compose to create the environment.

Use the following command to run the demo:

```sh
$ make demo-inotify
```

### RabbitMQ and S3

The idea is that:
* BundleCrypt is run as a service which listens for requests coming via a RabbitMQ queue
* when a request is found, BundleCrypt downloads a DAC bundle from S3 as specified in the request params
* BundleCrypt then processes the file and uploads a protected DAC bundle image back to S3

As with the other demo this demo uses the BundleCrypt Docker Image and Docker Compose to create the environment.

Note that this demo requires AWS credentials to be present in `$HOME/.aws/credentials` and that these credentials
provide read-write access to `lgi-onemw-tests` S3 bucket.

Use the following command to run the demo:

```sh
$ make demo-rabbitmq
```
