If you need to compile the tool manually use the following or similar steps:

 - On Debian-based distribution:

    $ cmake -DCPACK_GENERATOR=DEB -DCMAKE_INSTALL_PREFIX:PATH=/usr -DVERSION=1.8 .

 - On RPM-based distribution:

    $ cmake -DCPACK_GENERATOR=RPM -DCMAKE_INSTALL_PREFIX:PATH=/usr -DVERSION=1.8 .

 - Generate binary package:

    $ cmake --build . --target package


Then install it using e.g.:

 - On Debian-based distribution:

    $ sudo apt-get install -y ./*.deb

 - On RPM-based distribution:

    $ sudo dnf install -y ./*.rpm
