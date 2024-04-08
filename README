# sbuild

This repository provides a modified version of the official sbuild package from [Debian's salsa repository](https://salsa.debian.org/debian/sbuild). The modification allows network connections inside `dpkg-buildpackage` for added flexibility during package building.

## Usage

```bash
git clone https://github.com/eth-pkg/sbuild.git
cd sbuild 
# Install dependencies
sudo apt-get install dh-python dh-sequence-python3 libyaml-tiny-perl python3-all
# Build the package
dpkg-buildpackage -us -uc  
# Install the newly built package 
cd .. && sudo dpkg -i sbuild_0.85.6_all.deb libsbuild-perl_0.85.6_all.deb
```
