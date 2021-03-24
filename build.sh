# Post-Quantum and Composite Crypto
# build environment
#
# (c) 2021 by Massimiliano Pala

# Install dependencies
# sudo \
# dnf install   \
# 	cmake \
# 	gcc   \
# 	ninja-build \
# 	python3-pytest \
# 	python3-pytest-xdist \
# 	unzip \
# 	doxygen \
# 	graphviz

# Get liboqs latest repo
if [ ! -d "liboqs" -o "$1" = "liboqs" ] ; then

	# Really download only if needed
	[ -d "liboqs" ] || git clone https://github.com/open-quantum-safe/liboqs.git

	# Build the liboqs
	if ! [ -d "liboqs/build" ] ; then 
		mkdir -p "liboqs/build"
	fi

	# Execute the build
	cd liboqs/build && \
		cmake -DCMAKE_INSTALL_PREFIX=/opt/libpki-oqs -GNinja .. && \
		ninja && sudo ninja install
	cd ../..
fi

# Fetch the latest openssl-liboqs branch
if [ ! -d "openssl" -o "$1" = "openssl" ] ; then

	# Download only if needed
	[ -d "openssl" ] || git clone https://github.com/open-quantum-safe/openssl.git

	# Creates a missing link
	[ -e "openssl/oqs" ] || ln -s ../liboqs/build openssl/oqs

	# Links the includes in the current dir
	[ -e "openssl/include/oqs" ] || ln -s ../../liboqs/build/include/oqs openssl/include/oqs

	# Copy the default template to not overwrite it
	if ! [ -f "openssl/oqs-template/generate.yml" ] ; then
		cp openssl/oqs-template/generate.yml openssl/oqs-template/generate-default.yml
	fi

	# Copy the our template for enabled algorithms
	cp config/libpki-generate-template.yml openssl/oqs-template/generate.yml

	# Execute the build
	cd openssl && ./config --prefix=/opt/libpki-oqs --shared

	# Rebuilds the Objects database
	python3 oqs-template/generate.py
	make generate_crypto_objects

	# Let's now build the OpenSSL library
	make && sudo make install

	cd ..
fi

# Fetch the latest openssl-liboqs branch
if [ ! -d "libpki" -o "$1" = "libpki" ] ; then

	if ! [ -d "libpki" ] ; then
		git clone -b libpki-oqs https://github.com/openca/libpki.git
	fi

	# Execute the build
	cd libpki && ./configure --prefix=/opt/libpki-oqs --disable-ldap

	make && sudo make install

	cd ..
fi

