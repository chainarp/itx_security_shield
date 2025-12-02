# Compile library
gcc -fPIC -shared \
    -I./include \
    src/integrity_check.c \
    -o libintegrity.so \
    -lssl -lcrypto

# Compile test
gcc -I./include \
    test/test_main.c \
    -L. -lintegrity \
    -o test_integrity \
    -lssl -lcrypto

# Run
LD_LIBRARY_PATH=. ./test_integrity