# Compilation of libprotobuf-lite.a

Rather than rely on libprotobuf to build libprotobuf-lite.a, we just
symlink all necessary files here, then build with our typical
`Makefile.subdir` approach.  This makes absolutely sure that we're
only linking to and compiling with the normal mechanisms.

## Which files?

If you're a future person that's looking to update the protobuf dependency,
this list of symlinks was found by doing:

```
cd ../protobuf
autoreconf -i
./configure
(cd src && make libprotobuf-lite.la)
```

and looking at the `CXX` rules that were executed.
