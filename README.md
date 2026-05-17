# Cryptographically Hardened Type-Isolated Allocator

To run each example program:
```
odin run examples/metadata_corruption.odin -file
odin run examples/freelist_poisoning.odin -file
odin run examples/fake_chunk_insertion.odin -file
odin run examples/cross_type_uaf_replacement.odin -file
```

To run the tests:
```
odin test tests/allocator_tests.odin
```