

```sh
# build the notary and the final manifest
make SGX=1

# run the notary in Gramine-SGX
make SGX=1 start-gramine-server
```

To test with non-SGX Gramine instead, omit `SGX=1` in both commands.
