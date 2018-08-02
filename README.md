# Extended APIs Hook Example

## Description

Using EPT to hook a function call is a common use case for reverse engineering,
introspection, and offensive / defensive research. This repository provides a
simple example of how this can be done using the [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor),
and the [Extended APIs](https://github.com/Bareflank/extended_apis) repo using EPT.
For further information about the Bareflank Hypervisor and how to create extensions, please see the following
documentation.

[API Documentation](http://bareflank.github.io/hypervisor/html/)

## Compilation / Usage

To setup our extension, run the following (assuming Linux):

```
git clone https://github.com/Bareflank/hypervisor
git clone https://github.com/Bareflank/extended_apis
git clone https://github.com/Bareflank/extended_apis_example_hook.git
mkdir build; cd build
cmake ../hypervisor -DDEFAULT_VMM=example_vmm -DEXTENSION=../extended_apis -DEXTENSION=../extended_apis_example_hook
make -j<# cores + 1>
```

To test out our extended version of Bareflank, run the following commands:

```
make driver_quick
make quick
```

our extension has its own commands to run the example:
```
make info
make hook
```

to reverse this:

```
make unload
make driver_unload
```
