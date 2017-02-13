# Extended APIs Hook Example

## Description

Using EPT to hook a function call is a common use case for reverse engineering,
introspection, and offensive / defensive research. This repository provides a
simple example of how this can be done using the [Bareflank Hypervisor](https://github.com/Bareflank/hypervisor), 
and the [Extended APIs](https://github.com/Bareflank/extended_apis) repo using EPT / VPID. 
For further information about the Bareflank Hypervisor and how to create extensions, please see the following
documentation.

[API Documentation](http://bareflank.github.io/hypervisor/html/)

## Compilation / Usage

This example uses both the Bareflank Hypervisor, as well as the Extended APIs
repo. To keep things simple, we will use an in-tree build for this example.
Note that the Extended APIs build on their own, but to get our example to
build in-tree, we need to prepend "src_" to the folder name so that Bareflank
knows to compile it as well.

```
cd ~/
git clone https://github.com/Bareflank/hypervisor.git
cd ~/hypervisor
git clone https://github.com/Bareflank/extended_apis.git
git clone https://github.com/Bareflank/extended_apis_example_hook.git src_extended_apis_example_hook

./tools/scripts/setup-<xxx>.sh --no-configure
sudo reboot

~/hypervisor/configure -m src_extended_apis_example_hook/bin/hook.modules
make
```

To run this example, we need to first load the hypervisor, and then run the
example app that will get hooked by the hypervisor. Note that this app has to
perform a vmcall, so it will need root privileges.

```
make driver_load
make quick

sudo ./makefiles/src_extended_apis_example_hook/app/bin/native/hook

make stop
make driver_unload
```
