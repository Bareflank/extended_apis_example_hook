//
// Bareflank Hypervisor
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <ioctl.h>
#include <guard_exceptions.h>

#if defined(_WIN32) || defined (__CYGWIN__)
#include <windows.h>
#else
#include <sched.h>
#include <iostream>
#endif

void
hello_world()
{ std::cout << "hello world" << '\n'; }

void
hooked_hello_world()
{ std::cout << "hooked hello world" << '\n'; }

int
main(int argc, const char *argv[])
{
    (void) argc;
    (void) argv;

    vmcall_registers_t regs;

#if defined(_WIN32) || defined (__CYGWIN__)
    SetProcessAffinityMask(GetCurrentProcess(), 1);
#else
    cpu_set_t  mask;
    CPU_ZERO(&mask);
    CPU_SET(0, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);
#endif

    guard_exceptions([&]
    {
        // Open a connection to the bfdriver. We could just run the vmcall
        // instruction ourselves, but we would need to write a version for both
        // Windows and Linux, and that's a pain, so instead we reuse the IOCTL
        // interface that is provided by BFM.
        ioctl ctl;
        ctl.open();

        // Setup our vmcall to tell the hypervisor what function to hook, and what
        // to hook it with. Note that we could have used JSON as well, but in this
        // case, a register based vmcall was a lot easier
        regs.r00 = VMCALL_REGISTERS;
        regs.r01 = VMCALL_MAGIC_NUMBER;
        regs.r02 = 1;
        regs.r03 = reinterpret_cast<uintptr_t>(hello_world);
        regs.r04 = reinterpret_cast<uintptr_t>(hooked_hello_world);

        // Tell the hypervisor to hook. Any attempt to execute the hello world
        // function should be redirected to the hooked hello world function
        // instead
        ctl.call_ioctl_vmcall(&regs, 0);

        // Attempt to call hello world. If all goes well, this will end up calling
        // the hooked version instead. Note that we call it more than once to
        // ensure out trap is working properly.
        hello_world();
        hello_world();
        hello_world();

        // Setup our vmcall to tell the hypervisor to unhook the previous hook
        // that we just installed. If your hooking the kernel this step would
        // likely not be needed.
        regs.r00 = VMCALL_REGISTERS;
        regs.r01 = VMCALL_MAGIC_NUMBER;
        regs.r02 = 2;

        // Tell the hypervisor to unhook. This should put the system back to
        // normal, and the hypervisor should stop trapping.
        ctl.call_ioctl_vmcall(&regs, 0);
    });

    return 0;
}
