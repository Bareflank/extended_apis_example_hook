//
// Bareflank Hypervisor Examples
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

#ifndef EXIT_HANDLER_HOOK_H
#define EXIT_HANDLER_HOOK_H

#include <memory_manager/map_ptr_x64.h>

#include <vmcs/vmcs_intel_x64_eapis.h>
#include <vmcs/vmcs_intel_x64_16bit_control_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>

#include <exit_handler/exit_handler_intel_x64_eapis.h>

using namespace intel_x64;

class exit_handler_hook : public exit_handler_intel_x64_eapis
{
public:

    /// Default Constructor
    ///
    exit_handler_hook() :
        m_func(0),
        m_hook(0),
        m_func_phys(0)
    { }

    /// Destructor
    ///
    ~exit_handler_hook() override
    { }

    /// Monitor Trap Callback
    ///
    /// When the trap flag is set, and the VM is resumed, a VM exit is
    /// generated after the next instruction executes, providing a means
    /// to single step the execution of the VM. When this single step
    /// occurs, this callback is called.
    ///
    void
    monitor_trap_callback()
    {
        expects(m_entry != nullptr);

        // Reset the trap. This ensures that if the hooked function executes
        // again, we trap again. Note that since we are modifying an EPTE, we
        // need to flush the EPT mappings. Normally, you would want to only
        // flush the TLB associated with a specific set of virtual addresses
        // and VPID, but to keep the code simple for this example, we just do
        // a global flush.
        m_entry->trap_on_access();
        intel_x64::vmx::invept_global();

        // Resume the VM
        eapis_vmcs()->resume();
    }

    /// Handle Exit
    ///
    /// A lot of exits will occur, and we can hand these exits to Bareflank to
    /// handle for us. The only one that we are interested in is EPT violation
    /// which occurs when memory is accessed in a way that the EPTE said was
    /// not allowed.
    ///
    void handle_exit(intel_x64::vmcs::value_type reason) override
    {
        // There are two reason why an EPT violation might be generated in this
        // example
        // - The EPTE that we are trapping on has been accessed. This is the
        //   case that we are most concerned about and need to handle.
        // - A physical address was accessed that we have not setup an EPTE for
        //   when setting up the identity map. This is likely the result of
        //   the system using more memory than we accounted for, and we need
        //   to increase the size of the identity map.
        if (reason == intel_x64::vmcs::exit_reason::basic_exit_reason::ept_violation)
        {
            expects(m_entry != nullptr);

            auto &&mask = ~(ept::pt::size_bytes - 1);
            auto &&virt = intel_x64::vmcs::guest_linear_address::get();
            auto &&phys = intel_x64::vmcs::guest_physical_address::get();

            // We only marked a single, 4k EPTE to trap (i.e. read, write and
            // execute access are denied). If we get a trap on an address that
            // is not from this EPTE, we have an issue as the original EPTE
            // was not setup to be large enough
            if ((phys & mask) == (m_func_phys & mask))
            {
                // We are trapping on a 4k page, which has most of the code
                // from our example, and we really only care about the specific
                // function we are trying to hook, so we need to ignore
                // accesses to the EPTE that are not from our function.
                //
                // If the access does come from our hook, we perform the hook
                // by changing RIP. There are a lot of schemes here that you
                // could use. For example, MoRE and DdiMon use a shadow page.
                // This approach is simple. If the code attempts to execute
                // the function we want to hook, we change RIP to point to
                // the function we actually want to execute, which is our hook.
                //
                // Note that a more complete example would read the exit
                // qualification, and only perform this hook on an attempt to
                // execute, allowing reads through which would further mask the
                // hook.
                if (virt == m_func)
                    m_state_save->rip = m_hook;

                // We need the code to complete it's execution, which means we
                // need remove the trap on the EPTE. Note that since we are
                // modifying an EPTE, we need to flush the EPT mappings again.
                m_entry->pass_through_access();
                intel_x64::vmx::invept_global();

                // Since we removed the trap on the EPTE, we need a way to turn
                // the trap back on once the instruction finishes it's
                // execution. To do this, we install a monitor trap callback,
                // which will reverse the above operation.
                this->register_monitor_trap(&exit_handler_hook::monitor_trap_callback);

                // Resume the VM
                eapis_vmcs()->resume();
            }
            else
            {
                bfwarning << "EPT has not been setup for this address. " << bfendl;
                bfwarning << "To solve this issue, increase MAX_PHYS_ADDR. " << bfendl;
                bfwarning << "Note MAX_MEM_MAP_POOL might need to be increased too. " << bfendl;
            }
        }

        exit_handler_intel_x64_eapis::handle_exit(reason);
    }

    /// Handle VMCall Registers
    ///
    /// Bareflank handles a lot of the grunt work associated with VMCalls,
    /// and will call this function if a register based VMCall has been made
    /// by the VM. We override it here to provide the example with a means
    /// to report which function to hook, and what to hook it with.
    ///
    void
    handle_vmcall_registers(vmcall_registers_t &regs) override
    {
        // Get the physical address of the function we plan to hook.
        auto &&cr3 = intel_x64::vmcs::guest_cr3::get();
        m_func_phys = bfn::virt_to_phys_with_cr3(regs.r02, cr3);

        // We need to know what the physical address is for the function
        // we plan to hook aligned to both 2m and 4k. Currently, the physical
        // address that this function is on, exists on a 2m EPTE. The problem
        // is, the application is small, and thus, the kernel is only going
        // to give a small portion of that 2m EPTE to our application, and
        // will give out the remaining space to other applications. If we hook
        // the entire 2m, we could end up with a LOT of traps from applications
        // running in the background. So... to fix this issue, we will convert
        // the 2m EPTE to a 4k identity map, and then only hook the 4k region
        // associated with the function we plan to hook.
        auto &&func_phys_2m = m_func_phys & ~(ept::pd::size_bytes - 1);
        auto &&func_phys_4k = m_func_phys & ~(ept::pt::size_bytes - 1);

        // Get the start / end location for the 2m EPTE that we plan to
        // convert to a 4k identity map.
        auto &&saddr = func_phys_2m;
        auto &&eaddr = func_phys_2m + ept::pd::size_bytes;

        // Convert the EPTE associated with the function we plan to hook from
        // a 2m EPTE to a 4k identify map that takes up the same physical
        // address range.
        eapis_vmcs()->unmap(func_phys_2m);
        eapis_vmcs()->setup_ept_identity_map_4k(saddr, eaddr);

        // Get the EPTE associated with the function we plan to hook, and mark
        // this EPTE as trapped. Any accesses to this EPTE will result in a
        // EPT Violation VM exit. Once again, we need to flush the TLB since
        // we modified EPT.
        m_entry = eapis_vmcs()->gpa_to_epte(func_phys_4k);
        m_entry->trap_on_access();
        intel_x64::vmx::invept_global();

        bfdebug << "trapping on: " << view_as_pointer(func_phys_4k) << bfendl;

        m_func = regs.r02;
        m_hook = regs.r03;
    }

private:

    uintptr_t m_func;
    uintptr_t m_hook;
    uintptr_t m_func_phys;
    ept_entry_intel_x64 *m_entry;
};

#endif
