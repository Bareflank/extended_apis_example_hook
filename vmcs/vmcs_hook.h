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

#ifndef VMCS_HOOK_H
#define VMCS_HOOK_H

#include <vmcs/root_ept_intel_x64.h>
#include <vmcs/vmcs_intel_x64_eapis.h>

using namespace intel_x64;
using namespace vmcs;

#ifndef MAX_PHYS_ADDR
#define MAX_PHYS_ADDR 0x1000000000
#endif

std::unique_ptr<root_ept_intel_x64> g_root_ept;

class vmcs_hook : public vmcs_intel_x64_eapis
{
public:

    /// Default Constructor
    ///
    vmcs_hook() = default;

    /// Destructor
    ///
    ~vmcs_hook() override = default;

    /// Write Fields
    ///
    /// We override this function so that we can setup the VMCS the way we
    /// want.
    void
    write_fields(gsl::not_null<vmcs_intel_x64_state *> host_state,
                 gsl::not_null<vmcs_intel_x64_state *> guest_state) override
    {
        static auto initialized = false;

        // Let Bareflank do it's thing before we setup the VMCS. This setups
        // up a lot of default fields for us, which we can always overwrite
        // if we want once this is done.
        vmcs_intel_x64_eapis::write_fields(host_state, guest_state);

        if (!initialized)
        {
            g_root_ept = std::make_unique<root_ept_intel_x64>();

            // Setup an identity map. There are a couple of notes here:
            // - Using an identity map prevents us from having to implement on
            //   demand paging, which has it's own set of issues. Note that we
            //   setup by default 64G of memory, but you might need more.
            // - We use 2m granularity here. We do this because VMWare doesn't
            //   support 1g granularity, and because when we hook, we will convert
            //   a portion of the pages to 4k granularity, and this reduces the
            //   total number of pages that are needed to do this.
            g_root_ept->setup_identity_map_2m(0, MAX_PHYS_ADDR);

            // Since EPT in the Extended APIs is global, we should only set it
            // up once.
            initialized = true;
        }

        // Enable EPT and VPID. If your going to use EPT, you really should be
        // using VPID as well, and Intel comes with TLB invalidation
        // instructions that leverage VPID, which provide per-line invalidation
        // which you don't get without VPID. We also need to set the eptp that
        // we plan to use.
        this->enable_ept();
        this->enable_vpid();
        this->set_eptp(g_root_ept->eptp());
    }
};

#endif
