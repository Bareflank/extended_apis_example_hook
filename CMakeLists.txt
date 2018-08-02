#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# ------------------------------------------------------------------------------
# Extensions
# ------------------------------------------------------------------------------

userspace_extension(
    hook
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/app
    DEPENDS bfintrinsics
)

eapis_vmm_extension(
    hook
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/src
)

# ------------------------------------------------------------------------------
# Custom Target
# ------------------------------------------------------------------------------

add_custom_target_category("Hook Example Commands")

add_custom_target(hook
    COMMAND ${USERSPACE_PREFIX_PATH}/bin/hook
    USES_TERMINAL
)

add_custom_target_info(
    TARGET hook
    COMMENT "Run the hook example application"
)

