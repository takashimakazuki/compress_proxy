#
# Copyright (c) 2021 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project('COMM-CHANNEL', 'C', 'CPP',
	# Get version number from file.
	# Fallback to "more" for Windows compatibility.
	version: run_command(find_program('cat', 'more'),
		files('VERSION')).stdout().strip(),
	license: 'BSD',
	default_options: ['buildtype=debug',
			  'default_library=static'],
	meson_version: '>= 0.47.1'
)

# set up some global vars for compiler, platform, configuration, etc.
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')


if host_machine.cpu_family().startswith('x86')
	add_project_arguments('-march=native', language: 'c')
	add_project_arguments('-mavx', language: 'c')
	arch_subdir = 'x86'
elif host_machine.cpu_family().startswith('arm') or host_machine.cpu_family().startswith('aarch')
	arch_subdir = 'arm'
elif host_machine.cpu_family().startswith('ppc')
	arch_subdir = 'ppc'
endif

# Remove warnings of experimental compile
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: 'c')
add_project_arguments('-D DOCA_LOGGING_ALLOW_DLOG', language: 'c')


app_dependencies = []
libdpdk_dep = dependency('libdpdk', required : true)
if not libdpdk_dep.found()
	error('please set PKG_CONFIG_PATH to dpdk packages path, for further instructions check DOCA manuals')
endif
libdoca_dep = dependency('doca', required : true)
if not libdoca_dep.found()
    error('please set PKG_CONFIG_PATH to doca packages path')
endif

app_dependencies += libdpdk_dep
app_dependencies += libdoca_dep

client_sources = [
	'cc_client.c',
    'common.c',
    'cc_common.c',
]

server_sources = [
    'cc_server.c',
    'common.c',
    'cc_common.c',
]

inc_dir = include_directories(
    '/opt/mellanox/doca/include',
)


if host_machine.cpu_family().startswith('x86')
	executable('cc_client', client_sources, dependencies : app_dependencies, include_directories : inc_dir, install: true)
elif host_machine.cpu_family().startswith('arm') or host_machine.cpu_family().startswith('aarch')
	executable('cc_server', server_sources, dependencies : app_dependencies, include_directories : inc_dir, install: true)
endif