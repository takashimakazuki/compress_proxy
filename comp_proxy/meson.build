
project('COMPRESS-PROXY', 'C', 'CPP',
	# Get version number from file.
	# Fallback to "more" for Windows compatibility.
	version: run_command(find_program('cat', 'more'),
		files('VERSION'), check: true).stdout().strip(),
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
libdoca_dep = dependency('doca', required : true)
if not libdoca_dep.found()
    error('please set PKG_CONFIG_PATH to doca packages path')
endif
libucx_dep = dependency('ucx', required : true)
if not libucx_dep.found()
    error('please set PKG_CONFIG_PATH to ucx packages path')
endif

app_dependencies += libdoca_dep
app_dependencies += libucx_dep

sources = [
    'compress_proxy.c',
	'common.c',
    'pack.c',
    'utils.c',
]

inc_dir = include_directories(
    '/opt/mellanox/doca/include',
    'include',
    '.',
)


executable('compress_proxy', sources, dependencies : app_dependencies, include_directories : inc_dir, install: true)