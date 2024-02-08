
project('EXPERIMENT', 'C', 'CPP',
	# Get version number from file.
	# Fallback to "more" for Windows compatibility.
    version: '0.0.1',
	license: 'BSD',
	default_options: ['buildtype=release',
			  'default_library=static'],
	meson_version: '>= 0.47.1'
)

# set up some global vars for compiler, platform, configuration, etc.
cc = meson.get_compiler('c')
cpp = meson.get_compiler('cpp')


if host_machine.cpu_family().startswith('x86')
	app_dependencies = []
	libzstd_dep = dependency('libzstd', required : true)
	if not libzstd_dep.found()
		error('please set PKG_CONFIG_PATH to doca packages path')
	endif
	libmpi_dep = dependency('mpi', language: 'c', required : true)
	if not libmpi_dep.found()
		error('dependency mpi not found')
	endif

	app_dependencies += libzstd_dep
	app_dependencies += libmpi_dep


	### zstd PMPI library
	lib_sources = [
		'extern_zstd.c',
	]

	lib_inc = include_directories(
		'.',
	)

	### Shared library
	shared_library('extern_zstd', lib_sources, include_directories: lib_inc, dependencies: app_dependencies)
	### MPI test function MPI_Send
	executable('test_send', ['test_send.c'], dependencies: app_dependencies)
	executable('test_send_nbytes', ['test_send_nbytes.c'], dependencies: app_dependencies)
	executable('time_zstd', ['time_zstd.c'], dependencies: app_dependencies)
endif


if host_machine.cpu_family().startswith('arm') or host_machine.cpu_family().startswith('aarch')
	dpu_dependencies = []
	dpu_dependencies += dependency('doca', required: true)
	dpu_dependencies += dependency('libzstd', required: true)
	add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: 'c')

	src = [
		'time_compression.c',
		'../comp_proxy/common.c',
		'../comp_proxy/compress_util.c',
	]
	arch_subdir = 'arm'
	executable('time_compression', src, include_directories: ['../comp_proxy'], dependencies: dpu_dependencies)
endif