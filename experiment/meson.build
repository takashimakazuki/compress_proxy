
project('MPI-EXPERIMENT', 'C', 'CPP',
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

shared_library('extern_zstd', lib_sources, include_directories: lib_inc, dependencies: app_dependencies)

### MPI test function MPI_Send
executable('test_send', ['test_send.c'], dependencies: app_dependencies)
executable('test_send_nbytes', ['test_send_nbytes.c'], dependencies: app_dependencies)
