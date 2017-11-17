project('glorytun', 'c',
    version: run_command('./version.sh').stdout(),
    license: 'BSD-3-Clause',
    default_options : [ 'buildtype=debugoptimized' ]
)

add_global_arguments('-DPACKAGE_VERSION="'+meson.project_version()+'"', language : 'c')

src = [
  'src/common.c',
  'src/iface.c',
  'src/option.c',
  'src/tun.c',
  'mud/mud.c',
  'src/main.c'
]

deps = [
  dependency('libsodium', version : '>=1.0.4')
]

executable('glorytun', install: true, sources: src, dependencies: deps)
