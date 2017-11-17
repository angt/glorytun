project('glorytun', 'c',
    version: run_command('./version.sh').stdout()
)

add_global_arguments('-DPACKAGE_VERSION="'+meson.project_version()+'"', language : 'c')

executable('glorytun', install: true,
    sources: [ 'src/main.c', 'src/common.c', 'src/option.c', 'src/tun.c', 'src/iface.c', 'mud/mud.c' ],
    dependencies: [ dependency('libsodium', version : '>=1.0.4') ]
)
