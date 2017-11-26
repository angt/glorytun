project('glorytun', 'c',
    version: run_command('./version.sh').stdout(),
    license: 'BSD-3-Clause',
    default_options : [ 'buildtype=debugoptimized' ]
)

prefix = get_option('prefix')
bindir = join_paths(prefix, get_option('bindir'))

conf_data = configuration_data()
conf_data.set('prefix', prefix)
conf_data.set('bindir', bindir)

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

systemd = dependency('systemd', required: false)

if systemd.found()
  systemdutildir = systemd.get_pkgconfig_variable('systemdutildir')
  configure_file(
      input: 'systemd/glorytun@.service.in',
      output: 'glorytun@.service',
      configuration: conf_data,
      install_dir: join_paths(systemdutildir, 'system')
  )
  install_data('systemd/glorytun.network',
      install_dir: join_paths(systemdutildir, 'network'))
  install_data('systemd/glorytun-client.network',
      install_dir: join_paths(systemdutildir, 'network'))
  install_data('systemd/glorytun-run',
      install_dir: bindir)
  install_data('systemd/glorytun-setup',
      install_dir: bindir)
endif
