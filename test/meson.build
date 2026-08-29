# Compile helper programs
td = []
foreach prog: [ 'test_write_cache', 'test_setattr', 'hello' ]
    td += executable(prog, prog + '.c',
                     include_directories: include_dirs,
                     link_with: [ libfuse ],
                     dependencies: thread_dep,
                     install: false)
endforeach
td += executable('test_syscalls', 'test_syscalls.c',
                 include_directories: include_dirs,
                 install: false)
td += executable('readdir_inode', 'readdir_inode.c',
                 include_directories: include_dirs,
                 install: false)
td += executable('release_unlink_race', 'release_unlink_race.c',
                 dependencies: [ libfuse_dep ],
                 install: false)
td += executable('test_want_conversion', 'test_want_conversion.c',
                 dependencies: [ libfuse_dep ],
                 install: false)
td += executable('test_signals', 'test_signals.c',
                 dependencies: [ libfuse_dep, thread_dep ],
                 install: false)
td += executable('test_abi', 'test_abi.c',
                 dependencies: [ libfuse_dep ],
                 install: false)
td += executable('test_extfuse_init', 'test_extfuse_init.c',
                 dependencies: [ libfuse_dep ],
                 install: false)
extfuse_v3_test = executable(
    'test_extfuse_v3', 'test_extfuse_v3.c',
    dependencies: [ libfuse_dep ],
    install: false)
td += extfuse_v3_test
test('ExtFUSE coherence V3', extfuse_v3_test)
native_request_counter_test = executable(
    'test_native_request_counter', 'test_native_request_counter.c',
    dependencies: [ libfuse_dep ],
    install: false)
td += native_request_counter_test
test('native request counter', native_request_counter_test)

if private_cfg.get('HAVE_URING', false)
    uring_affinity_test = executable(
        'test_uring_affinity', 'test_uring_affinity.c',
        include_directories: include_dirs,
        dependencies: [ libnuma ],
        install: false)
    td += uring_affinity_test
    test('io_uring thread affinity', uring_affinity_test)
endif

test_scripts = [ 'conftest.py', 'pytest.ini', 'test_examples.py',
                 'util.py', 'test_ctests.py', 'test_custom_io.py',
                 'test_extfuse.py' ]
td += custom_target('test_scripts', input: test_scripts,
                      output: test_scripts, build_by_default: true,
                      command: ['cp', '-fPp',
                                '@INPUT@', meson.current_build_dir() ])

# Provide something helpful when running 'ninja test'

if meson.is_subproject()
	test('libfuse is a subproject, skipping tests', executable('wrong_command',
                      'wrong_command.c', install: false,
                       c_args: [ '-DMESON_IS_SUBPROJECT' ]))
else
	test('wrong_command', executable('wrong_command', 'wrong_command.c',
                      install: false))
endif
