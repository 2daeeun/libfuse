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
extfuse_background_limits_test = executable(
    'test_extfuse_background_limits', 'test_extfuse_background_limits.c',
    dependencies: [ libfuse_dep ], install: false)
td += extfuse_background_limits_test
test('ExtFUSE background limits', extfuse_background_limits_test)
extfuse_coherence_epochs_test = executable(
    'test_extfuse_coherence_epochs', 'test_extfuse_coherence_epochs.c',
    dependencies: [ libfuse_dep ],
    install: false)
td += extfuse_coherence_epochs_test
test('ExtFUSE coherence epochs', extfuse_coherence_epochs_test)
native_request_counter_test = executable(
    'test_native_request_counter', 'test_native_request_counter.c',
    dependencies: [ libfuse_dep ],
    install: false)
td += native_request_counter_test
test('native request counter', native_request_counter_test)

if host_machine.system().startswith('linux')
    test('writeback open/create/tmpfile flags', find_program('python3'),
        args: [files('../example/extfuse/test_writeback_open_flags.py')])
    workload_test = executable('test_workload_detector',
        ['test_workload_detector.c', '../lib/fuse_workload.c'],
        include_directories: include_dirs, install: false)
    test('adaptive workload detector', workload_test)
    qd_policy_test = executable('test_qd_policy',
        ['test_qd_policy.c', '../lib/fuse_qd_policy.c', '../lib/fuse_workload.c'],
        include_directories: include_dirs, install: false)
    test('adaptive QD policy', qd_policy_test,
        args: [files('fixtures/qd-policy.conf')])
    adaptive_init_test = executable('test_adaptive_init', 'test_adaptive_init.c',
        dependencies: [ libfuse_dep ], install: false)
    test('adaptive options and INIT', adaptive_init_test,
        args: [files('fixtures/qd-policy.conf')])
    if get_option('utils')
        test('adaptive control CLI', find_program('python3'),
            args: [files('test_adaptive_cli.py'),
                   join_paths(meson.project_build_root(), 'util', 'fuse-uring-ctl')])
    endif
endif

syncfs_test = executable('test_syncfs', 'test_syncfs.c',
                        dependencies: [ libfuse_dep ], install: false)
td += syncfs_test
test('SYNCFS negotiation and dispatch', syncfs_test)

reply_data_prepare_test = executable(
    'test_reply_data_prepare', 'test_reply_data_prepare.c',
    dependencies: [ libfuse_dep ], install: false)
td += reply_data_prepare_test
test('data reply preparation ordering and failures', reply_data_prepare_test)
test('data reply preparation splice ordering and failures',
     reply_data_prepare_test, args: ['--splice'])

if private_cfg.get('HAVE_URING', false)
    uring_reply_test = executable(
        'test_uring_reply', 'test_uring_reply.c',
        include_directories: include_dirs,
        install: false)
    td += uring_reply_test
    test('io_uring reply header', uring_reply_test)
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

if private_cfg.get('HAVE_URING', false)
    uring_runtime_test = executable(
        'test_uring_runtime', 'test_uring_runtime.c',
        include_directories: include_dirs,
        dependencies: [libfuse_dep, thread_dep, libnuma, dependency('liburing')],
        c_args: ['-ffunction-sections', '-fdata-sections'],
        link_args: ['-Wl,--gc-sections'],
        install: false)
    td += uring_runtime_test
    test('io_uring runtime QD engine', uring_runtime_test)
    adaptive_control_test = executable(
        'test_adaptive_control',
        ['test_adaptive_control.c', '../lib/fuse_workload.c', '../lib/fuse_qd_policy.c'],
        include_directories: include_dirs,
        dependencies: [thread_dep, libnuma, dependency('liburing')],
        install: false)
    td += adaptive_control_test
    test('adaptive monitor and control socket', adaptive_control_test,
        args: [files('fixtures/qd-policy.conf'), files('../config/qd-policy-tec.conf')], timeout: 15)
endif
