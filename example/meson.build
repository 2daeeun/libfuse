examples = [ 'passthrough', 'passthrough_fh',
             'hello', 'hello_ll',
             'printcap', 'ioctl_client', 'poll_client',
             'ioctl', 'cuse', 'cuse_client' ]

if not platform.endswith('bsd') and platform != 'dragonfly'
    examples += [ 'passthrough_ll', 'hello_ll_uds' ]

    # According to Conrad Meyer <cem@freebsd.org>, FreeBSD doesn't
    # support mounting files, This is enforced in vfs_domount_first()
    # with the v_type != VDIR check.
    examples += [ 'null' ]
endif

threaded_examples = [ 'notify_inval_inode',
                      'invalidate_path',
                      'notify_store_retrieve',
                      'notify_inval_entry',
                      'poll' ]

foreach ex : examples
    executable(ex, ex + '.c',
               dependencies: [ libfuse_dep ],
               install: false)
endforeach


foreach ex : threaded_examples
    executable(ex, ex + '.c',
               dependencies: [ thread_dep, libfuse_dep ],
               install: false)
endforeach

if platform != 'dragonfly' and add_languages('cpp', required : false)
    executable('passthrough_hp', 'passthrough_hp.cc',
               dependencies: [ thread_dep, libfuse_dep ],
               install: false)
    executable('memfs_ll', 'memfs_ll.cc',
               dependencies: [ thread_dep, libfuse_dep ],
               cpp_args : '-std=c++20',
               install: false)
endif

if get_option('enable-extfuse-example')
    if platform != 'linux' or host_machine.cpu_family() != 'x86_64'
        error('The local ExtFUSE example currently requires Linux x86_64')
    endif

    extfuse_kernel_source = get_option('extfuse-kernel-source')
    extfuse_kernel_build = get_option('extfuse-kernel-build')
    if extfuse_kernel_source == '' or extfuse_kernel_build == ''
        error('enable-extfuse-example requires extfuse-kernel-source and extfuse-kernel-build')
    endif

    extfuse_clang = find_program('clang', required: true)
    extfuse_libbpf_dep = dependency('libbpf', required: true)
    extfuse_inc = include_directories('extfuse/include')

    extfuse_loader = shared_library(
        'extfuse',
        'extfuse/src/ebpf.c',
        include_directories: extfuse_inc,
        dependencies: [ thread_dep, libfuse_dep, extfuse_libbpf_dep ],
        c_args: [ '-Werror' ],
        install: false,
    )

    executable(
        'extfuse-passthrough',
        'extfuse/extfuse_passthrough.c',
        include_directories: [ include_directories('.'), extfuse_inc ],
        dependencies: [ thread_dep, libfuse_dep, extfuse_libbpf_dep ],
        link_with: extfuse_loader,
        c_args: [ '-Werror' ],
        install: false,
    )

    extfuse_bpf_headers = files(
        'extfuse/bpf/attr.h',
        'extfuse/bpf/lookup.h',
        'extfuse/bpf/xattr.h',
        'extfuse/include/extfuse.h',
        'extfuse/include/extfuse_coherence.h',
        'extfuse/include/extfuse_epoch_cache.h',
    )
    custom_target(
        'extfuse-bpf',
        input: 'extfuse/bpf/extfuse.c',
        output: 'extfuse.bpf.o',
        depfile: 'extfuse.bpf.o.d',
        depend_files: extfuse_bpf_headers,
        command: [
            extfuse_clang,
            '-I' + join_paths(extfuse_kernel_source,
                             'arch/x86/include/uapi'),
            '-I' + join_paths(extfuse_kernel_build,
                             'arch/x86/include/generated/uapi'),
            '-I' + join_paths(extfuse_kernel_source, 'include/uapi'),
            '-I' + join_paths(extfuse_kernel_build,
                             'include/generated/uapi'),
            '-I' + join_paths(meson.current_source_dir(),
                             'extfuse/include'),
            '-O2', '-g', '-Wall', '-Wno-cpp',
            '-target', 'bpf', '-D__TARGET_ARCH_x86',
            '-MD', '-MF', '@DEPFILE@', '-c', '@INPUT@', '-o', '@OUTPUT@',
        ],
        build_by_default: true,
    )
endif

# TODO: Link passthrough_fh with ulockmgr if available
