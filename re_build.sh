#!/bin/sh
set -eu

die()
{
  printf 're_build.sh: %s\n' "$*" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
expected_dir=/home/leedaeeun/Documents/github/libfuse
[ "${script_dir}" = "${expected_dir}" ] ||
  die "unexpected repository root: ${script_dir}"
[ "$#" -eq 0 ] || die 'usage: ./re_build.sh'
cd -- "${script_dir}"

build_dir=${script_dir}/build-hand
kernel_source=/home/leedaeeun/Documents/github/linux
kernel_build=/home/leedaeeun/Documents/github/_kernel_build/build-6.19.14-ExtFUSE-AllOpt

set -- \
  -Dtests=false \
  -Dexamples=true \
  -Dutils=true \
  -Denable-io-uring=true \
  -Denable-extfuse-example=true \
  -Dextfuse-kernel-source="${kernel_source}" \
  -Dextfuse-kernel-build="${kernel_build}"

if [ -e "${build_dir}" ] || [ -L "${build_dir}" ]; then
  [ -d "${build_dir}" ] && [ ! -L "${build_dir}" ] ||
    die "refusing unsafe build directory: ${build_dir}"
  [ "$(realpath -e -- "${build_dir}")" = "${build_dir}" ] ||
    die "build directory escaped its fixed path: ${build_dir}"
  printf 'DELETE_TARGET=%s\n' "${build_dir}"
  rm -rf --one-file-system -- "${build_dir}"
fi
meson setup "${build_dir}" "$@"
meson compile -C "${build_dir}" extfuse-passthrough extfuse-bpf
