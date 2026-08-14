# libfuse 작업 원칙

## 경로 정의

- `libfuse` = `/home/leedaeeun/Documents/github/libfuse` (이 저장소)
- `linux` = `/home/leedaeeun/Documents/github/linux`
- `ExtFUSE_Code` = `/home/leedaeeun/Documents/github/ExtFUSE_Code`
- `fuse_exp` = `/home/leedaeeun/Documents/github/fuse_exp`
- `fuse_kbuild_tools` = `/home/leedaeeun/Documents/github/fuse_kbuild_tools`
- `research_exp` = `/home/leedaeeun/Documents/github/research_exp`
- `StackFS` = `/home/leedaeeun/Documents/github/StackFS`
- `filebench` = `/home/leedaeeun/Documents/github/filebench`

이하 본문의 `<이름>/<하위경로>` 표기는 모두 위 절대경로 기준이며, 현재 shell의 작업
디렉터리와 무관하게 유효하다.

## 절대 원칙

- 상위 시스템·개발자 지시를 제외하면 사용자의 현재 명시적 지시가 이
  문서보다 우선한다.
- 하위 작업 경로의 `AGENTS.override.md` 또는 `AGENTS.md`를 확인하고, 현재
  파일에 더 가까운 지시를 우선한다.
- 작업 전 `pwd -P`, repository root, `git status --short --branch`,
  `git rev-parse HEAD`, 관련 diff와 untracked 파일을 확인한다.
- 기존 tracked, staged, untracked 변경은 모두 사용자 작업으로 간주한다.
  요청과 관련된 파일만 수정하며 기존 작업을 삭제하거나 덮어쓰지 않는다.

## 작업 공간 지도

```text
/home/leedaeeun/Documents/github/
├── ExtFUSE_Code/       ATC'19 원본 Linux/libfuse 및 ExtFUSE BPF·loader 아카이브
├── filebench/          WML 기반 파일시스템·스토리지 workload/benchmark 실행기
├── fuse_exp/           ExtFUSE 실험, workload, trace, 분석과 결과 관리
├── fuse_kbuild_tools/  커널 설정·외부 빌드·설치와 fuse.ko 재빌드 도구
├── libfuse/            userspace FUSE (`fuse-3.18.2-ExtFUSE`, 현재 저장소)
├── linux/              대응 kernel FUSE Driver (`ExtFUSE-v6.19.14`)
├── research_exp/       격리 소스·빌드·실험·패치·보고서·결과 작업 공간
└── StackFS/             원본 ExtFUSE 검증용 StackFS Opt baseline/MDOpt filesystem
```

- modern: `linux` + `libfuse` → `fuse_exp`의 workload/trace/benchmark
- original 비교: `ExtFUSE_Code` + `StackFS` → `fuse_exp`
- 커널 빌드·배포: `linux` → `fuse_kbuild_tools`
- 격리 검증: 관련 source → `research_exp` → 검증된 관련 파일만 원본에 반영
- Filebench 실험은 `filebench` 실행기와 `fuse_exp` 설정을 함께 확인한다.
- 이 지도는 탐색 기준일 뿐 형제 저장소의 수정 권한을 부여하지 않는다.
  형제 저장소에서는 그 저장소의 지시 파일을 먼저 확인한다.

## ExtFUSE와 Linux FUSE Driver

- `linux`의 `ExtFUSE-v6.19.14`브랜치와 현재 저장소의 `fuse-3.18.2-ExtFUSE`브랜치는
  하나의 kernel/userspace 호환성 세트다.
- 연동 작업 전 두 저장소의 실제 브랜치를 확인한다. 예상 조합과 다르면
  호환된다고 가정하지 않는다.
- FUSE protocol, UAPI, capability, INIT 협상, 구조체 layout, ExtFUSE 또는
  io_uring 변경은 양쪽 구현과 ABI를 함께 확인한다.
- `linux`는 별도 작업 범위이므로 명시적인 요청 없이 수정하지 않는다.

ExtFUSE 코드와 설명은 다음 범주를 반드시 구분한다.

1. `ExtFUSE_Code`에서 유래한 핵심 동작의 semantic port
2. 현대 `linux`/`libfuse` 사이의 UAPI·capability·INIT·ABI 호환성 변경
3. 원본에 없던 로컬 확장
   - passthrough coherence: `libfuse/include/fuse_common.h`,
     `libfuse/include/fuse_kernel.h`, `libfuse/lib/fuse_lowlevel.c`,
     `libfuse/test/test_extfuse_init.c`
   - native request counter: `libfuse/include/fuse_lowlevel.h`,
     `libfuse/lib/fuse_i.h`, `libfuse/lib/fuse_lowlevel.c`,
     `libfuse/lib/fuse_versionscript`, `libfuse/test/test_native_request_counter.c`
   - `passthrough_ll`·benchmark 지원: `libfuse/example/passthrough_ll.c`,
     `libfuse/example/meson.build`, `libfuse/test/test_examples.py`;
     실험 설정은 `fuse_exp`

브랜치 이름이나 위 경로만으로 provenance를 단정하지 않는다. 원본 코드와
commit/diff를 확인하고 세 범주의 구현·검증 근거를 서로 대신하지 않는다.

## Git

- 기본적으로 Git은 조회에만 사용한다. working tree, index, history, refs,
  remote, config 또는 submodule 상태를 바꾸는 명령은 명시적인 허가가
  필요하다. 안전 여부가 불확실하면 실행하지 않는다.
- 허용 예: `status`, `diff`, `log`, `show`, `grep`, `blame`, `ls-files`,
  `rev-parse`, `shortlog`, branch/tag 조회, remote 이름 조회, `stash list`.
- remote URL이나 repository-local config에는 credential userinfo가 있을 수 있다.
  `git remote -v`, `git config --list`, `libfuse/.git/config` 또는 raw URL을
  출력하지 않고, 필요하면 credential/userinfo를 제거한 host/path만 보고한다.
- 허가 없이 금지되는 예: `add`, `commit`, `push`, `pull`, `fetch`, `checkout`,
  `switch`, `reset`, `restore`, `clean`, `rm`, `apply`, `am`, `rebase`, `merge`,
  `cherry-pick`, `revert`, stash 변경, worktree·branch·tag 변경, `update-index`,
  config 변경, `submodule update`, history rewrite와 force 옵션.

## 코드와 임시 작업 공간

- 기존 동작, ABI, ownership과 lifetime을 가능한 한 유지한다. public API를
  바꾸면 관련 header, implementation, documentation과 test를 함께 확인한다.
- C/C++은 `libfuse/.clang-format`을 따른다: tab indent, tab/indent 폭 8, 80 columns.
- 격리 검증이 필요하면 `research_exp/cleanup/workspace/sources`에 새 task-specific
  작업 공간을 만들고 필요한 코드만 물리 복사해 수정·빌드·검증할 수 있다. 원본으로
  이어지는 symlink나 `.git`은 복사하지 않는다.
- 반영 직전에 원본의 status와 diff를 다시 확인한다. 원본이 그대로이면
  검증된 파일을 반영할 수 있고, 새 사용자 변경이 있으면 필요한 hunk만
  병합한다. 안전하게 병합할 수 없으면 수정하지 않고 충돌을 보고한다.
- 격리 공간은 금지된 Git 작업을 우회하는 용도로 사용하지 않는다.

## 빌드와 검증

- 구현 요청에는 사용자가 범위를 더 제한하지 않은 한 관련 비특권 out-of-tree
  build와 targeted test가 포함된다. 분석·설명·review 요청은 읽기 전용이며,
  benchmark, tracing, mount lifecycle, sibling 저장소 변경, install과 권한 작업은
  각각 그 범위의 명시적 요청이 필요하다.
- `research_exp`에서 검증한 코드를 요청 범위의 원본 파일에 반영한 뒤에는 원본
  경로에서도 같은 비특권 build와 targeted test를 수행할 수 있다.
- 현재 작업용 새 build directory를 기본으로 사용한다. 기존 build directory를
  삭제·비우거나 현재 작업과 무관한 설정으로 reconfigure하지 않는다.
  `libfuse/re_build.sh`는 `libfuse/build`, `libfuse/build-extfuse`를 무조건
  `rm -rf`하므로 이 규칙과 충돌한다. 명시적으로 요청되지 않으면 실행하지 않는다.
- 기본 구성은
  `meson setup <build-dir> -Dtests=true -Dexamples=true -Dutils=true -Denable-io-uring=true`다.
  기존 build를 재구성할 때는 `meson setup --reconfigure <build-dir> ...`를 쓴다.
  `<build-dir>`은 임의로 선택한 out-of-tree build directory 경로다.
- 코드 변경 후 가능한 범위에서 다음 순서로 검증한다.
  1. `git diff --check`
  2. 위 Meson setup 또는 reconfigure
  3. `meson compile -C <build-dir>`
  4. 직접 관련 test. 예:
     - counter: `meson test -C <build-dir> 'native request counter'`
     - ExtFUSE INIT: `<build-dir>`에서 `python3 -m pytest libfuse/test/test_extfuse.py`
     - example: `<build-dir>`에서
       `python3 -m pytest libfuse/test/test_examples.py -k <name>`
  5. public API/protocol 또는 범위가 넓은 변경은 `<build-dir>`에서
     `python3 -m pytest libfuse/test/`
  6. 성능 관련 변경은 마지막에 benchmark
- protocol/UAPI 변경은 대응 Linux tree와
  `cmp libfuse/include/fuse_kernel.h linux/include/uapi/linux/fuse.h`로 wire
  header를 대조하고, 의도한 차이가 남지 않은 상태에서 `<build-dir>`의
  `python3 -m pytest libfuse/test/test_ctests.py -k test_abi`와 ExtFUSE INIT test를
  함께 실행한다.
- benchmark가 명시적으로 요청되면 runner, profile과 결과 관리 방식은 `fuse_exp`의
  지시와 workload/config를 따른다. build나 test 결과를 benchmark 증거로 대신하지
  않는다.
- commit을 제안하기 전에 비특권 lint를 실행한다. 둘 다 `libfuse/.github/workflows/`의
  CI에서 강제된다.
  - kernel style: 커밋된 각 commit에 대해
    `libfuse/checkpatch.pl --max-line-length=100 --no-tree -g <commit>` (CI와
    동일한 `--ignore` 목록은 `libfuse/.github/workflows/checkpatch.yml` 참고)
  - spelling: `libfuse`에서 `codespell` (`libfuse/.codespellrc`를 자동으로 사용).
    로컬에 없으면 설치 여부를 보고하고 건너뛴다.
- 전체 `meson test`/`ninja test`의 `wrong_command`는 pytest 사용법을 알리는
  의도적 실패 target이므로 실제 회귀와 구분한다.
- broad pytest에 mount test가 포함되는지 먼저 확인한다. mount/runtime이 요청되지
  않았으면 non-mount test만 실행하고 제외한 단계를 보고한다.
- 명시적으로 요청된 일반 사용자 FUSE mount/unmount는 새로 만든 빈 전용
  mountpoint에서만 수행한다. 기존 mount를 임의로 unmount하지 않는다.
- sudo/root, system-wide install, kernel/module 변경과 reboot는 별도 허가가
  필요하다. 실제 수행한 검증만 성공했다고 보고한다.

## 완료 보고

- 자동으로 stage, commit 또는 push하지 않는다.
- 마지막에 변경 파일, 주요 변경과 수행한 검증을 한국어로 간단히 보고한다.
- commit/push가 필요하면 실행하지 말고 관련 파일만 지정한 `git add` 명령,
  간결한 영어 commit subject, 한국어 상세 description과 push 대상·명령을
  추천한다.
