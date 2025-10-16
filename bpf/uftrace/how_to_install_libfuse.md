# passthrough_hp 설치 방법

rm -rf build
meson setup build -Dexamples=true -Dbuildtype=debugoptimized \
  -Dc_args='-fno-omit-frame-pointer' \
  -Dcpp_args='-fno-omit-frame-pointer' \
  -Db_lto=false
ninja -C build



