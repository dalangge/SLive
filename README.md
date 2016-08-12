# SLive
Smart Live Server

...........................
  follow me, step by step
...........................

step 1 , build LuaJIT  (optional）
$cd src/common-libs/LuaJIT-2.0.4
$make
$make install

add luajit to library path
$vi .bash_profile
$export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib

step 2 , build lua-cjson (optional)
$cd src/common-libs/lua-cjson-2.1.0
$vi Makefile
$LUA_INCLUDE_DIR =   ../LuaJIT-2.0.4/src
$cp cjson.so /usr/local/lib/lua/5.1

step 3 , build nginx
$./configure \
--with-openssl=../../common-libs/openssl-1.0.2h \
--with-pcre=../../common-libs/pcre-8.38 \
--with-zlib=../../common-libs/zlib-1.2.8 \
--add-module=../../modules/lua-nginx-module-0.10.5 \
--add-module=../../modules/nginx-rtmp-module-1.1.7
$make
$make install

