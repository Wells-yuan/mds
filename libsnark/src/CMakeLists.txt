include_directories(
  .
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
  ${DEPENDS_DIR}/libsnark/depends/libff
)

################
# 生成链接库
################
#shared library
add_library(
  zk_produce
  SHARED
  #STATIC
  produce/producecgo.cpp
)

add_library(
  zk_update
  SHARED
  update/updatecgo.cpp
)

add_library(
  zk_share
  SHARED
  share/sharecgo.cpp
)

add_library(
  zk_access
  SHARED
  access/accesscgo.cpp
)

###############################
# 生成各个gadget的所需的pk，vk
###############################
add_executable(
  produce_key

  produce/getpvk.cpp
)

target_link_libraries(
  produce_key

  snark
)

target_include_directories(
  produce_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  share_key

  share/getpvk.cpp
)

target_link_libraries(
  share_key

  snark
)

target_include_directories(
  share_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  access_key

  access/getpvk.cpp
)

target_link_libraries(
  access_key

  snark
)

target_include_directories(
  access_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  update_key

  update/getpvk.cpp
)

target_link_libraries(
  update_key

  snark
)

target_include_directories(
  update_key

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

##########################################
# test setup, genProof and verProof
#########################################
add_executable(
  produce

  produce/main.cpp
)

target_link_libraries(
  produce

  snark
)

target_include_directories(
  produce

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  share

  share/main.cpp
)

target_link_libraries(
  share

  snark
)

target_include_directories(
  share

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  access

  access/main.cpp
)

target_link_libraries(
  access

  snark
)

target_include_directories(
  access

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)
#########################
add_executable(
  update

  update/main.cpp
)

target_link_libraries(
  update

  snark
)

target_include_directories(
  update

  PUBLIC
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libfqfft
)

