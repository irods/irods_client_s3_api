target_sources(
  irods_s3_bridge
  PRIVATE
  listobjects.cpp
  getobject.cpp
  putobject.cpp
  deleteobject.cpp
  headobject.cpp copyobject.cpp)
