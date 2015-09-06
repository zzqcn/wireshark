#
# - Find kerberos
# Find the native KERBEROS includes and library
#
#  KERBEROS_INCLUDE_DIRS - where to find krb5.h, etc.
#  KERBEROS_LIBRARIES    - List of libraries when using krb5.
#  KERBEROS_FOUND        - True if krb5 found.


IF (KERBEROS_INCLUDE_DIRS)
  # Already in cache, be silent
  SET(KERBEROS_FIND_QUIETLY TRUE)
ENDIF (KERBEROS_INCLUDE_DIRS)

INCLUDE(FindWSWinLibs)
FindWSWinLibs("kfw-.*" "KERBOROS_HINTS")

find_package(PkgConfig)
pkg_search_module(KERBEROS krb5)

FIND_PATH(KERBEROS_INCLUDE_DIR krb5.h
  HINTS
    "${KERBEROS_INCLUDEDIR}"
    "${KERBOROS_HINTS}/include"
)

SET(KERBEROS_NAMES krb5 krb5_32)
FIND_LIBRARY(KERBEROS_LIBRARY NAMES ${KERBEROS_NAMES}
  HINTS
    "${KERBEROS_LIBDIR}"
    "${KERBOROS_HINTS}/lib"
)

# handle the QUIETLY and REQUIRED arguments and set KERBEROS_FOUND to TRUE if 
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(KERBEROS DEFAULT_MSG KERBEROS_LIBRARY KERBEROS_INCLUDE_DIR)

# todo
# add all kerberos libs
# autodetect HAVE_HEIMDAL_KERBEROS
# autodetect HAVE_MIT_KERBEROS (use pkg_search_module(mit-krb5)?)
# autodetect(?) HAVE_KEYTYPE_ARCFOUR_56

IF(KERBEROS_FOUND)
  SET( KERBEROS_LIBRARIES ${KERBEROS_LIBRARY} )
  SET( KERBEROS_INCLUDE_DIRS ${KERBEROS_INCLUDE_DIR} )
ELSE(KERBEROS_FOUND)
  SET( KERBEROS_LIBRARIES )
  SET( KERBEROS_INCLUDE_DIRS )
ENDIF(KERBEROS_FOUND)

MARK_AS_ADVANCED( KERBEROS_LIBRARIES KERBEROS_INCLUDE_DIRS )
