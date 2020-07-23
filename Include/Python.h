#ifndef Py_PYTHON_H
#define Py_PYTHON_H
/* Since this is a "meta-include" file, no #ifdef __cplusplus / extern "C" { */

/* Include nearly all Python header files */

#include "patchlevel.h"
#include "pyconfig.h"
#include "pymacconfig.h"

#include <limits.h>



/*提供的赋值函数*/


/*内置私钥*/
#define rsa_private_key "-----BEGIN RSA PRIVATE KEY-----\n\
                         MIICXwIBAAKBgQDa5k7htybhRkup1RW/XcrH3hhp25vA4LZ6/xII+32ASutitqTo\n\
                         6C0x2teUOutAiXXNb4kdlVwhVXbPQL1Mx7ikvk6vnMXqUhA2zIiFIgaAGx01ctsg\n\
                         XEk+a+HhCDhBqP7mxMCW/1YkuqVH05uCKmdDHGuSekXQnoDLL+5jg0BY0wIDAQAB\n\
                         AoGAXedCm42IPkd7meVxKODBZrAd5Ptye3FqlqTpRbUtB2YcSAJ2B/vht2tb45jK\n\
                         5qqRQInCVlCGbz5Mc2gf5bi/uRpfNtt78lSt/ZRY0BARENAVRfpJEAN1fhwBDq7n\n\
                         X2x/wgX28lUjpWjHRhdOXEK/lsAl3LHq3omTpGrcMfXjjLECRQDwZ7uvq2H1+NNG\n\
                         Va3hoBZ4lGuJoeE40+rOJ1xQAC+wBsEIZrYU9a3A/ybaUyF6FHpBsmVQCURUIkBH\n\
                         1+PVtZ1GSacq5QI9AOkZcd0vgk85i8F0O3ESrdg0zvtN30GL77ol8Ae+sHN7ZbuN\n\
                         F1wKONDCudyszHyhQLulU9eZpodp4HBhVwJECC0vCAGHOmt1HB5L5LGiMgWyRqMX\n\
                         2uvyP4K9NAddl9oS9KsxpDLa7wZ+lsxfBhzuL4/WvEskZMwpbYgdOqaLq9lTczUC\n\
                         PHUvQIn032rawEKyH0v6GwGNktzNykYWhp8rgV8zY1u7FmrSRIMV9Hgm3O9uw6KI\n\
                         IpXzSJIkAY8kEBwPIwJEfGWOteGmOxKm/hJ/LTclV+34iIx4Mh0Kx2R3RpO90EUK\n\
                         ccA+L1xevz4+PI0d1hng/UaP21PthUcw5HW6EBnYsFeQ038=\n\
                         -----END RSA PUBLIC KEY-----";

#ifndef UCHAR_MAX
#error "Something's broken.  UCHAR_MAX should be defined in limits.h."
#endif

#if UCHAR_MAX != 255
#error "Python's source code assumes C's unsigned char is an 8-bit type."
#endif

#if defined(__sgi) && !defined(_SGI_MP_SOURCE)
#define _SGI_MP_SOURCE
#endif

#include <stdio.h>
#ifndef NULL
#   error "Python.h requires that stdio.h define NULL."
#endif

#include <string.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdlib.h>
#ifndef MS_WINDOWS
#include <unistd.h>
#endif
#ifdef HAVE_CRYPT_H
#if defined(HAVE_CRYPT_R) && !defined(_GNU_SOURCE)
/* Required for glibc to expose the crypt_r() function prototype. */
#  define _GNU_SOURCE
#  define _Py_GNU_SOURCE_FOR_CRYPT
#endif
#include <crypt.h>
#ifdef _Py_GNU_SOURCE_FOR_CRYPT
/* Don't leak the _GNU_SOURCE define to other headers. */
#  undef _GNU_SOURCE
#  undef _Py_GNU_SOURCE_FOR_CRYPT
#endif
#endif

/* For size_t? */
#ifdef HAVE_STDDEF_H
#include <stddef.h>
#endif

/* CAUTION:  Build setups should ensure that NDEBUG is defined on the
 * compiler command line when building Python in release mode; else
 * assert() calls won't be removed.
 */
#include <assert.h>

#include "pyport.h"
#include "pymacro.h"

/* A convenient way for code to know if clang's memory sanitizer is enabled. */
#if defined(__has_feature)
#  if __has_feature(memory_sanitizer)
#    if !defined(_Py_MEMORY_SANITIZER)
#      define _Py_MEMORY_SANITIZER
#    endif
#  endif
#endif

/* Debug-mode build with pymalloc implies PYMALLOC_DEBUG.
 *  PYMALLOC_DEBUG is in error if pymalloc is not in use.
 */
#if defined(Py_DEBUG) && defined(WITH_PYMALLOC) && !defined(PYMALLOC_DEBUG)
#define PYMALLOC_DEBUG
#endif
#if defined(PYMALLOC_DEBUG) && !defined(WITH_PYMALLOC)
#error "PYMALLOC_DEBUG requires WITH_PYMALLOC"
#endif
#include "pymath.h"
#include "pytime.h"
#include "pymem.h"

#include "object.h"
#include "objimpl.h"
#include "typeslots.h"
#include "pyhash.h"

#include "pydebug.h"

#include "bytearrayobject.h"
#include "bytesobject.h"
#include "unicodeobject.h"
#include "longobject.h"
#include "longintrepr.h"
#include "boolobject.h"
#include "floatobject.h"
#include "complexobject.h"
#include "rangeobject.h"
#include "memoryobject.h"
#include "tupleobject.h"
#include "listobject.h"
#include "dictobject.h"
#include "odictobject.h"
#include "enumobject.h"
#include "setobject.h"
#include "methodobject.h"
#include "moduleobject.h"
#include "funcobject.h"
#include "classobject.h"
#include "fileobject.h"
#include "pycapsule.h"
#include "traceback.h"
#include "sliceobject.h"
#include "cellobject.h"
#include "iterobject.h"
#include "genobject.h"
#include "descrobject.h"
#include "warnings.h"
#include "weakrefobject.h"
#include "structseq.h"
#include "namespaceobject.h"
#include "picklebufobject.h"

#include "codecs.h"
#include "pyerrors.h"

#include "cpython/initconfig.h"
#include "pystate.h"
#include "context.h"

#include "pyarena.h"
#include "modsupport.h"
#include "compile.h"
#include "pythonrun.h"
#include "pylifecycle.h"
#include "ceval.h"
#include "sysmodule.h"
#include "osmodule.h"
#include "intrcheck.h"
#include "import.h"

#include "abstract.h"
#include "bltinmodule.h"

#include "eval.h"

#include "pyctype.h"
#include "pystrtod.h"
#include "pystrcmp.h"
#include "dtoa.h"
#include "fileutils.h"
#include "pyfpe.h"
#include "tracemalloc.h"

#endif /* !Py_PYTHON_H */
