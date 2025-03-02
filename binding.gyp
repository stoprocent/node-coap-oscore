{
  'variables': {
    'openssl_fips' : '' 
  },
  "targets": [
    {
      "target_name": "bindings",
      'defines': [
        'NAPI_CPP_EXCEPTIONS=1',
        'ZCBOR_CANONICAL=1',
        'OSCORE_MAX_PLAINTEXT_LEN=2048',
        'OSCORE_NVM_SUPPORT=1',
        'OSCORE_MAX_URI_PATH_LEN=128',
        'K_SSN_NVM_STORE_INTERVAL=1',
        'MBEDTLS=1',
        'C_I_SIZE=7',
        'C_R_SIZE=7'
      ],
      "sources": [ 
        "<!@(node -p \"require('fs').readdirSync('./external/uoscore-uedhoc/externals/zcbor/src').filter(f=>f.endsWith('.c')).map(f=>'external/uoscore-uedhoc/externals/zcbor/src/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('./external/uoscore-uedhoc/externals/mbedtls/library').filter(f=>f.endsWith('.c')).map(f=>'external/uoscore-uedhoc/externals/mbedtls/library/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('./external/uoscore-uedhoc/src/cbor').filter(f=>!f.startsWith('edhoc')).filter(f=>f.endsWith('.c')).map(f=>'external/uoscore-uedhoc/src/cbor/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('./external/uoscore-uedhoc/src/common').filter(f=>f.endsWith('.c')).map(f=>'external/uoscore-uedhoc/src/common/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('./external/uoscore-uedhoc/src/oscore').filter(f=>f.endsWith('.c')).map(f=>'external/uoscore-uedhoc/src/oscore/'+f).join(' ')\")",
        "<!@(node -p \"require('fs').readdirSync('./src').map(f=>'src/'+f).join(' ')\")"
      ],
      'include_dirs': [
        "<!@(node -p \"require('node-addon-api').include\")",
        "external/uoscore-uedhoc/inc",
        "external/uoscore-uedhoc/inc/cbor",
        "external/uoscore-uedhoc/inc/common",
        "external/uoscore-uedhoc/inc/oscore",
        "external/uoscore-uedhoc/externals/zcbor/include",
        "external/uoscore-uedhoc/externals/mbedtls/include",
        "external/uoscore-uedhoc/externals/mbedtls/library",
        "include"
      ],
      'dependencies': [
        "<!(node -p \"require('node-addon-api').gyp\")"
      ],
      'cflags!': [ '-fno-exceptions', '-std=c99' ],
      'cflags_cc!': [ '-fno-exceptions', '-std=c++20' ],
      'xcode_settings': {
        'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
        'CLANG_CXX_LIBRARY': 'libc++',
        'CLANG_CXX_LANGUAGE_STANDARD': 'c++20',
        'MACOSX_DEPLOYMENT_TARGET': '12'
      },
      'conditions': [
        ['OS=="win"', {
          'defines': [
            '_Static_assert=static_assert'
          ],
          'msvs_settings': {
            'VCCLCompilerTool': {
              'AdditionalOptions': [ '-std:c++20', ],
              'ExceptionHandling': 1
            }
          }
        }, { # OS != "win",
          'defines': [
            'restrict=__restrict'
          ],
        }]
      ],
    }
  ]
}
