{
  "targets": [
    {
      "target_name": "paeonia",
      "cflags": [
        '<!@(pkg-config --cflags botan-1.11)',
        '-std=c++11'],
      'cflags!': [ '-fno-exceptions', '-fno-rtti' ],
      'cflags_cc!': [ '-fno-exceptions', '-fno-rtti' ],
      "sources": [
        "addon.cc",
        "sync.cc",
        "pk.cc"
      ],
      "include_dirs": [
        "<!(node -e \"require('nan')\")"
      ],
      "link_settings": {
        "libraries": [
          '<!@(pkg-config --libs botan-1.11)',
        ],
      },
    },
  ],
}
