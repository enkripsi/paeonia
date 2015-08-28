{
  "targets": [
    {
      "target_name": "paeonia",
      "sources": [
        "addon.cc",
        "sync.cc"
      ],
      "include_dirs": ["<!(node -e \"require('nan')\")"]
    }
  ]
}
