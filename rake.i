name: Build

on: [push]

jobs:
  build:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macOS-latest]

    steps:
    - uses: actions/checkout@v2
    - name: Build glorytun
      run: |
          git submodule update --init --recursive
          ./sodium.sh
          make
