# metrovian project
project(
  'signature-generator',
  'cpp', 
  'c',
  version: '1.0.0',
  default_options: [
    'cpp_std=c++20',
    'c_std=c99',
    'warning_level=2',
    'buildtype=release'])

# include
inc = include_directories('include')

# source
src = files(
  'source/abstract.cpp',
  'source/command.cpp',
  'source/ecdsa.cpp',
  'source/rsa.cpp',
  'source/main.cpp')

# dependency
dep_gmp = dependency('gmp', required: true)
dep_openssl = dependency('openssl', required: true)
dep_spdlog = dependency('spdlog', required: true)
dep = [
  dep_gmp,
  dep_openssl,
  dep_spdlog]

executable(
  'signature-generator',
  src,
  include_directories: inc,
  dependencies: [dep])