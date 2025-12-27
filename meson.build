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
inc = include_directories('.')

# source
src = files(
  'core/abstract.cpp',
  'core/ecdsa.cpp',
  'core/rsa.cpp',
  'core/predefined.cpp',
  'command/abstract.cpp',
  'command/ecdsa.cpp',
  'command/rsa.cpp',
  'command/main.cpp')

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