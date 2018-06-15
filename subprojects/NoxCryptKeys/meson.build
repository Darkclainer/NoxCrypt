project('NoxCryptKeysLib', 'cpp', 
	license: 'GPL3', 
	version: '0.1.0',
	default_options : ['cpp_std=c++11']
)

internal_include = include_directories('src', 'include')
external_include = include_directories('include')

raw_src = ['keys.cpp', 'keysData.cpp']
src = []
foreach file : raw_src
	src += ['src/' + file]
endforeach

NoxCryptKeys_lib = static_library('NoxCryptKeys', 
	sources: src,
	include_directories: internal_include
)

NoxCryptKeys_dep = declare_dependency(
	link_with: NoxCryptKeys_lib,
	include_directories: external_include
)	

