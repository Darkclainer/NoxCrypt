project('NoxCryptUnpacker', 'cpp', 
	license: 'GPL3', 
	version: '0.1.0',
	default_options : ['cpp_std=c++17']
)

NoxCryptKeys_dep = dependency('NoxCryptKeys', 
	fallback: ['NoxCryptKeys', 'NoxCryptKeys_dep']
)

internal_include = include_directories('src')

raw_src = ['main.cpp', 'unpackerOptions.cpp']
src = []
foreach file : raw_src
	src += ['src/' + file]
endforeach

NoxCryptUnpacker_exe = executable('NoxCryptUnpacker', 
	sources: src,
	include_directories: internal_include,
	dependencies: NoxCryptKeys_dep
)


