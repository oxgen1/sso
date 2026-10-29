module github.com/oxgen1/sso

go 1.26.10

// The shared library is its own module so statusd and farm depend on it alone,
// and it only gets a new version when the protocol changes.
replace github.com/oxgen1/sso/lib => ./lib

require (
	github.com/fxamacker/cbor/v2 v2.10.0
	github.com/oxgen1/sso/lib v0.0.0-00010101000000-000000000000
)

require github.com/x448/float16 v0.8.4 // indirect
