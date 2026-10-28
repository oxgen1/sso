module github.com/oxgen1/sso

go 1.26.10

// The shared library is its own module so statusd and mvm depend on it alone,
// and it only gets a new version when the protocol changes.
replace github.com/oxgen1/sso/lib => ./lib
