module github.com/nucleoledger/nucleo

go 1.27.1

// El Go con el que se compila, se prueba y se publica: los workflows lo leen de aquí
// (go-version-file) y en local GOTOOLCHAIN=auto cambia a él. Subirlo es una decisión, con
// su commit: docs/RELEASING.md, «La versión de Go».
toolchain go1.27.2

require (
	github.com/shurlinet/go-slip39 v0.1.0
	golang.org/x/crypto v0.59.0
	golang.org/x/mod v0.43.0
	golang.org/x/term v0.48.0
	modernc.org/sqlite v1.62.0
)

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.50.0 // indirect
	modernc.org/libc v1.80.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
)
