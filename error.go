package godvdcss

import "fmt"

type Logger interface {
	Debug(string, ...any)
	Error(string, ...any)
}

// ported function -- to replace with idiomatic function in the future
func (dvdcss *Dvdcss_s) print_error(f string, args ...any) {
	dvdcss.psz_error = fmt.Sprintf(f, args...)
	dvdcss.log.Error(dvdcss.psz_error)
}

// ported function -- to replace with idiomatic function in the future
func (dvdcss *Dvdcss_s) print_debug(f string, args ...any) {
	dvdcss.log.Debug(fmt.Sprintf(f, args...))
}
