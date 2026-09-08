package godvdcss

type Dvdcss_s struct {
	psz_device string
	i_fd       uintptr
	i_pos      int64

	i_method    dvdcss_method
	css         *css
	b_ioctls    bool
	b_scrambled bool
	p_titles    *dvd_title

	psz_error string

	log Logger
}

type dvdcss_method int

const (
	DVDCSS_METHOD_KEY = dvdcss_method(iota)
	DVDCSS_METHOD_DISC
	DVDCSS_METHOD_TITLE
)
