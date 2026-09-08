package godvdcss

const DVD_KEY_SIZE = 5

type dvd_key [DVD_KEY_SIZE]uint8

type dvd_title struct {
	i_startlb int
	p_key     dvd_key
	p_next    *dvd_title
}

type css struct {
	i_agid      int
	p_bus_key   dvd_key
	p_disc_key  dvd_key
	p_title_key dvd_key
}
