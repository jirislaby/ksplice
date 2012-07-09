struct table_section {
	const char *sect;
	int entry_size;
	int entry_contents_size;
	int entry_align;
	int has_addr;
	int relative_addr;
	int addr_offset;
	const char *other_sect;
	int relative_other;
	int other_offset;
	const char *crc_sect;
	int crc_size;
};

struct ksplice_config {
	int ignore_devinit;
	int ignore_cpuinit;
	int ignore_meminit;
};
