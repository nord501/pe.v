import os

struct IMAGE_DOS_HEADER {  // DOS .EXE header
	e_magic      u16   // Magic number
	e_cblp       u16   // bytes on last page of file
	e_cp         u16   // Pages in file
	e_crlc       u16   // Relocations
	e_cparhdr    u16   // Size of header in paragraphs
	e_minalloc   u16   // Minimum extra paragraphs needed
	e_maxalloc   u16   // Maximum extra paragraphs needed
	e_ss         u16   // Initial (relative) SS value
	e_sp         u16   // Initial SP value
	e_csum       u16   // Checksum
	e_ip         u16   // Initial IP value
	e_cs         u16   // Initial (relative) CS value
	e_lfarlc     u16   // File address of relocation table
	e_ovno       u16   // Overlay number
	e_res[4]     u16   // Reserved words
	e_oemid      u16   // OEM identifier (for e_oeminfo)
	e_oeminfo    u16   // OEM information e_oemid specific
	e_res2[10]   u16   // Reserved words
	e_lfanew     u32   // File address of new exe header
}

struct IMAGE_DATA_DIRECTORY {
	virtual_address  u32
	size             u32
}

struct IMAGE_FILE_HEADER {
	machine                  u16
	number_of_sections	     u16
	time_date_stamp		     u32
	pointer_to_symbol_table  u32
	number_of_symbols        u32
	size_of_optional_header  u16
	characteristics          u16
}

struct IMAGE_OPTIONAL_HEADER64 {
	magic                          u16
	major_linker_version           byte
	minor_linker_version           byte
	size_of_code                   u32
	size_of_initialized_data       u32
	size_of_uninitialized_data     u32
	address_of_entry_point         u32
	base_of_code                   u32
	image_base                     u64
	section_alignment              u32
	file_alignment                 u32
	major_operating_system_version u16
	minor_operating_system_version u16
	major_image_version            u16
	minor_image_version            u16
	major_subsystem_version        u16
	minor_subsystem_version        u16
	win32_version_value            u32
	size_of_image                  u32
	size_of_headers                u32
	check_sum                      u32
	subsystem                      u16
	dll_characteristics            u16
	size_of_stack_reserve          u64
	size_of_stack_commit           u64
	size_of_heap_reserve           u64
	size_of_heap_commit            u64
	loader_flags                   u32
	number_of_rva_and_sizes        u32
	data_directory[16]             IMAGE_DATA_DIRECTORY
}

struct IMAGE_NT_HEADERS64 {
	signature        u32
	file_header      IMAGE_FILE_HEADER
	optional_header  IMAGE_OPTIONAL_HEADER64
} 

fn main() {
	dos_header := IMAGE_DOS_HEADER {
		e_magic:  0x5A4D       // MZ
		e_lfanew: 0x80         // Pointer to PE Header
	}

	optional_header := IMAGE_OPTIONAL_HEADER64 {
		size_of_code: 1
	}

	// op_len := sizeof(optional_header)
	file_header := IMAGE_FILE_HEADER {
		machine: 0x8664        // x64
		number_of_sections: 1  // one for now
		size_of_optional_header: u16(sizeof(optional_header))
	}

	// // V doesn't support embedded struct yet
	// nt_header := IMAGE_NT_HEADERS64{
	// 	signature: 0x00004550  // PE00
	// 	file_header: file_header
	// 	optional_header: optional_header
	// }

	pe_signature :=  0x00004550  // PE00

	mut f := os.create("a.exe") or {
		panic(err)
	}
	
	zero_buf := []int{ len: 64, init: 0 }
	
	f.write_bytes(&dos_header, 64)
	f.write_bytes(zero_buf, zero_buf.len)
	f.write_bytes(&pe_signature, 4)
	f.write_bytes(&file_header, int(sizeof(file_header)))
	f.write_bytes(&optional_header, int(sizeof(optional_header)))
	f.close()
}
