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

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
struct IMAGE_FILE_HEADER {
	machine                  u16
	number_of_sections       u16
	time_date_stamp          u32
	pointer_to_symbol_table  u32
	number_of_symbols        u32
	size_of_optional_header  u16
	characteristics          u16
}

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
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

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
struct IMAGE_SECTION_HEADER {
	name[8]                 byte
	virtual_size            u32
	virtual_address         u32
	size_of_raw_data        u32
	pointer_to_raw_data     u32
	pointer_to_relocations  u32
	pointer_to_linenumbers  u32
	number_of_relocations   u16
	number_of_linenumbers   u16
	characteristics         u32
}

const (
	number_of_sections = 3
)

fn main() {
	dos_header := IMAGE_DOS_HEADER {
		e_magic:  0x5A4D       // MZ
		e_cblp: 0x90
		e_cp: 0x03
		e_cparhdr: 0x04
		e_maxalloc: 0xFFFF
		e_sp: 0xB8
		e_lfarlc: 0x40
		e_lfanew: 0x80         // PE Header address
	}

	dos_stub := [byte(0x0E), 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 
		0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 
		0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 
		0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69, 0x6E, 0x20, 0x44, 
		0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A, 0x24, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

	optional_header := IMAGE_OPTIONAL_HEADER64 {
		magic: 0x020B  // PE64
		major_linker_version: 0x06
		size_of_code: 0x1000
		size_of_initialized_data: 0x400
		address_of_entry_point: 0x1234 //calculate
		base_of_code: 0x1000
		image_base: 0x0400000
		section_alignment: 0x1000
		file_alignment: 0x200
		major_operating_system_version: 0x06
		minor_operating_system_version: 0x01 // Windows 7 = 6.1
		major_subsystem_version: 0x06
		size_of_image: 0x4000
		size_of_headers: 0x200
		check_sum: 0x0000 // calculate
		subsystem: 0x003  // console
		dll_characteristics: 0x0000 // this is an EXE file
		size_of_stack_reserve: 0x100000
		size_of_stack_commit: 0x1000
		size_of_heap_reserve: 0x100000
		size_of_heap_commit: 0x1000
		number_of_rva_and_sizes: 0x10
	}

	file_header := IMAGE_FILE_HEADER {
		machine: 0x8664                        // x64
		number_of_sections: number_of_sections // .text, .data, .idata
		size_of_optional_header: u16(sizeof(optional_header))
		characteristics: 0x022F // executable, (reloc, line number, symbol, debug) stripped
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
	
	// code section
	text := [`.`, `t`, `e`, `x`, `t`, 0, 0, 0]

	text_header := IMAGE_SECTION_HEADER {
		// name: name
		virtual_size: 0x1000
		virtual_address: 0x1000
		size_of_raw_data: 0x200
		pointer_to_raw_data: 0x200
		characteristics: 0x60000020 // executable, readable, contains code
	}
	C.memcpy(text_header.name, &text[0], 8)

	data := [`.`, `d`, `a`, `t`, `a`, 0, 0, 0]

	data_header := IMAGE_SECTION_HEADER {
		// name: name
		virtual_size: 0x1000
		virtual_address: 0x2000
		size_of_raw_data: 0x200
		pointer_to_raw_data: 0x400
		characteristics: 0xC0000040 // readable, writable, contains initialized data
	}
	C.memcpy(data_header.name, &data[0], 8)

	idata := [`.`, `i`,`d`, `a`, `t`, `a`, 0, 0]

	idata_header := IMAGE_SECTION_HEADER {
		// name: name
		virtual_size: 0x1000
		virtual_address: 0x3000
		size_of_raw_data: 0x200
		pointer_to_raw_data: 0x600
		characteristics: 0xC0000040 // readable, contains initialized data
	}
	C.memcpy(idata_header.name, &idata[0], 8)

	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
	// TODO: calculate all address & size
	import_table_dir_size := 0x3c  
	import_table_dir := IMAGE_DATA_DIRECTORY {
		virtual_address: 0x1234
		size: u32(import_table_dir_size)
	}
	C.memcpy(&optional_header.data_directory[1], &import_table_dir, sizeof(import_table_dir))

	import_address_table_size := 0x60  
	import_address_table_dir := IMAGE_DATA_DIRECTORY {
		virtual_address: 0x1234
		size: u32(import_address_table_size)
	}
	C.memcpy(&optional_header.data_directory[12], &import_address_table_dir, sizeof(import_address_table_dir))

	// zero_buf := []int{ len: 64, init: 0 }
	
	f.write_bytes(&dos_header, 64)
	f.write_bytes(&dos_stub[0], dos_stub.len)
	f.write_bytes(&pe_signature, 4)
	f.write_bytes(&file_header, int(sizeof(file_header)))
	f.write_bytes(&optional_header, int(sizeof(optional_header)))
	f.write_bytes(&text_header, int(sizeof(text_header)))
	f.write_bytes(&data_header, int(sizeof(data_header)))
	f.write_bytes(&idata_header, int(sizeof(idata_header)))

	zero_buf_200 := []int{ len: 0x200, init: 0 }
	f.write_bytes(&zero_buf_200[0], zero_buf_200.len)
	// f.write_bytes(&zero_buf_200[0], zero_buf_200.len)
	// f.write_bytes(&zero_buf_200[0], zero_buf_200.len)

	println(int(sizeof(optional_header)))

	f.close()
}
