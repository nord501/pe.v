import os

struct ImageDosHeader {  // DOS .EXE header
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

struct ImageDataDirectory {
	virtual_address  u32
	size             u32
}

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
struct ImageFileHeader {
	machine                  u16
	number_of_sections       u16
	time_date_stamp          u32
	pointer_to_symbol_table  u32
	number_of_symbols        u32
	size_of_optional_header  u16
	characteristics          u16
}

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_optional_header64
struct ImageOptionalHeader64 {
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
	data_directory[16]             ImageDataDirectory
}

struct ImageNtHeader64 {
	signature        u32
	file_header      ImageFileHeader
	optional_header  ImageOptionalHeader64
}

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header
struct ImageSectionHeader {
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

struct ImageImportDescriptor {
pub mut:
	original_first_thunk  u32   /* RVA to original unbound IAT */
	time_date_stamp       u32
	forwarder_chain       u32   /* -1 if no forwarders */
	name                  u32
	first_thunk           u32  /* RVA to IAT (if bound this IAT has actual addresses) */
}

struct ImportTable {
pub mut:
	dll_name    string      // kernel32.dll, msvcrt.dll
	dll_offset  int
	api         map[string]int
	import_desc &ImageImportDescriptor
	thunk_len   int
}

const (
	number_of_sections = 3
)

fn main() {
	dos_header := ImageDosHeader {
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
		0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70,
		0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E,
		0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E, 0x20, 0x69,
		0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E,
		0x0D, 0x0D, 0x0A, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

	optional_header := ImageOptionalHeader64 {
		magic: 0x020B  // PE64
		major_linker_version: 0x06
		size_of_code: 0x400
		size_of_initialized_data: 0x400
		address_of_entry_point: 0x1000 //calculate
		base_of_code: 0x1000
		image_base: 0x0400000
		section_alignment: 0x1000
		file_alignment: 0x200
		major_operating_system_version: 0x04
		minor_operating_system_version: 0
		major_subsystem_version: 0x04
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

	file_header := ImageFileHeader {
		machine: 0x8664                        // x64
		number_of_sections: number_of_sections // .text, .data, .idata
		size_of_optional_header: u16(sizeof(optional_header))
		characteristics: 0x022F // executable, (reloc, line number, symbol, debug) stripped
	}

	// // V doesn't support embedded struct yet
	// nt_header := ImageNtHeader64{
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
	text_header := ImageSectionHeader {
		// name: name
		virtual_size: 0x1000
		virtual_address: 0x1000
		size_of_raw_data: 0x200
		pointer_to_raw_data: 0x200
		characteristics: 0x60000020 // executable, readable, contains code
	}
	C.memcpy(text_header.name, &text[0], 8)

	data := [`.`, `d`, `a`, `t`, `a`, 0, 0, 0]
	data_header := ImageSectionHeader {
		// name: name
		virtual_size: 0x1000
		virtual_address: 0x2000
		size_of_raw_data: 0x200
		pointer_to_raw_data: 0x400
		characteristics: 0xC0000040 // readable, writable, contains initialized data
	}
	C.memcpy(data_header.name, &data[0], 8)

	idata := [`.`, `i`,`d`, `a`, `t`, `a`, 0, 0]
	idata_header := ImageSectionHeader {
		// name: name
		virtual_size: 0x1000
		virtual_address: 0x3000
		size_of_raw_data: 0x100
		pointer_to_raw_data: 0x600
		characteristics: 0xC0000040 // readable, contains initialized data
	}
	C.memcpy(idata_header.name, &idata[0], 8)

	kernel32_desc := ImageImportDescriptor {
		original_first_thunk: 0x0000   /* RVA to original unbound IAT */
		time_date_stamp:      0x0000
		forwarder_chain:      0x0000   /* -1 if no forwarders */
		name:                 0x0000
		first_thunk:          0x0000   /* RVA to IAT (if bound this IAT has actual addresses) */
	}

	msvcrt_desc := ImageImportDescriptor {
		original_first_thunk: 0x0000   /* RVA to original unbound IAT */
		time_date_stamp:      0x0000
		forwarder_chain:      0x0000   /* -1 if no forwarders */
		name:                 0x0000
		first_thunk:          0x0000   /* RVA to IAT (if bound this IAT has actual addresses) */
	}

	null_import := ImageImportDescriptor { }

	mut kernel32 := ImportTable {
		dll_name: "kernel32.dll"
		dll_offset: 0
		api: {'ExitProcess': int(0), 'Sleep': int(0)}
		import_desc: &kernel32_desc
		thunk_len: 0
	}

	mut msvcrt := ImportTable {
		dll_name: "msvcrt.dll"
		dll_offset: 0
		api: {'printf': int(0), 'putchar': int(0)}
		import_desc: &msvcrt_desc
		thunk_len: 0
	}

	import_desc_len := int(sizeof(null_import))
	mut imports := []ImportTable { }
	imports << kernel32
	imports << msvcrt

	mut thunk_names := []byte { len: 128, init: 0}

	mut total_bytes := 0 // calculate thunks table len
	mut total_thunk_len := u32(0)
	mut offset := 0
	for i, imp in imports {
		imports[i].dll_offset = offset
		C.memcpy(&thunk_names[offset], imp.dll_name.str, imp.dll_name.len)
		offset += imp.dll_name.len + 1   // +1 null
		total_bytes += import_desc_len

		for api, _ in imp.api {
			imports[i].api[api] = offset
			offset += 2  // add 2 bytes for null ordinal value
			C.memcpy(&thunk_names[offset], api.str, api.len)
			offset += api.len + 1       // +1 null
			total_bytes += 8	        // sizeof(u64)
			imports[i].thunk_len++
			total_thunk_len++
		}
		total_thunk_len++
		total_bytes += 8 // null terminated
		println('')
	}

	imp_desc_table_len := u32((imports.len * import_desc_len) + import_desc_len)

	total_bytes += import_desc_len // null terminated struct
	println('total_bytes: $total_bytes')
	// println(imports[1].api['printf'])

	for _, b in thunk_names {
		if b == 0 {
			print('_')
		} else {
			print('${b:c}')
		}
	}
	print('\n')

	buf := []byte{ len: 200, init: 0 }
	rva := u32(0x2000)
	offset = 0

	for i, imp in imports {
		mut tlen := 0
		mut hint_offset := u32(0)
		if i > 0 {
			tlen = (imports[i-1].thunk_len + 1 ) * 8
		}
		println('tlen  0x${tlen:08d}')
		first_thunk := imp_desc_table_len + u32(tlen)
		original_first_thunk := imp_desc_table_len + (total_thunk_len * 8) + u32(tlen)
		name := imp_desc_table_len + (total_thunk_len * 8 * 2) + u32(imports[i].dll_offset)

		imports[i].import_desc.first_thunk = rva + first_thunk
		imports[i].import_desc.original_first_thunk = rva + original_first_thunk
		imports[i].import_desc.name = rva + name

		for _, v in imp.api {
			t := u32(v) + imports[0].import_desc.name
			C.memcpy(&buf[hint_offset + first_thunk], &t, 8)
			C.memcpy(&buf[hint_offset + original_first_thunk], &t, 8)
			hint_offset += 8
		}
		C.memcpy(&buf[offset], imp.import_desc, import_desc_len)
		println('$imp.import_desc')
		offset += import_desc_len
	}
	C.memcpy(&buf[offset], &null_import, import_desc_len)
	offset += import_desc_len

	for i, b in buf {
		if (i % 8 == 0) && (i > 0) {
			println('')
		}
		print('0x${b:02x}, ')
	}

	// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory
	// TODO: calculate all address & size
	import_table_dir_size := (imports.len * import_desc_len) + import_desc_len
	import_table_dir := ImageDataDirectory {
		virtual_address: rva
		size: u32(import_table_dir_size)
	}
	C.memcpy(&optional_header.data_directory[1], &import_table_dir, sizeof(import_table_dir))

	import_address_table_size := total_thunk_len * 8
	import_address_table_dir := ImageDataDirectory {
		virtual_address: imports[0].import_desc.first_thunk
		size: u32(import_address_table_size)
	}
	C.memcpy(&optional_header.data_directory[12], &import_address_table_dir, sizeof(import_address_table_dir))
	print('${import_address_table_dir}')

	f.write_bytes(&dos_header, 64)
	f.write_bytes(&dos_stub[0], dos_stub.len)
	f.write_bytes(&pe_signature, 4)
	f.write_bytes(&file_header, int(sizeof(file_header)))
	f.write_bytes(&optional_header, int(sizeof(optional_header)))
	f.write_bytes(&text_header, int(sizeof(text_header)))
	f.write_bytes(&data_header, int(sizeof(data_header)))
	f.write_bytes(&idata_header, int(sizeof(idata_header)))

	zero_buf_200 := []byte{ len: 0x200, init: 0 }
	printf_instr := [byte(0x48), 0x8D,0x05,0xF9,0x1F,0x00,0x00,0x49,0x89,0xC2,0x49,0x89,0xCA,0xFF,0x15,0x41,0x10,0x00,0x00,0xFF,0x15,0x23,0x10,0x00,0x00]

	C.memcpy(&zero_buf_200[0], &printf_instr[0], printf_instr.len)
	f.write_bytes(&zero_buf_200[0], zero_buf_200.len)

	thunk_table_len := (int(imp_desc_table_len + (total_thunk_len * 8 * 2)))
	f.write_bytes(&buf[0], thunk_table_len)
	f.write_bytes(&thunk_names[0], thunk_names.len)

	hello := 'hello world'
	C.memcpy(&zero_buf_200[228], hello.str, hello.len)
	f.write_bytes(&zero_buf_200[0], 488)

	f.close()
}
