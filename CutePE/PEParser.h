#pragma once

#include <iostream>
#include <vector>
#include <phnt_windows.h>
#include <phnt.h>

enum ResultCode
{
	SUCCESS = 0x0,
	INVALID_DOS_HEADER = 0x1,
	INVALID_NT_HEADER = 0x2,
	READFILE_ERROR = 0x3
};

class PEParser
{
public:	
	PIMAGE_DOS_HEADER pe_dos_header;
	PIMAGE_NT_HEADERS pe_nt_headers;
	PIMAGE_SECTION_HEADER pe_section_headers;
	PIMAGE_IMPORT_DESCRIPTOR pe_imports;

	PEParser();

	ResultCode from_bytes(char* bytes);
	ResultCode from_disk(char* path);

protected:
	char* raw_pe_data;

	ResultCode parse();
};