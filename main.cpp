#include <Windows.h>
#include <stdio.h>
#include <conio.h>

#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew))
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

int main(int argc, char *argv[])
{
	char chStr[38] = "c:\\Games\\PES 2011\\pes2011.exe";
	long w;
	HANDLE hfPat = CreateFile(CharToWchar(chStr), 0xC0000000, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hfPat == INVALID_HANDLE_VALUE) {printf("Open file error!"); CloseHandle(hfPat); return 0; }
	w = SetFilePointer(hfPat, 0,0,FILE_END);
	//printf("\nsize virus = %ld",w);
	HANDLE hMap = CreateFileMapping(hfPat, NULL, PAGE_READWRITE, 0, w, NULL);
	if(hMap==NULL) {printf("error - hMap"); CloseHandle(hfPat); return 0; }
	BYTE* hMapAddress = (BYTE*) MapViewOfFile(hMap, 0x02, 0, 0, w);
	if(!hMapAddress) {printf("error - hMapAddress");return 0;}

	BYTE* hPE = (BYTE*)NTSIGNATURE(hMapAddress);

	if(*((DWORD*)(hPE)) == IMAGE_NT_SIGNATURE) printf("\nsucces");
	else printf("\nerror PE");

	//*(DWORD*)(hPE + 0x54) = 0x600;
	DWORD AEP_PAT = *((DWORD*)(hPE + 0x28)), FA = *((DWORD*)(hPE + 0x3C));
	//printf("\nsize headers = %x\n", GETSIZEOFHEADERS(hPE));
	printf("\nAddress of entery point = %x\nSize base = %x\nSize of code = %x", *((DWORD*)(hPE + 0x28)),*((DWORD*)(hPE + 0x50)),*((DWORD*)(hPE + 0x1c)));
	
	//find last section


	
	UnmapViewOfFile(hMapAddress);
	CloseHandle(hfPat);
	if (!FindFiles()) return 0;
	getch();
	return 1;	

}

wchar_t* CharToWchar(char *temp)
{
	int len = strlen(temp) + 1;
	wchar_t *wStr = new wchar_t[len];
	::MultiByteToWideChar(CP_ACP,NULL,temp,-1,wStr,len);
	return wStr;
}

char* WcharToChar(wchar_t *temp)
{
	int len = 0;
	while(temp[len])
		len++;
	char *Str = new char[len+1];
	::WideCharToMultiByte(1251,NULL,temp,-1,Str,len,NULL,NULL);
	Str[len] = '\0';
	return Str;
}

bool FindFiles()
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
    wchar_t DirSpec[MAX_PATH];  // directory specification
    DWORD dwError;
	DWORD BufSize = MAX_PATH;
    //path[strlen(path)-10] = '\0';
	GetCurrentDirectory(BufSize, DirSpec);
    printf ("\nTarget directory is %s\n", WcharToChar(DirSpec));
    //strncpy (DirSpec, path, strlen(path)+1);
    wcscat(DirSpec, CharToWchar("\\*.EXE"));

    hFind = FindFirstFile(DirSpec, &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE) 
    {
       printf ("Invalid file handle. Error is %u\n", GetLastError());
       return false;
    } 
    else 
    {
		printf ("First file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
       while (FindNextFile(hFind, &FindFileData) != 0) 
       {
          printf ("Next file name is %s\nFile size = %x\n", WcharToChar(FindFileData.cFileName), FindFileData.nFileSizeLow);
       }
    
       dwError = GetLastError();
       FindClose(hFind);
       if (dwError != ERROR_NO_MORE_FILES) 
       {
          printf ("FindNextFile error. Error is %u\n", dwError);
          return false;
       }
    }
    return true;
}