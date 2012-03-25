#include <windows.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <fstream>
#include "define.h"

/*  Declare Windows procedure  */
LRESULT CALLBACK WindowProcedure (HWND, UINT, WPARAM, LPARAM);
void AddLogLine(char *line);
void Editor();
DWORD RvaToOffset(IMAGE_NT_HEADERS *NT, DWORD Rva);
DWORD CalcAlignment(DWORD Alignment, DWORD TrueSize);
/* GLOBAL VAR DECLARATIONS */
   HANDLE hFile;
   BYTE *BaseAddress, *ImageBase;
   WORD x,*NameOrds,nSection;
   UINT y;
   DWORD FileSize, BR, IT_Offset, ET_Offset,BRW, NameSize, Size;
   std::string log;
   // structure pointers
   IMAGE_DOS_HEADER *ImageDosHeader; 
   IMAGE_NT_HEADERS *ImageNtHeaders;
   IMAGE_SECTION_HEADER *ImageSectionHeader;
   _IMAGE_OPTIONAL_HEADER *ImageOptionalHeader;
   IMAGE_IMPORT_DESCRIPTOR *ImageImportDescr;
   IMAGE_EXPORT_DIRECTORY *ImageExportDir;
   DWORD *Thunks,*Functions,*Names;
   IMAGE_IMPORT_BY_NAME *ImgName;
   FILE *f;
   char FileName[MAX_PATH],FileName1[MAX_PATH],Sect_Name[MAX_PATH];
   char SectionName[9] = { 0 };
   char *strings1;
   char *Name,*FName;
   HWND hwnd;

/*  Make the class name into a global variable  */
char szClassName[ ] = "WindowsApp";
HWND   hBtn1,hBtn2,hEdit1,hEdit2,hLabel1,hLabel2,hLabel3,hLabel4,hLabel5,hLabel6,hLabel?7,hLabel8,hLabel9,hLabel10,hBtn5,hBtn6;
HWND   hLabel11,hLabel12,hLabel13,hLabel14,hBtn3,hLabel15,hLabel16,hLabel17,hEdit3,hLab?el18,hEdit4,hLabel19,hLabel20,hBtn4,hEdit5,hEdit6,hLabel21,hLabel22,hLabel23,hEd?it7;
int WINAPI WinMain (HINSTANCE hThisInstance,
                    HINSTANCE hPrevInstance,
                    LPSTR lpszArgument,
                    int nFunsterStil)
 
{
    hwnd;               /* This is the handle for our window */
    MSG messages;            /* Here messages to the application are saved */
    WNDCLASSEX wincl;        /* Data structure for the windowclass */
 
    /* The Window structure */
    wincl.hInstance = hThisInstance;
    wincl.lpszClassName = szClassName;
    wincl.lpfnWndProc = WindowProcedure;      /* This function is called by windows */
    wincl.style = CS_DBLCLKS;                 /* Catch double-clicks */
    wincl.cbSize = sizeof (WNDCLASSEX);
 
    /* Use default icon and mouse-pointer */
    wincl.hIcon = LoadIcon (NULL, IDI_APPLICATION);
    wincl.hIconSm = LoadIcon (NULL, IDI_APPLICATION);
    wincl.hCursor = LoadCursor (NULL, IDC_ARROW);
    wincl.lpszMenuName = NULL;                 /* No menu */
    wincl.cbClsExtra = 0;                      /* No extra bytes after the window class */
    wincl.cbWndExtra = 0;                      /* structure or the window instance */
    /* Use Windows's default color as the background of the window */
    wincl.hbrBackground = (HBRUSH) COLOR_APPWORKSPACE+1;
 
    /* Register the window class, and if it fails quit the program */
    if (!RegisterClassEx (&wincl))
        return 0;
 
    /* The class is registered, let's create the program*/
    hwnd = CreateWindowEx (
           0,                   /* Extended possibilites for variation */
           szClassName,         /* Classname */
           "[UG] ZPE -PE Reader-",           /* Title Text */
           WS_EX_DLGMODALFRAME, /* default window */
           0,       /* Windows decides the position */
           0,       /* where the window ends up on the screen */
           560,                 /* The programs width */
           700,                 /* and height in pixels */
           HWND_DESKTOP,        /* The window is a child-window to desktop */
           NULL,                /* No menu */
           hThisInstance,       /* Program Instance handler */
           NULL                 /* No Window Creation data */
           );
DWORD Style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL| ES_AUTOHSCROLL | ES_AUTOVSCROLL | ES_LEFT | ES_MULTILINE;
 
hLabel1 = CreateWindowExW(0,L"STATIC",L"Select File:",WS_VISIBLE|WS_CHILD,13,25,80,20,hwnd,(HMENU)LABEL1,GetModuleHandle(NULL),NULL);
hEdit1 = CreateWindowExW(0,L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_CENTER,90,23,350,20,hwnd,(HMENU)EDIT1,GetModuleHandle(NULL),NULL);
hBtn1 = CreateWindowExW(0,L"BUTTON",L"Open",WS_TABSTOP|WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON,450,5,65,22,hwnd,(HMENU)BUTTON1,GetModuleHandle(NULL),NULL);   
hBtn2 = CreateWindowExW(0,L"BUTTON",L"Analyze",WS_TABSTOP|WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON,450,35,65,22,hwnd,(HMENU)BUTTON2,GetModuleHandle(NULL),NULL);   
hLabel2 = CreateWindowExW(0,L"STATIC",L"___________________________________________________________________________?_______________________________________________",WS_VISIBLE|WS_CHILD,8,59,520,20,hwnd,(HMENU)LABEL2,GetModuleHandle(NULL),NULL); 
hEdit2 = CreateWindowExW(0,L"EDIT",L"",Style,13,100,250,240,hwnd,(HMENU)EDIT2,GetModuleHandle(NULL),NULL);
hLabel3 = CreateWindowExW(0,L"STATIC",L"Section Headers:",WS_VISIBLE|WS_CHILD,13,80,500,20,hwnd,(HMENU)LABEL3,GetModuleHandle(NULL),NULL); 
hLabel4 = CreateWindowExW(0,L"STATIC",L"Useful Informations:",WS_VISIBLE|WS_CHILD,280,80,500,20,hwnd,(HMENU)LABEL4,GetModuleHandle(NULL),NULL); 
hLabel5 = CreateWindowExW(0,L"STATIC",L"ImageBase: ",WS_VISIBLE|WS_CHILD,280,100,500,20,hwnd,(HMENU)LABEL5,GetModuleHandle(NULL),NULL); 
hLabel6 = CreateWindowExW(0,L"STATIC",L"AddressOfEntryPoint: ",WS_VISIBLE|WS_CHILD,280,120,500,20,hwnd,(HMENU)LABEL6,GetModuleHandle(NULL),NULL); 
hLabel7 = CreateWindowExW(0,L"STATIC",L"BaseOfCode: ",WS_VISIBLE|WS_CHILD,280,140,500,20,hwnd,(HMENU)LABEL7,GetModuleHandle(NULL),NULL); 
hLabel8 = CreateWindowExW(0,L"STATIC",L"BaseOfData: ",WS_VISIBLE|WS_CHILD,280,160,500,20,hwnd,(HMENU)LABEL8,GetModuleHandle(NULL),NULL); 
hLabel9 = CreateWindowExW(0,L"STATIC",L"SectionAlignment: ",WS_VISIBLE|WS_CHILD,280,180,500,20,hwnd,(HMENU)LABEL9,GetModuleHandle(NULL),NULL); 
hLabel10 = CreateWindowExW(0,L"STATIC",L"FileAlignment: ",WS_VISIBLE|WS_CHILD,280,200,500,20,hwnd,(HMENU)LABEL10,GetModuleHandle(NULL),NULL); 
hLabel11 = CreateWindowExW(0,L"STATIC",L"Subsystem: ",WS_VISIBLE|WS_CHILD,280,220,500,20,hwnd,(HMENU)LABEL11,GetModuleHandle(NULL),NULL); 
hLabel12 = CreateWindowExW(0,L"STATIC",L"SizeOfCode: ",WS_VISIBLE|WS_CHILD,280,240,500,20,hwnd,(HMENU)LABEL12,GetModuleHandle(NULL),NULL); 
hLabel13 = CreateWindowExW(0,L"STATIC",L"SizeOfInitializedData: ",WS_VISIBLE|WS_CHILD,280,260,500,20,hwnd,(HMENU)LABEL13,GetModuleHandle(NULL),NULL); 
hLabel14 = CreateWindowExW(0,L"STATIC",L"SizeOfUnitializedData: ",WS_VISIBLE|WS_CHILD,280,280,500,20,hwnd,(HMENU)LABEL14,GetModuleHandle(NULL),NULL); 
hLabel15 = CreateWindowExW(0,L"STATIC",L"EMagic Signature: ",WS_VISIBLE|WS_CHILD,280,300,500,20,hwnd,(HMENU)LABEL15,GetModuleHandle(NULL),NULL); 
hLabel16 = CreateWindowExW(0,L"STATIC",L"PE Signature: ",WS_VISIBLE|WS_CHILD,280,320,500,20,hwnd,(HMENU)LABEL16,GetModuleHandle(NULL),NULL); 
hLabel17 = CreateWindowExW(0,L"STATIC",L"Import Table: ",WS_VISIBLE|WS_CHILD,13,340,500,20,hwnd,(HMENU)LABEL17,GetModuleHandle(NULL),NULL); 
hEdit3 = CreateWindowExW(0,L"EDIT",L"",Style,13,355,515,100,hwnd,(HMENU)EDIT3,GetModuleHandle(NULL),NULL);
hLabel18 = CreateWindowExW(0,L"STATIC",L"Export Table: ",WS_VISIBLE|WS_CHILD,13,455,500,20,hwnd,(HMENU)LABEL18,GetModuleHandle(NULL),NULL); 
hEdit4 = CreateWindowExW(0,L"EDIT",L"",Style,13,470,515,100,hwnd,(HMENU)EDIT4,GetModuleHandle(NULL),NULL);
hLabel19 = CreateWindowExW(0,L"STATIC",L"___________________________________________________________________________?_______________________________________________",WS_VISIBLE|WS_CHILD,8,570,520,20,hwnd,(HMENU)LABEL19,GetModuleHandle(NULL),NULL); 
hLabel20 = CreateWindowExW(0,L"STATIC",L"Section Adder:",WS_VISIBLE|WS_CHILD,13,590,520,20,hwnd,(HMENU)LABEL20,GetModuleHandle(NULL),NULL); 
hLabel21 = CreateWindowExW(0,L"STATIC",L"Name for the new section:",WS_VISIBLE|WS_CHILD,13,610,520,20,hwnd,(HMENU)LABEL21,GetModuleHandle(NULL),NULL); 
hEdit5 = CreateWindowExW(0,L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_CENTER,190,608,80,20,hwnd,(HMENU)EDIT5,GetModuleHandle(NULL),NULL);
hLabel22 = CreateWindowExW(0,L"STATIC",L"Size:",WS_VISIBLE|WS_CHILD,285,610,520,20,hwnd,(HMENU)LABEL22,GetModuleHandle(NULL),NULL); 
hEdit6 = CreateWindowExW(0,L"EDIT",L"",WS_VISIBLE|WS_CHILD|WS_BORDER|ES_CENTER,325,608,80,20,hwnd,(HMENU)EDIT6,GetModuleHandle(NULL),NULL);
hBtn4 = CreateWindowExW(0,L"BUTTON",L"Add",WS_TABSTOP|WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON,420,607,65,22,hwnd,(HMENU)BUTTON4,GetModuleHandle(NULL),NULL);   
hLabel23 = CreateWindowExW(0,L"STATIC",L"___________________________________________________________________________?_______________________________________________",WS_VISIBLE|WS_CHILD,8,628,520,20,hwnd,(HMENU)LABEL23,GetModuleHandle(NULL),NULL); 
hBtn3 = CreateWindowExW(0,L"BUTTON",L"Exit",WS_TABSTOP|WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON,465,650,65,22,hwnd,(HMENU)BUTTON3,GetModuleHandle(NULL),NULL);   
hBtn5 = CreateWindowExW(0,L"BUTTON",L"Info",WS_TABSTOP|WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON,295,650,65,22,hwnd,(HMENU)BUTTON5,GetModuleHandle(NULL),NULL);   
hBtn6 = CreateWindowExW(0,L"BUTTON",L"Visit Us!",WS_TABSTOP|WS_VISIBLE|WS_CHILD|BS_DEFPUSHBUTTON,380,650,65,22,hwnd,(HMENU)BUTTON6,GetModuleHandle(NULL),NULL);   
 
SendDlgItemMessage(hwnd,EDIT2,EM_FMTLINES,(WPARAM)true,(LPARAM)0);
SendDlgItemMessage(hwnd,EDIT3,EM_FMTLINES,(WPARAM)true,(LPARAM)0);
SendDlgItemMessage(hwnd,EDIT4,EM_FMTLINES,(WPARAM)true,(LPARAM)0);
SendDlgItemMessage(hwnd,EDIT7,EM_FMTLINES,(WPARAM)true,(LPARAM)0);
SendDlgItemMessage(hwnd,EDIT1,EM_SETREADONLY,(WPARAM)true,(LPARAM)0);
SendDlgItemMessage(hwnd,EDIT2,EM_SETREADONLY,(WPARAM)true,(LPARAM)0);
SendDlgItemMessage(hwnd,EDIT3,EM_SETREADONLY,(WPARAM)true,(LPARAM)0);
SendDlgItemMessage(hwnd,EDIT4,EM_SETREADONLY,(WPARAM)true,(LPARAM)0);

remove("import.txt"); //remove old logs if existing 
remove("export.txt");    
ShowWindow (hwnd, nFunsterStil);
 
    /* Run the message loop. It will run until GetMessage() returns 0 */
    while (GetMessage (&messages, NULL, 0, 0))
    {
        /* Translate virtual-key messages into character messages */
        TranslateMessage(&messages);
        /* Send message to WindowProcedure */
        DispatchMessage(&messages);
    }
 
    /* The program return-value is 0 - The value that PostQuitMessage() gave */
    return messages.wParam;
}
 
 
/*  This function is called by the Windows function DispatchMessage()  */
 
LRESULT CALLBACK WindowProcedure (HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)                  /* handle the messages */
    {
    case WM_COMMAND:
            {
                switch(LOWORD(wParam))
                    {
                    case BUTTON1:{ // OPEN A PE FILE  
                                    OPENFILENAME ofn;
                                    char szFileName[MAX_PATH] = "";
                                    SendDlgItemMessage(hwnd,BUTTON5, BN_CLICKED, (WPARAM)hBtn5,(LPARAM) hwnd);
                                    ZeroMemory(&ofn, sizeof(ofn));
                                    ofn.lStructSize = sizeof(ofn);
                                    ofn.hwndOwner = hwnd;
                                    ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0Dll (*.dll)\0*.dll\0";
                                    ofn.lpstrFile = szFileName;
                                    ofn.nMaxFile = MAX_PATH;
                                    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
                                    ofn.lpstrDefExt = "";
                                    if(GetOpenFileName(&ofn)){
                                          SetDlgItemText(hwnd,EDIT1,szFileName);
                                    }
                    }break;
                    case BUTTON2:{ // READS INFORMATIONF FROM PE HEADER
                                    remove("import.txt");
                                    remove("export.txt");
                                    char txt[5024], txt1[2056], txt2[2056], txt3[2056], txt4[2056], txt5[2056]; 
                                    txt[0] = txt1[0] = txt2[0] = txt3[0] = txt4[0] = txt5[0] = '\0';
 
                                    int len = GetWindowTextLength (GetDlgItem (hwnd, EDIT1));
                                    GetDlgItemText(hwnd,EDIT1,FileName, len + 1);                  
                                    hFile = CreateFile(FileName, GENERIC_READ, FILE_SHARE_READ, 0,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
                                    if (hFile == INVALID_HANDLE_VALUE){
                                          MessageBoxA(NULL,"Cannot Open the File","Error",MB_OK);break;
                                    }
                                    
                                    FileSize = GetFileSize(hFile, NULL);
                                    BaseAddress = (BYTE *) malloc(FileSize);
                                    if (!ReadFile(hFile, BaseAddress, FileSize, &BR, NULL)){
                                          free(BaseAddress);
                                          CloseHandle(hFile);
                                          break;
                                    }
 
                                    ImageDosHeader = (IMAGE_DOS_HEADER *) BaseAddress;
                                    ImageOptionalHeader = (_IMAGE_OPTIONAL_HEADER *) BaseAddress;
                                    
                                    if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) // checks the DOS SIGNATURE, if not equals to (MZ) then stops
                                    {
                                          MessageBoxA(NULL,"Invalid Dos Header","Error",MB_OK);
                                          free(BaseAddress);
                                          CloseHandle(hFile);
                                          break;
                                    }
 
                                    ImageNtHeaders = (IMAGE_NT_HEADERS *) (ImageDosHeader->e_lfanew + (DWORD) ImageDosHeader);
 
                                    if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) // checks the PE header, if not equals to NT signature stops
                                    {
                                          MessageBoxA(NULL,"Invalid PE Signature","Error",MB_OK);
                                          free(BaseAddress);
                                          CloseHandle(hFile);
                                          break;
                                    }
 
                                    // takes the address of first section
                                    ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);
                                    // shows the section table
                                    for (x = 0; x < ImageNtHeaders->FileHeader.NumberOfSections; x++)
                                    {
                                          memcpy(SectionName, ImageSectionHeader[x].Name,IMAGE_SIZEOF_SHORT_NAME);
                                          long lSize;
                                          char * buffer;
                                          size_t result;  
                                          _ultoa(ImageSectionHeader[x].VirtualAddress,txt1,16);
                                          _ultoa(ImageSectionHeader[x].Misc.VirtualSize,txt2,16);
                                          _ultoa(ImageSectionHeader[x].PointerToRawData,txt3,16);
                                          _ultoa(ImageSectionHeader[x].SizeOfRawData,txt4,16);
                                          _ultoa(ImageSectionHeader[x].Characteristics,txt5,16);
                                          
                                          strcat(txt, "Section Name: ");
                                          strcat(txt, SectionName);
                                          strcat(txt , "\r\n");
                                          strcat(txt, "Virtual Address: ");
                                          strcat(txt, txt1);
                                          strcat(txt , "\r\n");
                                          strcat(txt, "Virtual Size: ");
                                          strcat(txt, txt2);
                                          strcat(txt , "\r\n"); 
                                          strcat(txt, "Raw Address: ");
                                          strcat(txt, txt3);
                                          strcat(txt , "\r\n"); 
                                          strcat(txt, "Raw Size: ");
                                          strcat(txt, txt4);
                                          strcat(txt , "\r\n");
                                          strcat(txt, "Characteristics: ");
                                          strcat(txt, txt5);
                                          strcat(txt , "\r\n\r\n");
                                          
                                          SetDlgItemText(hwnd,EDIT2,txt);  
                                 }
                                 
                                 /* VARIABLES USED TO STORE AND SHOW INFORMATIONS */
                                 char Img[LENGTH],Img1[LENGTH];
                                 char AeP[LENGTH],AeP1[LENGTH];
                                 char BoC[LENGTH],BoC1[LENGTH];
                                 char BoD[LENGTH],BoD1[LENGTH];
                                 char Sa[LENGTH] ,Sa1[LENGTH];
                                 char Fa[LENGTH] ,Fa1[LENGTH];
                                 char Ss[LENGTH] ,Ss1[LENGTH];
                                 char SoC[LENGTH],SoC1[LENGTH];
                                 char SiD[LENGTH],SiD1[LENGTH];
                                 char SuD[LENGTH],SuD1[LENGTH];
                                 char Em[LENGTH] ,Em1[LENGTH];
                                 char Sgn[LENGTH],Sgn1[LENGTH];
                                 
                                 Img[0], Img1[0], AeP[0], AeP1[0], BoC[0], BoC1[0], BoD[0], BoD1[0], Sa[0] , Sa1[0] , Fa[0],  Fa1[0] = '\0';
                                 Ss[0] , Ss1[0] , SoC[0], SoC1[0], SiD[0], SiD1[0], SuD[0], SuD1[0], Em[0] , Em1[0] , Sgn[0], Sgn1[0] = '\0';
                                 
                                 for (int i = 0; i < LENGTH; i++){
                                       Img[i] = '\0';
                                       AeP[i] = '\0';
                                       BoC[i] = '\0';
                                       BoD[i] = '\0';
                                       Sa[i] =  '\0';
                                       Fa[i] =  '\0';
                                       Ss[i] =  '\0';
                                       SoC[i] = '\0';
                                       SiD[i] = '\0';
                                       SuD[i] = '\0';
                                       Em[i] =  '\0';
                                       Sgn[i] = '\0';
                                 }
                                 //STORES VALUES
                                 DWORD ImageBase = ImageNtHeaders->OptionalHeader.ImageBase;
                                 DWORD AddressOfEntryPoint = ImageNtHeaders->OptionalHeader.AddressOfEntryPoint;
                                 DWORD BaseOfCode = ImageNtHeaders->OptionalHeader.BaseOfCode;
                                 DWORD BaseOfData = ImageNtHeaders->OptionalHeader.BaseOfData;
                                 DWORD SectionAlignment = ImageNtHeaders->OptionalHeader.SectionAlignment;
                                 DWORD FileAlignment = ImageNtHeaders->OptionalHeader.FileAlignment;
                                 DWORD Subsystem = ImageNtHeaders->OptionalHeader.Subsystem;
                                 DWORD SizeOfCode = ImageNtHeaders->OptionalHeader.SizeOfCode;
                                 DWORD SizeOfInitializedData = ImageNtHeaders->OptionalHeader.SizeOfInitializedData;
                                 DWORD SizeOfUnitializedData = ImageNtHeaders->OptionalHeader.SizeOfUninitializedData;
                                 DWORD EMagic = ImageDosHeader->e_magic;
                                 DWORD Signature = ImageNtHeaders->Signature;
                                 
                                 /* CONVERT DWORD TO HEX ==> I REALLY LOVE THIS FUNCTION :P*/
                                 _ultoa(ImageBase,Img1,16);
                                 _ultoa(AddressOfEntryPoint,AeP1,16);
                                 _ultoa(BaseOfCode,BoC1,16);
                                 _ultoa(BaseOfData,BoD1,16);
                                 _ultoa(SectionAlignment,Sa1,16);
                                 _ultoa(FileAlignment,Fa1,16);
                                 _ultoa(Subsystem,Ss1,16);
                                 _ultoa(SizeOfCode,SoC1,16);
                                 _ultoa(SizeOfInitializedData,SiD1,16);
                                 _ultoa(SizeOfUnitializedData,SuD1,16);
                                 _ultoa(EMagic,Em1,16);
                                 _ultoa(Signature,Sgn1,16);
                                 
                                 strcat(Img,"ImageBase: 0x");
                                 strcat(Img, Img1);
                                 strcat(AeP, "AddressOfEntryPoint: 0x");
                                 strcat(AeP, AeP1);
                                 strcat(BoC, "BaseOfCode: 0x");
                                 strcat(BoC, BoC1);
                                 strcat(BoD, "BaseOfData: 0x");
                                 strcat(BoD, BoD1);
                                 strcat(Sa, "SectionAlignment: 0x");
                                 strcat(Sa, Sa1);
                                 strcat(Fa, "FileAlignment: 0x");
                                 strcat(Fa, Fa1);      
                                 strcat(Ss, "Subsystem: 0x");
                                 strcat(Ss, Ss1);
                                 strcat(SoC, "SizeOfCode: 0x");
                                 strcat(SoC, SoC1);
                                 strcat(SiD, "SizeOfInitializedData: 0x");
                                 strcat(SiD, SiD1);
                                 strcat(SuD, "SizeOfUnitializedData: 0x");
                                 strcat(SuD, SuD1);
                                 strcat(Em, "EMagic Signature: 0x");
                                 strcat(Em, Em1);
                                 strcat(Sgn, "PE Signature: 0x");
                                 strcat(Sgn, Sgn1);
                                 
                                 SetDlgItemText(hwnd,LABEL5, Img);
                                 SetDlgItemText(hwnd,LABEL6, AeP);
                                 SetDlgItemText(hwnd,LABEL7, BoC);
                                 SetDlgItemText(hwnd,LABEL8, BoD);
                                 SetDlgItemText(hwnd,LABEL9, Sa);
                                 SetDlgItemText(hwnd,LABEL10,Fa);
                                 SetDlgItemText(hwnd,LABEL11,Ss);
                                 SetDlgItemText(hwnd,LABEL12,SoC);
                                 SetDlgItemText(hwnd,LABEL13,SiD);
                                 SetDlgItemText(hwnd,LABEL14,SuD);
                                 SetDlgItemText(hwnd,LABEL15,Em);
                                 SetDlgItemText(hwnd,LABEL16,Sgn);    
                                 /* INFORMATION */
   
                                 /* LOGS FROM IMPORT TABLE */
 
                                 f = fopen("import.txt","wa");
                                 IT_Offset = RvaToOffset(ImageNtHeaders,ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
                                 ImageImportDescr = (IMAGE_IMPORT_DESCRIPTOR *) (IT_Offset + (DWORD) BaseAddress);
                                 x = 0; // counter used under
                                                
                                 while (ImageImportDescr[x].FirstThunk != 0) // analyzes all  descriptors
                                 {
                                       Name = (char *) (RvaToOffset(ImageNtHeaders, ImageImportDescr[x].Name) + (DWORD) BaseAddress);
                                       fprintf(f,"\nModule Name: %s\r\nFunctions:\r\n", Name);
 
                                       // selects the array to analyze
                                       Thunks = (DWORD *) (RvaToOffset(ImageNtHeaders, ImageImportDescr[x].OriginalFirstThunk != 0 ? ImageImportDescr[x].OriginalFirstThunk : ImageImportDescr[x].FirstThunk) + (DWORD) BaseAddress);
                                       y = 0; // another counter
 
                                       // browse into internal functions of the analyzed file
                                       while (Thunks[y] != 0)
                                       {
                                             //imports
                                             if (Thunks[y] & IMAGE_ORDINAL_FLAG)
                                             {
                                                   fprintf(f,"Ordinal: %08X\r\n", (Thunks[y] - IMAGE_ORDINAL_FLAG));
                                                   y++;
                                                   continue;
                                             }
 
                                       ImgName = (IMAGE_IMPORT_BY_NAME *) (RvaToOffset(ImageNtHeaders, Thunks[y]) + (DWORD) BaseAddress);
                                       fprintf(f,"Name: %s\r\n", &ImgName->Name);
                                       y++;
                                       }
 
                                       x++;
                                 } 
                                 fflush(f);
                                 fclose(f);
                                 std::ifstream of("import.txt");
                                 char *s;
                                 char sf[LENGTH*50],sf1[LENGTH*50];
                                 sf[0], sf1[0] = '\0';

                                 while (of)
                                 {
                                       of.getline(sf,1000);
                                       strcat(sf1,sf);
                                       strcat(sf1,"\r\n");
                                 }
                                 SetDlgItemText(hwnd,EDIT3,sf1);
                                 of.close();
                                 remove("import.txt");
                                 /* IMPORT TABLE */   
 
                                 /* LOGS FROM EXPORT TABLE */
                                 ET_Offset = RvaToOffset(ImageNtHeaders,ImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                                 ImageExportDir = (IMAGE_EXPORT_DIRECTORY *) (ET_Offset +(DWORD) BaseAddress);
                                 Name = (char *) (RvaToOffset(ImageNtHeaders,ImageExportDir->Name) + (DWORD) BaseAddress);
                                 Functions = (DWORD *) (RvaToOffset(ImageNtHeaders, ImageExportDir->AddressOfFunctions) + (DWORD) BaseAddress);
                                 Names = (DWORD *) (RvaToOffset(ImageNtHeaders, ImageExportDir->AddressOfNames) + (DWORD) BaseAddress);
                                 NameOrds = (WORD *) (RvaToOffset(ImageNtHeaders, ImageExportDir->AddressOfNameOrdinals) + (DWORD) BaseAddress);
 
                                 // enums and shows functions
 
                                 for (x = 0; x < ImageExportDir->NumberOfFunctions; x++)
                                 {
                                       // controllo se l'EP e' 0
                                       // se si' allora passa alla prossima funzione
                                       if (Functions[x] == 0)continue;
 
                                       printf("\nOrd: %04X\nEP: %08X\n", (x + ImageExportDir->Base), Functions[x]);
                                       f=fopen("export.txt","a");
                                       
                                       if (f != NULL) {
                                             fprintf(f,"\nOrd: %04X\nEP: %08X\n", (x + ImageExportDir->Base), Functions[x] );
                                             fflush(f);
                                       }
                                       
                                       // if the function has also a name I show it
                                       for (y = 0; y < ImageExportDir->NumberOfNames; y++)
                                       {
                                             if (NameOrds[y] == x)
                                             {
                                                   FName = (char *) (RvaToOffset(ImageNtHeaders, Names[y]) + (DWORD) BaseAddress);
                                                   printf("Name: %s\n", FName);
                                                   if (f != NULL) 
                                                   {
                                                         fprintf(f,"Name: %s\n", FName);
                                                         fflush(f);
                                                         fclose(f);
                                                   }
                                             break;
                                             }
                                       }
                                 }
                                 
                                 std::ifstream of1("export.txt");
                                 char sf2[LENGTH*80],sf3[LENGTH*80];
                                 sf2[0], sf3[0] = '\0';

                                 while (of1) 
                                 {
                                       of1.getline(sf2,1000);
                                       strcat(sf3,sf2);
                                       strcat(sf3,"\r\n");
                                 }
                                 SetDlgItemText(hwnd,EDIT4,sf3);
                                 of1.close();
                                 remove("export.txt");
                                 /* EXPORT TABLE */
   
                                 free(BaseAddress);
                                 CloseHandle(hFile);
                         }break; // end case BUTTON2   
                         
                         case BUTTON3:{PostQuitMessage (0);break;}
                         
                         case BUTTON4:{
 
   HANDLE hFile;
   BYTE *BaseAddress;
   WORD nSection;
   DWORD FileSize, BRW, NameSize, Size;
 
   IMAGE_DOS_HEADER *ImageDosHeader;
   IMAGE_NT_HEADERS *ImageNtHeaders;
   IMAGE_SECTION_HEADER *ImageSectionHeader;
 
   char Dim[MAX_PATH];
   int len = GetWindowTextLength (GetDlgItem (hwnd, EDIT6));
   GetDlgItemText(hwnd,EDIT6,Dim, len + 1);  
   char Sect[MAX_PATH];
int lent = GetWindowTextLength (GetDlgItem (hwnd, EDIT5));
   GetDlgItemText(hwnd,EDIT5,Sect, lent + 1);   
   Size = atoi(Dim);
 
   if (Size > 0 && lent > 0) {
 
   hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
 
   if (hFile == INVALID_HANDLE_VALUE)
   {
      printf("Cannot Open the File\n");
      return -1;
   }
 
   FileSize = GetFileSize(hFile, NULL);
 
   BaseAddress = (BYTE *) malloc(FileSize);
 
   if (!ReadFile(hFile, BaseAddress, FileSize, &BRW, NULL))
   {
      free(BaseAddress);
      CloseHandle(hFile);
      return -1;
   }
 
   ImageDosHeader = (IMAGE_DOS_HEADER *) BaseAddress;
/* le signature le avevo gi� controllate ma lo rifaccio per 
evitare che possa insorgere qualche erorre strano */
 
   // controlliamo il Dos Header
   if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
   {
      printf("Invalid Dos Header\n");
      free(BaseAddress);
      CloseHandle(hFile);
      return -1;
   }
 
   ImageNtHeaders = (IMAGE_NT_HEADERS *)
      (ImageDosHeader->e_lfanew + (DWORD) ImageDosHeader);
 
   // controlliamo il PE Header
   if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
   {
      printf("Invalid PE Header\n");
      free(BaseAddress);
      CloseHandle(hFile);
      return -1;
   }
 
   // prende le dimensioni
 
 
   printf("Creating New Section...\n");
 
   nSection = ImageNtHeaders->FileHeader.NumberOfSections;
   ImageNtHeaders->FileHeader.NumberOfSections++;
   ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);
   ImageNtHeaders->OptionalHeader.SizeOfImage +=
      CalcAlignment(ImageNtHeaders->OptionalHeader.SectionAlignment, Size);
 
   ZeroMemory(&ImageSectionHeader[nSection],
      IMAGE_SIZEOF_SECTION_HEADER);
 
 
   if (strlen(Sect) <= IMAGE_SIZEOF_SHORT_NAME)
      NameSize = strlen(Sect);
   else
      NameSize = IMAGE_SIZEOF_SHORT_NAME;
 
   memcpy(&ImageSectionHeader[nSection].Name, Sect, NameSize);
 
 
   // calcola il Virtual Address della nuova sezione
   ImageSectionHeader[nSection].VirtualAddress =
      CalcAlignment(ImageNtHeaders->OptionalHeader.SectionAlignment,
      (ImageSectionHeader[nSection - 1].VirtualAddress +
      ImageSectionHeader[nSection - 1].Misc.VirtualSize));
 
 
   ImageSectionHeader[nSection].Misc.VirtualSize = Size;
 
   if (ImageSectionHeader[nSection - 1].SizeOfRawData %
    ImageNtHeaders->OptionalHeader.FileAlignment)
   {
      // se la sezione prima di quella che vogliamo creare noi non � allineata lo faccio
      ImageSectionHeader[nSection - 1].SizeOfRawData =
         CalcAlignment(ImageNtHeaders->OptionalHeader.FileAlignment,
         ImageSectionHeader[nSection - 1].SizeOfRawData);
 
      SetFilePointer(hFile,
         (ImageSectionHeader[nSection - 1].PointerToRawData +
         ImageSectionHeader[nSection - 1].SizeOfRawData), NULL,
         FILE_BEGIN);
 
      SetEndOfFile(hFile);
   }
 
   ImageSectionHeader[nSection].PointerToRawData = GetFileSize(hFile, NULL);
   ImageSectionHeader[nSection].SizeOfRawData = CalcAlignment(ImageNtHeaders->OptionalHeader.FileAlignment, Size);
   ImageSectionHeader[nSection].Characteristics = IMAGE_SCN_MEM_READ;
   SetFilePointer(hFile, ImageSectionHeader[nSection].SizeOfRawData,NULL, FILE_END);
   SetEndOfFile(hFile);
 
   // salvo le modifiche
   SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
   WriteFile(hFile, BaseAddress, FileSize, &BRW, NULL);
   MessageBox(NULL,"The section has been successfully added!","Info",MB_OK); 
   free(BaseAddress);
   CloseHandle(hFile);}
   else {
   MessageBox(NULL,"The section was not added correctly <img src="images/smilies1/sad.gif" style="vertical-align: middle;" border="0" alt="Sad" title="Sad" />","Error",MB_OK); }   
 
 
}break; // fine button 4
           case BUTTON5:{
                MessageBoxA(NULL,"Program created by Zyrel aka Marco Lagalla.\nVisit us on: <a href="http://www.unfair-gamers.com" target="_blank">http://www.unfair-gamers.com</a>!\nThanks to Ntoskrnl <img src="images/smilies1/wink1.gif" style="vertical-align: middle;" border="0" alt="Wink" title="Wink" />","Credits and Disclaimer",MB_OK);
                }break;
           case BUTTON6:{
                ShellExecute(NULL,"open","http://www.unfair-gamers.com/forum/index.php",NULL,NULL,SW_HIDE);
                }break;
                default:{break;} // DEFAUL CONTROLLI
             }break;} // FINE WM_COMMAND
        case WM_DESTROY:
            PostQuitMessage (0);       /* send a WM_QUIT to the message queue */
            break;
        default:                      /* for messages that we don't deal with */
            return DefWindowProc (hwnd, message, wParam, lParam);
        case WM_CTLCOLORSTATIC:
             SetTextColor((HDC)hLabel2,RGB(141,149,155)); 
    }
 
    return 0;
}
 
void AddLogLine(char *line) {
log += line;
log += "\n";
SetWindowText( hEdit7, log.c_str() );
}
 
 
DWORD RvaToOffset(IMAGE_NT_HEADERS *NT, DWORD Rva)
{
   DWORD Offset = Rva, Limit;
   IMAGE_SECTION_HEADER *Img;
   WORD i;
 
   Img = IMAGE_FIRST_SECTION(NT);
 
   if (Rva < Img->PointerToRawData)
      return Rva;
 
   for (i = 0; i < NT->FileHeader.NumberOfSections; i++)
   {
      if (Img[i].SizeOfRawData)
         Limit = Img[i].SizeOfRawData;
      else
         Limit = Img[i].Misc.VirtualSize;
 
      if (Rva >= Img[i].VirtualAddress &&
       Rva < (Img[i].VirtualAddress + Limit))
      {
         if (Img[i].PointerToRawData != 0)
         {
            Offset -= Img[i].VirtualAddress;
            Offset += Img[i].PointerToRawData;
         }
 
         return Offset;
      }
   }
 
   return NULL;
}
DWORD CalcAlignment(DWORD Alignment, DWORD TrueSize)
{
   DWORD CalculatedAlignment;
 
   for(CalculatedAlignment = Alignment; ; CalculatedAlignment
      += Alignment)
   {
      if (TrueSize <= CalculatedAlignment) break;
   }
 
   return CalculatedAlignment;
}