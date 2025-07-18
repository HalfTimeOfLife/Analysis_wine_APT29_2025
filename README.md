# wine_APT29
An analysis of the phishing campaign, with a particular focus on the malware wine.EXE and its behavior. It also includes a small PoC of the malware behavior.


![Warning](https://img.shields.io/badge/Warning-Malware%20Sample-red)

**This repository contains a malware sample. I strongly recommend executing the code ONLY in a secure and isolated environment that you trust.**

---

## What is in this repository ?

- [Poc](PoC/): This directory contains all the code used for the PoC :
    - [server.py](PoC/server.py) : Custom server in Python that try to mimic the orignal one (`ophibre.com`).

- [Report](Report/) : This directory contains three files presenting the analysis of the malware :
    - [record_wine.mp4](Report/record_wine.mp4) : Video showing the execution of the malware with the custom server.
    - [ppcore.dll.bndb](Report/ppcore.dll.bndb) : Binary Ninja database containing the analysis results for `ppcore.dll`.
    - [Report_fr.md](Report/Report_fr.md) : Report in french of the analysis of the whole malware.
    - [Report.md](Report/Report_fr.md) : Report in english of the analysis of the whole malware.

- [Ressources](Ressources/) This directory contains additional ressources to run the PoC, as well as sample of the malware :
    - [adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8.exe](Ressources/adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8.exe) : Library (`vmtools.dll`) used for installing the backdoor and for making some tests (anti-vm, anti-analysis, anti-debug, ...)
    - [cert.pem](Ressources/cert.pem) : Certificate file required for secure communication between the malware and the server.
    - [key.pem](Ressources/key.pem) : Key file required for secure communication between the malware and the server.

> The file `cert.pem` and `key.pem` are custom made, they aren't the real ones.

## Run the PoC

To run the PoC, you will need to redirect the http request to `ophibre.com` to your localhost or to the IP where the custom server ([server.py](PoC/server.py)) will be running.


To do that, you will need to change the `hosts` file :

### On Linux (for those who will use *Wine Is Not an Emulator*) :

```bash
sudo nano /etc/hosts
```

Add the line :

```text
<TARGET_IP> ophibre.com
```

### On Windows :

Open in privilege mode : `C:\Windows\System32\drivers\etc\hosts`
Add the line :

```text
<TARGET_IP> ophibre.com
```

### Launch the PoC

Then launch the python server in a command line :

```cmd
python.exe server.py
```

> Be careful to the location of the `.pem` files ! By default, server.py will search them in the directory [Ressources](Ressources/)

Finally compile [dummy.c](PoC/dummy.c) and launch it :

```cmd
./dummy.exe
```

The following video is a proof of the functionnality of the PoC : [record_poc.mp4](PoC/record_poc.mp4)

You can also watch how the server behave using the sample of the wine malware : [record_wine.mp4](Report/record_wine.mp4)

## References

- [Renewed APT29 Phishing Campaign Against European Diplomats
](https://research.checkpoint.com/2025/apt29-phishing-campaign/?source=post_page-----fd72fa1430b6---------------------------------------), April 15, 2025, Check Point Research: CPR


## To Do :

- Add analysis of the `vmtools.dll`.