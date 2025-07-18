# wine_APT29
An analysis of the phishing campaign, with a particular focus on the malware wine.EXE and its behavior.

---

![Warning](https://img.shields.io/badge/Warning-Malware%20Sample-red)

**This repository contains a malware sample. I strongly recommend executing the code ONLY in a secure and isolated environment that you trust.**

---

## What is in this repository ?

- [Code](Code/): This directory contains all the code used for testing the server :
    - [dummy.c](Code/dummy.c) : PoC of the malware behaviour for communicating with the server, downloading the payload and launching it.
    - [serveur.py](Code/serveur.py) : Custom server in Python that try to mimic the orignal one (`ophibre.com`).

- [Rapport](Rapport/) : This directory contains three files presenting the analysis of the malware :
    - [ppcore.dll.bndb](Rapport/ppcore.dll.bndb) : Binary Ninja database containing the analysis results for `ppcore.dll`.
    - [Rapport_fr.md](Rapport/Rapport_fr.md) : Report in french of the analysis of the whole malware.
    - [record_wine.mp4](Rapport/record_wine.mp4) : Video showing the execution of the malware with the custom server.

- [Ressource](Ressource/) This directory contains additional ressources to run the PoC, as well as sample of the malware :
    - [653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358.zip](Ressource/653db3b63bb0e8c2db675cd047b737cefebb1c955bd99e7a93899e2144d34358.zip) : Archive containing all the file of the malware.
    - [adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8.exe](Ressource/adfe0ef4ef181c4b19437100153e9fe7aed119f5049e5489a36692757460b9f8.exe) : Library (`vmtools.dll`) used for installing the backdoor and for making some tests (anti-vm, anti-analysis, anti-debug, ...)
    - [cert.pem](Ressource/cert.pem) : Certificate file required for secure communication between the malware and the server.
    - [key.pem](Ressource/key.pem) : Key file required for secure communication between the malware and the server.

## References

- [Renewed APT29 Phishing Campaign Against European Diplomats
](https://research.checkpoint.com/2025/apt29-phishing-campaign/?source=post_page-----fd72fa1430b6---------------------------------------), April 15, 2025, Check Point Research: CPR


## To Do :

- Write the report in english
- Add analysis of the `vmtools.dll`.