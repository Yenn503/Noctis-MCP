## MaldevAcademyLdr.2: RunPE implementation with multiple evasive techniques

<br>

### Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)
  
[Maldev Academy Syllabus](https://maldevacademy.com/syllabus?ref=gh)

[Maldev Academy Pricing](https://maldevacademy.com/pricing?ref=gh)

<br>
<br>

> [!NOTE]
> Although this repo can be used to execute other binaries, the **whole focus** was on running the **mimikatz.exe** executable.
> This is for demonstration and testing purposes, as mimikatz.exe is a well-known post-exploitation tool.

<br>

## Most Notable Features

* **Stegnography:** Hiding PE payloads in *PNG/JPG/JPEG/BMP/GIF* files using [Discrete Wavelet Transform (DWT)](https://en.wikipedia.org/wiki/Discrete_wavelet_transform) with [Quantization Index Modulation (QIM)](https://sia.mit.edu/wp-content/uploads/2015/04/2001-chen-wornell-it.pdf) and [Error-Correcting Codes (ECC)](https://en.wikipedia.org/wiki/Error-correcting_code). It is worth noting that the [Reed-Solomon Error Correction Algorithm](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction) implemented by the PE loader is based on [SRI-CSL/jel](https://github.com/SRI-CSL/jel/tree/master/rscode).

* **Utilizing The GPU For Memory Scanners Evasion:** Using the [D3d11](https://learn.microsoft.com/en-us/windows/win32/api/d3d11/) library, the implementation moves the injected PE payload into the GPU memory when it's idle, hiding it from memory scanners.

* **Thread Stack Spoofing:** Based on [Cobalt-Strike/CallStackMasker](https://github.com/Cobalt-Strike/CallStackMasker), the code searches for a suitable thread stack and masks the thread running the PE payload whenever the payload is in GPU memory.

* **Syscalls Tampering:** [Maldev-Academy/TrapFlagForSyscalling](https://github.com/Maldev-Academy/TrapFlagForSyscalling) is used to invoke tampered syscalls relying on the Trap Flag.

<br>

### Other Features/Tricks

* Handles API Set Dlls using [ajkhoury/ApiSet](https://github.com/ajkhoury/ApiSet).
* Loads the required payload DLLs in a random sequence to help against sequence-based image-load notifications (if any).
* Uses AES-NI from [Intel.AES-NI](https://github.com/NUL0x4C/Intel.AES-NI/blob/main/AES-NI/Aes.intrinsic.c) to encrypt the PE payload sections before affloading them to the GPU memory, and decrypt them after fetching them from there.
* Counts prime numbers for a specified duration as a method to delay execution. This technique is not executed by default.
* Unhooks loaded Dlls from the `\knownDlls\` directory without using `RWX` memory permissions. This technique is not executed by default, as some EDRs were able to detect the logic.
* If not using the aforementioned Syscalls Tampering technique, the implementation will use [HellsHall](https://maldevacademy.com/modules/89). Additionally, in the DLL unhooking routine, the implementation utilizes `win32u.dll` to execute the `syscall` instruction, as `ntdll.dll`'s text section will be `RW`, which blocks us from jumping to a `syscall` instruction there.
* Overwrite **EDR C**'s VEH that is used to handle `STATUS_GUARD_PAGE_VIOLATION` exceptions, as this vendor was found to be using `PAGE_GUARD` permissions to trigger exceptions when accessing fake DLLs:

  <img width="687" height="207" alt="image" src="https://github.com/user-attachments/assets/8a2a2f28-524c-4e0c-bda0-7c344e8b2ddd" />
  
  The code is refactored from [mannyfreddy](https://github.com/mannyfred) in the [Introduction to Vectored Handler Manipulation](https://maldevacademy.com/new/modules/69) module.
* Manually fetching resource section payloads, avoiding APIs like `FindResourceW` and `LoadResource`.

<br>
<br>

## Usage - RunPeFile

[RunPeFile](https://github.com/Maldev-Academy/MaldevAcademyLdr.2/tree/main/RunPeFile) is the main binary file that will execute the provided EXE from the stored PNG file(s) in its resource section. Some notes when compiling `RunPeFile`:

* Using the [Configuration.h](https://github.com/Maldev-Academy/MaldevAcademyLdr.2/blob/main/RunPeFile/Configuration.h) header file, one can add and remove features.
* Define the [ _DEBUG](https://github.com/Maldev-Academy/MaldevAcademyLdr.2/blob/main/RunPeFile/DebugMacros.h#L11) macro to enable the debug mode. Or compile in Debug mode.
* In the repository, the current `RunPeFile` implementation will run `mimikatz.exe`.
* One should utilize the `FileConstructor.py` script to update the payload delivered by `RunPeFile`.

<br>

## Usage - FileConstructor.py

The `FileConstructor.py` script is the main script used to generate PNG files containing the DWT-encoded EXE payload. These PNGs are placed in the `EncodedPngs` directory, from which the updated `RunPeFile` project embeds them into the resource section of the compiled binary. Each EXE is split into multiple chunks, with every chunk embedded into its own PNG image. As a result, you'll see several PNG files that all display the same picture. This chunking is necessary because the steganography method (based on DWT combined with Reed–Solomon error correction) typically cannot fit an entire EXE payload into a single image (depending on the size/pixels in the PNG, as well as the size of the payload). This script relies on the [NUM_SPLIT_PARTS ](https://github.com/Maldev-Academy/MaldevAcademyLdr.2/blob/main/FileConstructor.py#L15) constant to determine how many chunks the input EXE will be split into.

`FileConstructor.py` handles the Visual Studio Project files of `RunPeFile`, as well as the chunking logic. It calls the `DwtStegPeFileToPng.py` script to do the actual payload embedding. 

Examples of calling `FileConstructor.py` are:

```
# Adds the embedded PNG(s) to the 'RunPeFile\RunPeFile.vcxproj' project by dafault:
python.exe .\FileConstructor.py --pe mimikatz.exe --png memes\cat.png                              

# Adds the embedded PNG(s) to the 'XYZ\XYZ.vcxproj' project:
python.exe .\FileConstructor.py --pe mimikatz.exe --png memes\cat.png --project XYZ\XYZ.vcxproj   
```


<br>

### Usage - DwtStegPeFileToPng.py

The `DwtStegPeFileToPng.py` script is the main script that handles implementing the DWT algorithm to encode a given file into a specified PNG one. It is a stand-alone script and can be used in other scenarios, but in this repository, it's called through the `FileConstructor.py` script only. Below is how `DwtStegPeFileToPng.py` can be called:

```
usage: DwtStegPeFileToPng.py [-h] (--encode | --decode) --png PNG --output OUTPUT [--file FILE] [-v]

DWT-based steganography tool for hiding files in PNG images

options:
  -h, --help       show this help message and exit
  --encode         Encode/embed a file
  --decode         Decode/extract a file
  --png PNG        PNG image file
  --output OUTPUT  Output file path
  --file FILE      File to embed (required for --encode)
  -v, --verbose    Verbose output
```


<br>

### Usage - ExtractPePayloadFromPng

The `ExtractPePayloadFromPng` project is a standalone tool for pulling payloads out of PNG files. It can handle single images, or, when given the PNG containing the first chunk of a split PE file, it will reconstruct the full payload across all related PNGs. For example, calling `ExtractPePayloadFromPng.exe` like this:

```
.\ExtractPePayloadFromPng.exe --i ..\..\EncodedPngs\mimikatz_part01.png --o mimikatz.exe
```

Will pull the full mimikatz.exe binary from the PNG files located under the `EncodedPngs` directory.


<br>

## Limitations

* The Stack spoofing technique implemented was tested on Windows 11 only. 
* To move the PE payload sections back and forth from and to the GPU memory, one should have a Direct3D-11 capable GPU (discrete or integrated), a WDDM 1.1+ driver, and have the DirectX 11 runtime installed. 
* Only x64 PE payloads are supported.

<br>

## Demo

> [!NOTE]
> Some EDRs required further tweaks to the code for a successful bypass. Some features were enabled or disabled depending on the security vendor encountered.

<br>


### MaldevAcademyLdr.2 Against EDR A

<img width="2135" height="1280" alt="MDE BYPASS" src="https://github.com/Maldev-Academy/MaldevAcademyLdr.2/blob/main/Media/ELASTIC.BYPASS.png" />

<br>

### MaldevAcademyLdr.2 Against EDR B

<img width="1884" height="1313" alt="S1 BYPASS" src="https://github.com/Maldev-Academy/MaldevAcademyLdr.2/blob/main/Media/MDE.BYPASS.png" />

<br>

### MaldevAcademyLdr.2 Against EDR C

<img width="1865" height="1080" alt="ELASTIC BYPASS" src="https://github.com/Maldev-Academy/MaldevAcademyLdr.2/blob/main/Media/S1.BYPASS.png" />

<br>

### MaldevAcademyLdr.2 Against PESIEVE

Bypassing [Pesieve](https://github.com/hasherezade/pe-sieve) version [0.4.1.1](https://github.com/hasherezade/pe-sieve/releases/tag/v0.4.1.1) with the following command:

```
.\pe-sieve64.exe /data 4 /refl /iat 3 /obfusc 3 /shellc 4 /threads /pid XXXX
```

https://github.com/user-attachments/assets/47f5c3b9-e3c3-4be9-a063-2f3998071a57


<br>
