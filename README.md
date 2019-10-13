# dotNetMemoryScan

[![forthebadge](https://forthebadge.com/images/badges/made-with-c-sharp.svg)](https://forthebadge.com)

## What is it ?
This is a .NET library for reading and writing memory. focuses mainly on byte array scanning.
using a specific search pattern.
You can look for an AOB pattern in all process memory, dynamic and static.

## Example of use:
C#
```csharp
dotNetMemoryScan find_aob = new dotNetMemoryScan();

// with simple array
var find_ptr = find_aob.scan_all("test.exe", "83 05 ?? ?? ?? ?? 0A A1");

//... or

// with pattern and mask
var find_ptr = find_aob.scan_all("test.exe", @"\x83\x05\x00\x00\x00\x00\x0A\xA1", "xx????xx");

var p = Process.GetProcessesByName("test");
if (p != null && p.Count() > 0)
{
    // can be used by passing the process handle directly.
    var find_ptr = find_aob.scan_all(p[0].Handle, "83 05 ?? ?? ?? ?? 0A A1");

    // can be used by passing the process.
    var find_ptr = find_aob.scan_all(p[0], "83 05 ?? ?? ?? ?? 0A A1");

    // can be used by passing the process id.
    var find_ptr = find_aob.scan_all(p[0].Id, "83 05 ?? ?? ?? ?? 0A A1");  
}

// scan_module: scans only the static part of the module
var find_ptr = find_aob.scan_module("test.exe", "test.exe", "83 05 ?? ?? ?? ?? 0A A1");

// with pattern and mask
var find_ptr = find_aob.scan_module("test.exe", "name.dll", @"\x83\x05\x00\x00\x00\x00\x0A\xA1", "xx????xx");

// Writing in memory.
find_aob.write_mem("test.exe", find_ptr, "90 90 90 90 90 90 90");
```

VB
```vb
Dim find_aob As New dotNetMemoryScan()
' with simple array
Dim find_ptr = find_aob.scan_all("test.exe", "83 05 ?? ?? ?? ?? 0A A1")

' with pattern And mask
Dim find_ptr = find_aob.scan_all("test.exe", "\x83\x05\x00\x00\x00\x00\x0A\xA1", "xx????xx")

Dim p = Process.GetProcessesByName("test")
If Not IsNothing(p) And p.Count() > 0 Then
    ' can be used by passing the process handle directly.
    Dim find_ptr = find_aob.scan_all(p(0).Handle, "83 05 ?? ?? ?? ?? 0A A1")

    ' can be used by passing the process.
    Dim find_ptr = find_aob.scan_all(p(0), "83 05 ?? ?? ?? ?? 0A A1")

    ' can be used by passing the process id.
    Dim find_ptr = find_aob.scan_all(p(0).Id, "83 05 ?? ?? ?? ?? 0A A1")
End If

' scan_module: scans only the Static part Of the Module
Dim find_ptr = find_aob.scan_module("test.exe", "test.exe", "83 05 ?? ?? ?? ?? 0A A1")

' with pattern And mask
Dim find_ptr = find_aob.scan_module("test.exe", "name.dll", "\x83\x05\x00\x00\x00\x00\x0A\xA1", "xx????xx")

' Writing in memory.
find_aob.write_mem("test.exe", find_ptr, "90 90 90 90 90 90 90")

' or
find_aob.write_mem("test.exe", find_ptr, "\x90\x90\x90\x90\x90\x90\x90")
```
## License
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://raw.githubusercontent.com/guilhermelim/Process-Memory-Tools/master/LICENSE)
