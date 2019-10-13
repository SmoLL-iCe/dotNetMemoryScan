Module Module1


    '83 05 ?? ?? ?? ?? 0A A1
    '\x83\x05\x00\x00\x00\x00\x0A\xA1
    'xx????xx
    '0045B072

    Sub use_example()

        Dim find_aob As New dotNetMemoryScan()
        ' scan_all: will scan all process memory, from Static And dynamic.
        Dim test1 = IntPtr.Zero
        Dim test2 = IntPtr.Zero

        ' with simple array
        test2 = find_aob.scan_all("test.exe", "83 05 ?? ?? ?? ?? 0A A1")

        ' with pattern And mask
        test1 = find_aob.scan_all("test.exe", "\x83\x05\x00\x00\x00\x00\x0A\xA1", "xx????xx")

        Console.WriteLine("result 0x{0:X16}, 0x{0:X16}", test1.ToInt64(), test2.ToInt64())
        Dim p = Process.GetProcessesByName("test")
        If Not IsNothing(p) And p.Count() > 0 Then

            ' can be used by passing the process handle directly.
            test1 = find_aob.scan_all(p(0).Handle, "83 05 ?? ?? ?? ?? 0A A1")
            Console.WriteLine("[handle] result 0x{0:X16}", test1.ToInt64())

            ' can be used by passing the process.
            test1 = find_aob.scan_all(p(0), "83 05 ?? ?? ?? ?? 0A A1")
            Console.WriteLine("[process] result 0x{0:X16}", test1.ToInt64())

            ' can be used by passing the process id.
            test1 = find_aob.scan_all(p(0).Id, "83 05 ?? ?? ?? ?? 0A A1")
            Console.WriteLine("[pid] result 0x{0:X16}", test1.ToInt64())
        End If

        ' scan_module: scans only the Static part Of the Module
        test2 = find_aob.scan_module("test.exe", "test.exe", "83 05 ?? ?? ?? ?? 0A A1")
        Console.WriteLine("[module 1] result 0x{0:X16}", test1.ToInt64())

        ' with pattern And mask
        test1 = find_aob.scan_module("test.exe", "name.dll", "\x83\x05\x00\x00\x00\x00\x0A\xA1", "xx????xx")
        Console.WriteLine("[module 2] result 0x{0:X16}", test1.ToInt64())

        ' Writing in memory.
        find_aob.write_mem("test.exe", test1, "90 90 90 90 90 90 90")

        ' or
        find_aob.write_mem("test.exe", test1, "\x90\x90\x90\x90\x90\x90\x90")
    End Sub
    Sub Main()
        use_example()
        Console.ReadKey()
    End Sub

End Module
