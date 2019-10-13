using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32.SafeHandles;
using System.Windows.Forms;
using System.Text.RegularExpressions;
using System.Runtime.ConstrainedExecution;
using System.Security;
using System.Security.Principal;

public class dotNetMemoryScan
{

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern void SetLastError(uint dwErrorCode);
    [DllImport("kernel32.dll")]
    public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    protected static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    protected static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool IsWow64Process([In] IntPtr processHandle,
     [Out, MarshalAs(UnmanagedType.Bool)] out bool wow64Process);
    [DllImport("kernel32.dll", EntryPoint = "GetProcessId", CharSet = CharSet.Auto)]
    static extern int GetProcessId(IntPtr handle);
    [DllImport("kernel32.dll")]
    static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress,
    UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    public dotNetMemoryScan()
    {
        EnablePrivileges.GoDebugPriv();
    }

    public static string GetSystemMessage(uint errorCode)
    {
        var exception = new System.ComponentModel.Win32Exception((int)errorCode);
        return exception.Message;
    }
    [StructLayout(LayoutKind.Sequential)]
    protected struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public uint RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
    //uint PROCESS_ALL_ACCESS = 0x1F0FF;
    //Memory Protect
    //https://msdn.microsoft.com/en-us/library/windows/hardware/dn957515(v=vs.85).aspx
    private enum AllocationProtectEnum : uint
    {
        PAGE_EXECUTE            = 0x00000010,
        PAGE_EXECUTE_READ       = 0x00000020,
        PAGE_EXECUTE_READWRITE  = 0x00000040,
        PAGE_EXECUTE_WRITECOPY  = 0x00000080,
        PAGE_NOACCESS           = 0x00000001,
        PAGE_READONLY           = 0x00000002,
        PAGE_READWRITE          = 0x00000004,
        PAGE_WRITECOPY          = 0x00000008,
        PAGE_GUARD              = 0x00000100,
        PAGE_NOCACHE            = 0x00000200,
        PAGE_WRITECOMBINE       = 0x00000400
    }
    //Memory State
    //https://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
    private enum StateEnum : uint
    {
        MEM_COMMIT              = 0x1000,
        MEM_FREE                = 0x10000,
        MEM_RESERVE             = 0x2000
    }
    private enum TypeEnum : uint
    {
        MEM_IMAGE               = 0x1000000,
        MEM_MAPPED              = 0x40000,
        MEM_PRIVATE             = 0x20000
    }
    byte[] current_aob = null;
    string mask = "";
    IntPtr handle = IntPtr.Zero;
    int pid = 0;
    bool is_valid_hex_array(string text)
    {
        var regex = new Regex(@"^([a-fA-F0-9]{2}?(.*\?)?\s?)+$");
        var match = regex.Match(text);
        return (match.Success);
    }
    bool is_valid_pattern_mask(string text)
    {
        var regex = new Regex(@"^([\\*][x][a-fA-F0-9]{2})+$");
        var match = regex.Match(text);
        return (match.Success);
    }
    bool is_valid_mask(string text)
    {
        var regex = new Regex(@"^([xX]?(.*\?)?)+$");
        var match = regex.Match(text);
        return (match.Success);
    }
    int str_array_to_aob(string inputed_str)
    {
        var trated_str = inputed_str.Replace("  ", "");
        trated_str = (trated_str[0] == ' ') ? trated_str.Substring(1, trated_str.Length - 1) : trated_str;
        trated_str = (trated_str.Substring(trated_str.Length - 1, 1) == " ") ? trated_str.Substring(0, trated_str.Length - 1) : trated_str;

        if (!is_valid_hex_array(trated_str))
        {
            MessageBox.Show("not valid hex array {x1F0}", "by dotNetMemoryScan");
            return 0;
        }
      
        mask = "";
        var part_hex = inputed_str.Split(' ');
        current_aob = new byte[part_hex.Count()];
        for (var i = 0; i < part_hex.Count(); ++i)
        {
            if (part_hex[i].Contains("?"))
            {
                current_aob[i] = 0xCC;
                mask += "?";
            } else {
                current_aob[i] = Convert.ToByte(part_hex[i], 16);
                mask += "x";
            }
        }
        return part_hex.Count();
    }
   int pattern_to_aob(string inputed_str, string i_mask)
    {
        if (!is_valid_mask(i_mask))
            return 0;
        var trated_str = inputed_str.Replace(" ", "");
        if (!is_valid_pattern_mask(trated_str))
        {
            MessageBox.Show("not valid pattern {x1F0}", "by dotNetMemoryScan");
            return 0;
        }

        var part_hex = inputed_str.Split(new[] { @"\x" }, StringSplitOptions.None);
        if ((part_hex.Count() - 1) != i_mask.Length)
            return 0;
        mask = i_mask;
        current_aob = new byte[part_hex.Count()-1];
        for (var i = 1; i < part_hex.Count(); ++i)
        {
            var l = i - 1;
            if (i_mask[l] == '?')
                current_aob[l] = 0xCC;
            else
                current_aob[l] = Convert.ToByte(part_hex[i], 16);     
        }
        return part_hex.Count();
    }

    int pattern_to_aob(string inputed_str)
    {
        var trated_str = inputed_str.Replace(" ", "");
        if (!is_valid_pattern_mask(trated_str))
        {
            MessageBox.Show("not valid pattern {x1F1}", "by dotNetMemoryScan");
            return 0;
        }
        var part_hex = inputed_str.Split(new[] { @"\x" }, StringSplitOptions.None);
        current_aob = new byte[part_hex.Count() - 1];
        for (var i = 1; i < part_hex.Count(); ++i)
             current_aob[i - 1] = Convert.ToByte(part_hex[i], 16);    
        return part_hex.Count();
    }
    public static bool IsAdministrator()
    {
        return (new WindowsPrincipal(WindowsIdentity.GetCurrent()))
                  .IsInRole(WindowsBuiltInRole.Administrator);
    }
    IntPtr get_handle(Process p)
    {
        if (p == null)
            return IntPtr.Zero;
        try
        { return p.Handle; }
        catch(Exception ex)
        {
            if (!IsAdministrator())
                MessageBox.Show("Run the program as an administrator.", "by dotNetMemoryScan");
            else
                MessageBox.Show("error: " + ex.Message);
        }
        return IntPtr.Zero;
    }
    //===================================================================================================================================
    //===================================================================================================================================
    //===================================================================================================================================
    public IntPtr scan_all(IntPtr handle, string pattern)
    {
        if (str_array_to_aob(pattern) == 0)
            return IntPtr.Zero;
        this.handle = handle;
        this.pid    = GetProcessId(this.handle);
        return scan_all_regions();
    }
    public IntPtr scan_all(Process p, string pattern)
    {
        var by_handle = get_handle(p);
        if (by_handle != IntPtr.Zero)
            return scan_all(by_handle, pattern);
        return IntPtr.Zero;
    }
    public IntPtr scan_all(string p_name, string pattern)
    {
        var by_handle = get_handle(GetPID(p_name.Replace(".exe", "")));
        if (by_handle != IntPtr.Zero)
            return scan_all(by_handle, pattern);
        return IntPtr.Zero;
    }
    public IntPtr scan_all(int pid, string pattern)
    {
        var by_handle = get_handle(Process.GetProcessById(pid));
        if (by_handle != IntPtr.Zero)
            return scan_all(by_handle, pattern);
        return IntPtr.Zero;
    }
    //===================================================================================================================================
    //===================================================================================================================================
    //===================================================================================================================================
    public IntPtr scan_all(IntPtr handle, string pattern, string mask)
    {
        if (pattern_to_aob(pattern, mask) == 0)
            return IntPtr.Zero;
        this.handle = handle;
        return scan_all_regions();
    }
    public IntPtr scan_all(Process p, string pattern, string mask)
    {
        var by_handle = get_handle(p);
        if (by_handle != IntPtr.Zero)
            return scan_all(by_handle, pattern, mask);
        return IntPtr.Zero;
    }
    public IntPtr scan_all(string p_name, string pattern, string mask)
    {
        var by_handle = get_handle(GetPID(p_name.Replace(".exe", "")));
        if (by_handle != IntPtr.Zero)
            return scan_all(by_handle, pattern, mask);
        return IntPtr.Zero;
    }
    public IntPtr scan_all(int pid, string pattern, string mask)
    {
        var by_handle = get_handle(Process.GetProcessById(pid));
        if (by_handle != IntPtr.Zero)
            return scan_all(by_handle, pattern, mask);
        return IntPtr.Zero;
    }
    //===================================================================================================================================
    //===================================================================================================================================
    //===================================================================================================================================
    public IntPtr scan_module(Process p, string module_name, string pattern)
    {
        this.handle = get_handle(p);
        if (this.handle == IntPtr.Zero)
            return IntPtr.Zero;
        if (str_array_to_aob(pattern) == 0)
            return IntPtr.Zero;
        return module_region(p, module_name);
    }
    public IntPtr scan_module(int pid, string module_name, string pattern)
    {
        var p = Process.GetProcessById(pid);
        if (p != null)
            return scan_module(p, module_name, pattern);
        return IntPtr.Zero;
    }
    public IntPtr scan_module(string p_name, string module_name, string pattern)
    {
        var p = GetPID(p_name.Replace(".exe", ""));
        if (p != null)
            return scan_module(p, module_name, pattern);
        return IntPtr.Zero;
    }
    public IntPtr scan_module(IntPtr handle, string module_name, string pattern)
    {
        int pid = GetProcessId(handle);
        if (pid == 0)
            return IntPtr.Zero;
        return scan_module(pid, module_name, pattern);
    }
    //===================================================================================================================================
    //===================================================================================================================================
    //===================================================================================================================================
    public IntPtr scan_module(Process p, string module_name, string pattern, string mask)
    {
        this.handle = get_handle(p);
        if (this.handle == IntPtr.Zero)
            return IntPtr.Zero;
        if (pattern_to_aob(pattern, mask) == 0)
            return IntPtr.Zero;
        return module_region(p, module_name);
    }
    public IntPtr scan_module(int pid, string module_name, string pattern, string mask)
    {
        var p = Process.GetProcessById(pid);
        if (p != null)
            return scan_module(p, module_name, pattern, mask);
        return IntPtr.Zero;
    }
    public IntPtr scan_module(string p_name, string module_name, string pattern, string mask)
    {
        var p = GetPID(p_name.Replace(".exe", ""));
        if (p != null)
            return scan_module(p, module_name, pattern, mask);
        return IntPtr.Zero;
    }
    public IntPtr scan_module(IntPtr handle, string module_name, string pattern, string mask)
    {
        int pid = GetProcessId(handle);
        if (pid == 0)
            return IntPtr.Zero;
        return scan_module(pid, module_name, pattern, mask);
    }
    //===================================================================================================================================
    //===================================================================================================================================
    //===================================================================================================================================
    protected bool map_process_memory(IntPtr pHandle, List<MEMORY_BASIC_INFORMATION> mapped_memory)
    {
        IntPtr address = new IntPtr();
        MEMORY_BASIC_INFORMATION MBI = new MEMORY_BASIC_INFORMATION();
        while (VirtualQueryEx(pHandle, address, out MBI, (uint)Marshal.SizeOf(MBI)) != 0)
        {
            if ((MBI.State & (uint)StateEnum.MEM_COMMIT) != 0 && (MBI.Protect & (uint)AllocationProtectEnum.PAGE_GUARD) != (uint)AllocationProtectEnum.PAGE_GUARD)
                mapped_memory.Add(MBI);
            address = new IntPtr(MBI.BaseAddress.ToInt64() + MBI.RegionSize);
        }
        return (mapped_memory.Count() > 0);
    }
    int is_x64_process(IntPtr by_handle)
    {
        var is_64 = false;
        if (!IsWow64Process(by_handle, out is_64))
            return -1;
        return Convert.ToInt32(!is_64);
    }
    int search_pattern(byte[] buffer, int init_index)
    {
        for (var i = init_index; i < buffer.Count(); ++i)
        {
            for (var x = 0; x < current_aob.Count(); x++)
            {
                if (current_aob[x] != buffer[i + x] && mask[x] != '?')
                    goto end;
            }
            return i;
            end:;
        }
        return 0;
    }
    IntPtr module_region(Process p,  string module_str)
    {
        if (is_x64_process(Process.GetCurrentProcess().Handle) != is_x64_process(this.handle))
        {
            MessageBox.Show("Problems with retaining information or architectural incompatibility with the target process.", "by dotNetMemoryScan");
            return IntPtr.Zero;
        }
        var mod = find_module(p, module_str);
        if (mod == null)
            return IntPtr.Zero;
        byte[] buffer = new byte[mod.ModuleMemorySize];
        uint NumberOfBytesRead;
        if (ReadProcessMemory(handle, mod.BaseAddress, buffer, (uint)mod.ModuleMemorySize, out NumberOfBytesRead) && NumberOfBytesRead > 0)
        {
            var ret = search_pattern(buffer, 0);
            if (ret != 0)
                return (IntPtr)(mod.BaseAddress.ToInt64() + ret);
        }

        return IntPtr.Zero;
    }
    IntPtr scan_all_regions()
    {
        if (is_x64_process(Process.GetCurrentProcess().Handle) != is_x64_process(this.handle))
        {
            MessageBox.Show("Problems with retaining information or architectural incompatibility with the target process.", "by dotNetMemoryScan");
            return IntPtr.Zero;
        }
        var mapped_memory = new List<MEMORY_BASIC_INFORMATION>();
        if (!map_process_memory(handle, mapped_memory))
            return IntPtr.Zero;

        for (int i = 0; i < mapped_memory.Count(); i++)
        {
            byte[] buffer = new byte[mapped_memory[i].RegionSize];
            uint NumberOfBytesRead;
            if (ReadProcessMemory(handle, mapped_memory[i].BaseAddress, buffer, mapped_memory[i].RegionSize, out NumberOfBytesRead) && NumberOfBytesRead > 0)
            {
                var ret = search_pattern(buffer, 0);
                if (ret != 0)
                    return (IntPtr)(mapped_memory[i].BaseAddress.ToInt64() + ret);
            }
            var error_code = GetLastError();
            if (error_code == 6)//sometimes .net closes the handle.
            {
                var p = Process.GetProcessById(pid);
                if (p != null)
                    this.handle = p.Handle;
            }
        }
        return IntPtr.Zero;
    }
    public Process GetPID(string ProcessName)
    {
        try
        { return Process.GetProcessesByName(ProcessName)[0];  }
        catch {  }
        return null;
    }
    bool write_mem(IntPtr address, string pattern)
    {
        var size = 0;
        if (pattern.Contains(@"\x"))
            size = pattern_to_aob(pattern);
        else
            size = str_array_to_aob(pattern);
        if (size == 0)
            return false;
        uint old_p = 0;
        if (!VirtualProtectEx(handle, address, (UIntPtr)size, (uint)AllocationProtectEnum.PAGE_EXECUTE_READWRITE, out old_p))
            return false;
        var ret = WriteProcessMemory(handle, address, current_aob, (uint)size, 0);
        VirtualProtectEx(handle, address, (UIntPtr)size, old_p, out old_p);
        return ret;
    }
    public bool write_mem(IntPtr handle, IntPtr address, string pattern)
    {
        if (address == null)
            return false;
        this.handle = handle;
        return write_mem(address, pattern);
    }
    public bool write_mem(Process p, IntPtr address, string pattern)
    {
        var by_handle = get_handle(p);
        if (by_handle == IntPtr.Zero)
            return false;
        return write_mem(by_handle, address, pattern);
    }
    public bool write_mem(string p_name, IntPtr address, string pattern)
    {
        var by_handle = get_handle(GetPID(p_name.Replace(".exe", "")));
        if (by_handle == IntPtr.Zero)
            return false;
        return write_mem(by_handle, address, pattern);
    }
    public bool write_mem(int pid, IntPtr address, string pattern)
    {
        var by_handle = get_handle(Process.GetProcessById(pid));
        if (by_handle == IntPtr.Zero)
            return false;
        return write_mem(by_handle, address, pattern);
       
    }
    public ProcessModule find_module(Process p, string module_str)
    {
        foreach (ProcessModule modu in p.Modules)
        {
            if (modu.FileName.ToLower().Contains(module_str.ToLower()))
             return modu;
        }
        return null;
    }
    public Process get_chrome_flashplayer_process()
    {
        foreach (Process proc in Process.GetProcessesByName("chrome"))
        {
            if (find_module(proc, "pepflashplayer.dll") != null)
                return proc;
        }
        return null;
    }
}

