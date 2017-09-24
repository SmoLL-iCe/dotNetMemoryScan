using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Diagnostics;


using System.IO;
using Microsoft.Win32.SafeHandles;
public class DotNetScanMemory_SmoLL
{
    [DllImport("kernel32.dll",
        EntryPoint = "GetStdHandle",
        SetLastError = true,
        CharSet = CharSet.Auto,
        CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll",
        EntryPoint = "AllocConsole",
        SetLastError = true,
        CharSet = CharSet.Auto,
        CallingConvention = CallingConvention.StdCall)]
    private static extern int AllocConsole();
    private const int STD_OUTPUT_HANDLE = -11;
    private const int MY_CODE_PAGE = 437;









    [DllImport("kernel32.dll")]
    public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    protected static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(int hProcess, int lpBaseAddress, byte[] buffer, int size, int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll")]
    protected static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

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
    List<MEMORY_BASIC_INFORMATION> MemReg { get; set; }


    uint PROCESS_ALL_ACCESS = 0x1F0FF;

    //Memory Protect
    //https://msdn.microsoft.com/en-us/library/windows/hardware/dn957515(v=vs.85).aspx
    private enum AllocationProtectEnum : uint
    {
        PAGE_EXECUTE = 0x00000010,
        PAGE_EXECUTE_READ = 0x00000020,
        PAGE_EXECUTE_READWRITE = 0x00000040,
        PAGE_EXECUTE_WRITECOPY = 0x00000080,
        PAGE_NOACCESS = 0x00000001,
        PAGE_READONLY = 0x00000002,
        PAGE_READWRITE = 0x00000004,
        PAGE_WRITECOPY = 0x00000008,
        PAGE_GUARD = 0x00000100,
        PAGE_NOCACHE = 0x00000200,
        PAGE_WRITECOMBINE = 0x00000400
    }

    //Memory State
    //https://msdn.microsoft.com/en-us/library/windows/desktop/aa366775(v=vs.85).aspx
    private enum StateEnum : uint
    {
        MEM_COMMIT = 0x1000,
        MEM_FREE = 0x10000,
        MEM_RESERVE = 0x2000
    }

    private enum TypeEnum : uint
    {
        MEM_IMAGE = 0x1000000,
        MEM_MAPPED = 0x40000,
        MEM_PRIVATE = 0x20000
    }


    protected void MemInfo(IntPtr pHandle)
    {
        IntPtr Addy = new IntPtr();
        while (true)
        {
            MEMORY_BASIC_INFORMATION MemInfo = new MEMORY_BASIC_INFORMATION();
            int MemDump = VirtualQueryEx(pHandle, Addy, out MemInfo, Marshal.SizeOf(MemInfo));
            if (MemDump == 0) break;
            //not ((Mbi.Protect and PAGE_GUARD) = PAGE_GUARD)
            if ((MemInfo.State & 0x1000) != 0 && (MemInfo.Protect & 0x100) == 0)
                MemReg.Add(MemInfo);
            Addy = new IntPtr(MemInfo.BaseAddress.ToInt32() + (int)MemInfo.RegionSize);
        }
    }

    public String[] BytesToScan;

    protected IntPtr _Scan(byte[] sIn, string[] sFor)
    {
        int[] sBytes = new int[256]; int Pool = 0;
        int End = sFor.Length - 1;
        for (int i = 0; i < 256; i++)
            sBytes[i] = sFor.Length;
        for (int i = 0; i < End; i++)
        {
            if ((sFor[i] == "XX") == false)
            {
                sBytes[Int32.Parse(sFor[i])] = End - i;
            }
        }
        //0B 00 00 00 ?? 00 00 00 14 00 00 00 14 00 00 00 ?? ??
        while (Pool <= sIn.Length - sFor.Length)
        {
            for (int i = End; (sFor[i] == "XX" || sIn[Pool + i].ToString() == sFor[i]); i--)
                if (i == 0) return new IntPtr(Pool);
            Pool += sBytes[sIn[Pool + End]];
        }
        return IntPtr.Zero;
    }


    public IntPtr AobScan(string ProcessName)
    {


       // MessageBox.Show("Now I'm happy!");



        for (int i = 0; i < (BytesToScan.Count() - 1); i++)
        {
            if (BytesToScan[i].ToLower().Contains("x"))
            {
                BytesToScan[i] = "XX";
            }
        }
        Process[] P = Process.GetProcessesByName(ProcessName);
        if (P.Length == 0) return IntPtr.Zero;
        MemReg = new List<MEMORY_BASIC_INFORMATION>();
        MemInfo(P[0].Handle);
        for (int i = 0; i < MemReg.Count; i++)
        {
            byte[] buff = new byte[MemReg[i].RegionSize];
            ReadProcessMemory(P[0].Handle, MemReg[i].BaseAddress, buff, MemReg[i].RegionSize, 0);

            IntPtr Result = _Scan(buff, BytesToScan);
            if (Result != IntPtr.Zero)
                return new IntPtr(MemReg[i].BaseAddress.ToInt32() + Result.ToInt32());
        }
        return IntPtr.Zero;
    }

    public IntPtr AobScanID(int PID)
    {

        for (int i = 0; i < (BytesToScan.Count() - 1); i++)
        {
            if (BytesToScan[i].ToLower().Contains("x"))
            {
                BytesToScan[i] = "XX";
            }
        }
        Process P = Process.GetProcessById(PID);
        if (P.Handle.ToInt32() == 0) return IntPtr.Zero;
        MemReg = new List<MEMORY_BASIC_INFORMATION>();
        MemInfo(P.Handle);
        for (int i = 0; i < MemReg.Count; i++)
        {
            byte[] buff = new byte[MemReg[i].RegionSize];
            ReadProcessMemory(P.Handle, MemReg[i].BaseAddress, buff, MemReg[i].RegionSize, 0);

            IntPtr Result = _Scan(buff, BytesToScan);
            if (Result != IntPtr.Zero)
                return new IntPtr(MemReg[i].BaseAddress.ToInt32() + Result.ToInt32());
        }
        return IntPtr.Zero;
    }


    public IntPtr MudarPara(string processname, Int32 address, byte[] osbytes)
    {
        Process[] p = Process.GetProcessesByName(processname);

        if (p.Length == 0)
            return IntPtr.Zero;
        int processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, p[0].Id);
        WriteProcessMemory(processHandle, address, osbytes, osbytes.Length, 0);
        return IntPtr.Zero;
    }

    public IntPtr MudarParaID(int pid, Int32 address, byte[] osbytes)
    {
        Process p = Process.GetProcessById(pid);

        if (p.Handle == IntPtr.Zero)
            return IntPtr.Zero;

        int processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, p.Id);
        WriteProcessMemory(processHandle, address, osbytes, osbytes.Length, 0);
        return IntPtr.Zero;
    }

    public int chrome()
    {
        foreach (Process proc in Process.GetProcessesByName("chrome"))
        {
            try
            {
                foreach (ProcessModule modu in proc.Modules)
                {
                    if (modu.FileName.Contains("pepflashplayer.dll"))
                    {
                        return proc.Id;
                    }
                }
            }
            catch
            {

            }
        }
        return 0;
    }


}

