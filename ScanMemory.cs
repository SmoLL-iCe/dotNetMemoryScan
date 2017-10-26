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

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    [DllImport("kernel32.dll")]
    public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    protected static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(int hProcess, int lpBaseAddress, byte[] buffer, int size, int lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
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
    List<MEMORY_BASIC_INFORMATION> MappedMemory { get; set; }


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
    public static string GetSystemMessage(uint errorCode)
    {
        var exception = new System.ComponentModel.Win32Exception((int)errorCode);
        return exception.Message;
    }
    //######################## VARS #############################
    public UInt64 InicioScan = 0x0;
    public UInt64 FimScan = 0xFFFFFFFF;
    Boolean StopTheFirst = false;
    Process Attacked;
    List<IntPtr> AddressList = new List<IntPtr>();
    //###########################################################

    protected void MemInfo(IntPtr pHandle)
    {
        IntPtr Addy = new IntPtr();
        Addy = (IntPtr)InicioScan;
        while (true)
        {
            if ((UInt64)Addy > FimScan)
            {
                break;
            }
            var MBI = new MEMORY_BASIC_INFORMATION();
            int MemDump = VirtualQueryEx(pHandle, Addy, out MBI, Marshal.SizeOf(MBI));
            if (MemDump == 0) break;
            if (((uint)MBI.State & (uint)StateEnum.MEM_COMMIT) != 0 && 
                !(((uint)MBI.Protect & (uint)AllocationProtectEnum.PAGE_GUARD)
                == (uint)AllocationProtectEnum.PAGE_GUARD))
                MappedMemory.Add(MBI);

            Addy = new IntPtr(MBI.BaseAddress.ToInt32() + (int)MBI.RegionSize);
        }
    }











    protected IntPtr ScanInBuff(IntPtr Address,byte[] Buff, string[] StrMask)
    {
        int TamanhoBuf = Buff.Length;
        int TamanhoScan = StrMask.Length;
        int TScan = TamanhoScan - 1;
        byte[] SigScan = new byte[TamanhoScan];
        for (int i = 0; i < TamanhoScan; i++)
        {
            if (StrMask[i] == "??")
                SigScan[i] = 0x0;
            else
                SigScan[i] = Convert.ToByte(StrMask[i], 16);
        }
        int go = 0;
        while (go <= (TamanhoBuf - TamanhoScan - 1))
        {
            if (Buff[go] == SigScan[0])
            {
                for (int i = TScan; ((StrMask[i] == "??") || (Buff[go + i] == SigScan[i])); i--)
                    if (i == 0)
                    {
                        if (StopTheFirst)
                            return new IntPtr(go);
                        else
                            AddressList.Add((IntPtr)(Address.ToInt32() + go));
                        break;
                    }

            }
            go += 1;
        }
        return IntPtr.Zero;
    }

    public Process GetPID(string ProcessName)
    {      
       
        try
        {
            return Process.GetProcessesByName(ProcessName)[0];
        }
        catch
        {

        }
        return (Process)null;
    }
    public IntPtr[] ScanArray(Process P,string ArrayString )
    {
        EnablePrivileges.GoDebugPriv();
        IntPtr[] Retorna = new IntPtr[1];
        Logs.DeleteLog();
        if (P == (Process)null)
        {
            Retorna = new IntPtr[1];
            return Retorna;
        }else
            Attacked = Process.GetProcessById(P.Id); //ReCheck Pos Privileges
        String[] BytesToScan = ArrayString.Split(" "[0]);
        for (int i = 0; i < BytesToScan.Length; i++)
            if (BytesToScan[i] == "?")
                BytesToScan[i] = "??";


        
        MappedMemory = new List<MEMORY_BASIC_INFORMATION>();
        MemInfo(Attacked.Handle);
        for (int i = 0; i < MappedMemory.Count; i++)
        {
           
            byte[] buff = new byte[MappedMemory[i].RegionSize];
            ReadProcessMemory(Attacked.Handle, MappedMemory[i].BaseAddress, buff, MappedMemory[i].RegionSize, 0);
            IntPtr Result = IntPtr.Zero;
            if (buff.Length > 0)
                Result = ScanInBuff(MappedMemory[i].BaseAddress,buff, BytesToScan);
            if (StopTheFirst)
            {
                if (Result != IntPtr.Zero)
                {
                    Retorna = new IntPtr[0];
                    Retorna[0] = (IntPtr)(MappedMemory[i].BaseAddress.ToInt32() + Result.ToInt32());              
                    return Retorna;
                }

            }
        }


        if (!StopTheFirst && AddressList.Count > 0)
        {
            Retorna = new IntPtr[AddressList.Count];
            for (int l = 0; l < (AddressList.Count); l++)
            {
                Retorna[l] = AddressList[l];
            }
            AddressList.Clear();
            return Retorna;
        }
        return Retorna;
    }



     

    public bool WriteArray(IntPtr address, string ArrayString)
    {       
        if (Attacked == (Process)null)
            return false;
        String[] BytesToScan = ArrayString.Split(" "[0]);
        byte[] ArrayWrite = new byte[BytesToScan.Length];
        for (int i = 0; i < BytesToScan.Length; i++)
        {
            if (BytesToScan[i] == "?" || BytesToScan[i] == "??")
                ArrayWrite[i] = 0;
            else
                ArrayWrite[i] = Convert.ToByte(BytesToScan[i], 16);
        }
        // int processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, p.Id);
        return  
            WriteProcessMemory((int)Attacked.Handle, address.ToInt32(), ArrayWrite, ArrayWrite.Length, 0);
       
    }

    public Process GetChrome()
    {
       
        Process Retorna ;
        foreach (Process proc in Process.GetProcessesByName("chrome"))
        {
            try
            {
                foreach (ProcessModule modu in proc.Modules)
                {
                    if (modu.FileName.Contains("pepflashplayer.dll"))
                    {
                        return proc;
                    }
                }
            }
            catch
            {

            }
        }
        return  (Process)null;
    }


}

