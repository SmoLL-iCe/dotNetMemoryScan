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

public class DotNetScanMemory_SmoLL
{

    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
    //[DllImport("kernel32.dll")]
    //public static extern int OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")]
    protected static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, uint lpNumberOfBytesRead);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, uint lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    protected static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);



#if WIN64 
    //estrutura para x64
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public int AllocationProtect;
        public int __alignment1;
        public ulong RegionSize;
        public int State;
        public int Protect;
        public int Type;
        public int __alignment2;
    }
    //http://www.pinvoke.net/default.aspx/kernel32.virtualqueryex
#else
    //estrutura para x86
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
#endif


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
#if WIN64
    public UInt64 FimScan = 0x7fffffffffffffff;//limite de x64
#else
    public UInt64 FimScan = 0xFFFFFFFF;//limite de x64
#endif
    Boolean StopTheFirst = false;
    Process Attacked;
    List<IntPtr> AddressList = new List<IntPtr>();
    //###########################################################

    protected void MemInfo(IntPtr pHandle)
    {
        IntPtr mAddress = new IntPtr();
        mAddress = (IntPtr)InicioScan; 
        while (true)
        {
            //Logs.WriteLog("teste");
            if ((UInt64)mAddress > FimScan) break;           
            var MBI = new MEMORY_BASIC_INFORMATION();
            int MemDump = VirtualQueryEx(pHandle, mAddress, out MBI, (uint)Marshal.SizeOf(MBI));
            //Logs.WriteLog(MemDump.ToString());
            if (MemDump == 0) break;
            if ((MBI.State & (uint)StateEnum.MEM_COMMIT) != 0 && //paginas que contem a memoria do armazenamento físico 
                !((MBI.Protect & (uint)AllocationProtectEnum.PAGE_GUARD) 
                == (uint)AllocationProtectEnum.PAGE_GUARD))//evita paginas de guarda
                MappedMemory.Add(MBI);//lista de mapeamento da memoria 
#if WIN64
            mAddress = (IntPtr)(MBI.BaseAddress + MBI.RegionSize);
#else
            mAddress = new IntPtr(MBI.BaseAddress.ToInt64() + MBI.RegionSize);
#endif

      
        }
    }











    protected IntPtr ScanInBuff(IntPtr Address,byte[] Buff, string[] StrMask)
    {
        Int64 TamanhoBuf = Buff.Length;
        int TamanhoScan = StrMask.Length;
        int TScan = TamanhoScan - 1;
        byte[] SigScan = new byte[TamanhoScan];
        for (int i = 0; i < TamanhoScan; i++)
        {
            if (StrMask[i] == "??") // bytes indefinitos altera pra zero 
                SigScan[i] = 0x0;
            else
                SigScan[i] = Convert.ToByte(StrMask[i], 16); //converte byte a byte da mascara 
        }

        Int64 go = 0;
        while (go <= (TamanhoBuf - TamanhoScan - 1))
        {
            if (Buff[go] == SigScan[0])//confere se o primeiro byte do array é igual o do ponto atual do buffer  
            {
                for (int i = TScan; ((StrMask[i] == "??")/* ou a mascara nesses byte é indefinido ou*/ || 
                    (Buff[go + i] == SigScan[i]))/* ou os bytes são iguais*/; i--/*vai reduzindo o valor do tamanho do array*/)
                    if (i == 0)//chegou a zero, achou o array
                    {
                        if (StopTheFirst)//parar ao encontrar o primeiro ? 
                            return new IntPtr(go);
                        else {
                            if ((UInt64)(Address.ToInt64() + go) >= InicioScan && 
                                (UInt64)(Address.ToInt64() + go) <= FimScan)
                                AddressList.Add((IntPtr)(Address.ToInt64() + go));//adiciona a lista com os endereços encontrados
                        }
                            
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
        return null;
    }



    IntPtr[] Retorna =  null;
    string ArrayString;
    public IntPtr[] ScanArray(Process P, string ArrayString_) {
        EnablePrivileges.GoDebugPriv();//Define o privilégio de depuração       
        //Logs.DeleteLog();
       
        if (P == null)//se não encontrar o processo       
            return Retorna;        
        else
            Attacked = Process.GetProcessById(P.Id); //ReCheck Pos Privileges

        ArrayString = ArrayString_;
        StartScan();
        return Retorna;  
    }



    void StartScan()
    {

        
        String[] BytesToScan = ArrayString.Split(" "[0]);
        for (int i = 0; i < BytesToScan.Length; i++)
            if (BytesToScan[i] == "?")//caso informou apenas um imterrogação 
                BytesToScan[i] = "??";
      
        MappedMemory = new List<MEMORY_BASIC_INFORMATION>();//cria uma lista pra salvar o mapa da memoria
        MemInfo(Attacked.Handle);//faz o mapeamento
        for (int i = 0; i < MappedMemory.Count; i++)//procurar em cada região
        {          
            byte[] buff = new byte[MappedMemory[i].RegionSize];//define o tamanho do buffer com o tamanho da região
           
            ReadProcessMemory(Attacked.Handle, (IntPtr)MappedMemory[i].BaseAddress, buff, (uint)MappedMemory[i].RegionSize, 0);
            IntPtr Result = IntPtr.Zero;
            if (buff.Length > 0)
                Result = ScanInBuff((IntPtr)MappedMemory[i].BaseAddress,buff, BytesToScan);
            if (StopTheFirst)
            {
                if (Result != IntPtr.Zero)
                {
                    Retorna = new IntPtr[0];

#if WIN64
                    Retorna[0] = (IntPtr)(MappedMemory[i].BaseAddress + (ulong)Result.ToInt64());        
#else
                    Retorna[0] = (IntPtr)(MappedMemory[i].BaseAddress.ToInt64() + Result.ToInt64());
#endif

                    return;
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
            return;
        }
        return;
    }



     

    public bool WriteArray(IntPtr address, string ArrayString)
    {       
        if (Attacked == null)
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
            WriteProcessMemory(Attacked.Handle, address, ArrayWrite, (uint)ArrayWrite.Length, 0);
       
    }

    public Process GetChrome()
    {
       
  
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
        return null;
    }


}

