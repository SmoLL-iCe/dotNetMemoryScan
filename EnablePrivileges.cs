using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;


public class EnablePrivileges
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle,
            UInt32 DesiredAccess, out IntPtr TokenHandle);

        private static uint STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        private static uint STANDARD_RIGHTS_READ = 0x00020000;
        private static uint TOKEN_ASSIGN_PRIMARY = 0x0001;
        private static uint TOKEN_DUPLICATE = 0x0002;
        private static uint TOKEN_IMPERSONATE = 0x0004;
        private static uint TOKEN_QUERY = 0x0008;
        private static uint TOKEN_QUERY_SOURCE = 0x0010;
        private static uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private static uint TOKEN_ADJUST_GROUPS = 0x0040;
        private static uint TOKEN_ADJUST_DEFAULT = 0x0080;
        private static uint TOKEN_ADJUST_SESSIONID = 0x0100;
        private static uint TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        private static uint TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool LookupPrivilegeValue(string lpSystemName, string lpName,
            out LUID lpLuid);

        public const string SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        public const string SE_AUDIT_NAME = "SeAuditPrivilege";

        public const string SE_BACKUP_NAME = "SeBackupPrivilege";

        public const string SE_CHANGE_NOTIFY_NAME = "SeChangeNotifyPrivilege";

        public const string SE_CREATE_GLOBAL_NAME = "SeCreateGlobalPrivilege";

        public const string SE_CREATE_PAGEFILE_NAME = "SeCreatePagefilePrivilege";

        public const string SE_CREATE_PERMANENT_NAME = "SeCreatePermanentPrivilege";

        public const string SE_CREATE_SYMBOLIC_LINK_NAME = "SeCreateSymbolicLinkPrivilege";

        public const string SE_CREATE_TOKEN_NAME = "SeCreateTokenPrivilege";

        public const string SE_DEBUG_NAME = "SeDebugPrivilege";

        public const string SE_ENABLE_DELEGATION_NAME = "SeEnableDelegationPrivilege";

        public const string SE_IMPERSONATE_NAME = "SeImpersonatePrivilege";

        public const string SE_INC_BASE_PRIORITY_NAME = "SeIncreaseBasePriorityPrivilege";

        public const string SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";

        public const string SE_INC_WORKING_SET_NAME = "SeIncreaseWorkingSetPrivilege";

        public const string SE_LOAD_DRIVER_NAME = "SeLoadDriverPrivilege";

        public const string SE_LOCK_MEMORY_NAME = "SeLockMemoryPrivilege";

        public const string SE_MACHINE_ACCOUNT_NAME = "SeMachineAccountPrivilege";

        public const string SE_MANAGE_VOLUME_NAME = "SeManageVolumePrivilege";

        public const string SE_PROF_SINGLE_PROCESS_NAME = "SeProfileSingleProcessPrivilege";

        public const string SE_RELABEL_NAME = "SeRelabelPrivilege";

        public const string SE_REMOTE_SHUTDOWN_NAME = "SeRemoteShutdownPrivilege";

        public const string SE_RESTORE_NAME = "SeRestorePrivilege";

        public const string SE_SECURITY_NAME = "SeSecurityPrivilege";

        public const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";

        public const string SE_SYNC_AGENT_NAME = "SeSyncAgentPrivilege";

        public const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";

        public const string SE_SYSTEM_PROFILE_NAME = "SeSystemProfilePrivilege";

        public const string SE_SYSTEMTIME_NAME = "SeSystemtimePrivilege";

        public const string SE_TAKE_OWNERSHIP_NAME = "SeTakeOwnershipPrivilege";

        public const string SE_TCB_NAME = "SeTcbPrivilege";

        public const string SE_TIME_ZONE_NAME = "SeTimeZonePrivilege";

        public const string SE_TRUSTED_CREDMAN_ACCESS_NAME = "SeTrustedCredManAccessPrivilege";

        public const string SE_UNDOCK_NAME = "SeUndockPrivilege";

        public const string SE_UNSOLICITED_INPUT_NAME = "SeUnsolicitedInputPrivilege";

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public UInt32 LowPart;
            public Int32 HighPart;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hHandle);

        public const UInt32 SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001;
        public const UInt32 SE_PRIVILEGE_ENABLED = 0x00000002;
        public const UInt32 SE_PRIVILEGE_REMOVED = 0x00000004;
        public const UInt32 SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000;

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public LUID Luid;
            public UInt32 Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public UInt32 Attributes;
        }

        // Use this signature if you do not want the previous state
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool AdjustTokenPrivileges(IntPtr TokenHandle,
           [MarshalAs(UnmanagedType.Bool)]bool DisableAllPrivileges,
           ref TOKEN_PRIVILEGES NewState,
           UInt32 Zero,
           IntPtr Null1,
           IntPtr Null2);

    public static void GoDebugPriv()
    {
            IntPtr hToken;
            LUID luidSEDebugNameValue;
            TOKEN_PRIVILEGES tkpPrivileges;

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out hToken))
            {            
                return;
            }
            if (!LookupPrivilegeValue(null, SE_DEBUG_NAME, out luidSEDebugNameValue))
            {
                CloseHandle(hToken);
                return;
            }
            tkpPrivileges.PrivilegeCount = 1;
            tkpPrivileges.Luid = luidSEDebugNameValue;
            tkpPrivileges.Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero);
            CloseHandle(hToken);
        }
    }
