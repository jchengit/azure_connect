using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.DirectoryServices;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.Net;
using System.IO;
using System.Threading;
using Microsoft.Web.Administration;
using Microsoft.WindowsAzure.ServiceRuntime;

namespace WAConnectHelpers
{
    public class AppPoolConfigInfo
    {
        public string UserName { get; private set; }
        public SecureString UserPassword { get; private set; }

        public AppPoolConfigInfo(string userName, SecureString userPassword)
        {
            this.UserName = userName;
            this.UserPassword = userPassword;
        }
    }

    public class WAConnectUtils
    {
        private enum NetSetupJoinStatus
        {
            NetSetupUnknownStatus = 0,
            NetSetupUnjoined,
            NetSetupWorkgroupName,
            NetSetupDomainName
        }

        private const int ErrorSuccess = 0;

        private const string SydneyRrasInterfaceName = "Windows Azure Connect Relay";

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetGetJoinInformation(
            string machineName,
            out IntPtr domain,
            out NetSetupJoinStatus status);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetApiBufferFree(IntPtr buffer);

        public static AppPoolConfigInfo GetAppPoolConfigInfo()
        {
            string appPoolUserName = RoleEnvironment.GetConfigurationSettingValue("AppPoolUserName");
            string encryptedPassword = RoleEnvironment.GetConfigurationSettingValue("AppPoolUserPassword");
            SecureString appPoolUserPassword = DecryptPassword(encryptedPassword);
            AppPoolConfigInfo appPoolInfo = new AppPoolConfigInfo(appPoolUserName, appPoolUserPassword);
            return appPoolInfo;
        }

        private static SecureString DecryptPassword(string encryptedPassword)
        {
            SecureString password = null;
            if (string.IsNullOrEmpty(encryptedPassword))
            {
                password = null;
            }
            else
            {
                try
                {
                    var encryptedBytes = Convert.FromBase64String(encryptedPassword);
                    var envelope = new EnvelopedCms();
                    envelope.Decode(encryptedBytes);
                    var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                    store.Open(OpenFlags.ReadOnly);
                    envelope.Decrypt(store.Certificates);
                    char[] passwordChars = Encoding.UTF8.GetChars(envelope.ContentInfo.Content);
                    password = new SecureString();
                    foreach (var character in passwordChars)
                    {
                        password.AppendChar(character);
                    }
                    Array.Clear(envelope.ContentInfo.Content, 0, envelope.ContentInfo.Content.Length);
                    Array.Clear(passwordChars, 0, passwordChars.Length);
                    password.MakeReadOnly();
                }
                catch (CryptographicException)
                {
                    // Unable to decrypt password. Make sure that the cert used for encryption was uploaded to the Azure service
                    password = null;
                }
                catch (FormatException)
                {
                    // Encrypted password is not a valid base64 string
                    password = null;
                }
            }
            return password;
        }

        private static string GetUnsecuredString(SecureString secureString)
        {
            if (secureString == null)
            {
                throw new ArgumentNullException("secureString");
            }

            IntPtr ptrUnsecureString = IntPtr.Zero;

            try
            {
                ptrUnsecureString = Marshal.SecureStringToGlobalAllocUnicode(secureString);
                return Marshal.PtrToStringUni(ptrUnsecureString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(ptrUnsecureString);
            }
        }

        public static void ConfigureIISAppPool(
            string webSiteName,
            string userName,
            SecureString userPassword)
        {
            string appPoolName;
            using (var server = new ServerManager())
            {
                var siteNameFromServiceModel = webSiteName;
                var siteName = string.Format("{0}_{1}", RoleEnvironment.CurrentRoleInstance.Id, siteNameFromServiceModel);
                var site = server.Sites[siteName];
                appPoolName = site.Applications[0].ApplicationPoolName;
            }

            var processInfo = new ProcessStartInfo();
            processInfo.FileName = Path.Combine(Environment.SystemDirectory, @"inetsrv\appcmd.exe");
            processInfo.Arguments = "set APPPOOL " + appPoolName + " -processModel.IdentityType:SpecificUser -processModel.username:" + userName + " -processModel.password:" + GetUnsecuredString(userPassword);
            processInfo.UseShellExecute = false;
            processInfo.RedirectStandardError = true;
            processInfo.RedirectStandardOutput = true;

            Process appCmdProcess = Process.Start(processInfo);
            appCmdProcess.WaitForExit();
            int exitCode = appCmdProcess.ExitCode;
        }

        /// <summary>
        /// Determine if the current machine is domain joined
        /// </summary>
        /// <returns></returns>
        private static bool IsMachineDomainJoined()
        {
            bool result = false;

            NetSetupJoinStatus status = NetSetupJoinStatus.NetSetupUnknownStatus;
            IntPtr pDomainName = IntPtr.Zero;

            int returnCode = NetGetJoinInformation(
                Environment.MachineName,
                out pDomainName,
                out status);

            if (ErrorSuccess == returnCode)
            {
                if (status == NetSetupJoinStatus.NetSetupDomainName &&
                    pDomainName != IntPtr.Zero)
                {
                    string domain = System.Runtime.InteropServices.Marshal.PtrToStringAuto(pDomainName);
                    result = true;
                }
            }
            if (pDomainName != IntPtr.Zero)
            {
                NetApiBufferFree(pDomainName);
            }
           
            return result;
        }

        /// <summary>
        /// Determine if a valid IPv6 DNS server is configured on RRAS interface
        /// </summary>
        /// <returns></returns>
        private static bool IsDnsServerConfiguredOnRrasInterface()
        {
            bool dnsServerConfigured = false;

            NetworkInterface[] netInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface netInterface in netInterfaces)
            {
                if (netInterface.Name.StartsWith(SydneyRrasInterfaceName, StringComparison.InvariantCultureIgnoreCase))
                {
                    IPInterfaceProperties interfaceProperties = netInterface.GetIPProperties();

                    foreach (IPAddress dnsServerIP in interfaceProperties.DnsAddresses)
                    {
                        if (dnsServerIP.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                            !(dnsServerIP.IsIPv6LinkLocal) &&
                            !(dnsServerIP.IsIPv6SiteLocal) &&
                            !(dnsServerIP.IsIPv6Multicast))
                        {
                            dnsServerConfigured = true;
                            break;
                        }
                    }
                    if (dnsServerConfigured)
                    {
                        break;
                    }
                }
            }

            return dnsServerConfigured;
        }

        /// <summary>
        /// Determine if the RRAS interface is connected and has a valid IPv6 address
        /// </summary>
        /// <returns></returns>
        private static bool IsRrasInterfaceConnected()
        {
            bool rrasInterfaceConnected = false;
            NetworkInterface[] netInterfaces = NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface netInterface in netInterfaces)
            {
                if (netInterface.Name.StartsWith(SydneyRrasInterfaceName, StringComparison.InvariantCultureIgnoreCase))
                {
                    IPInterfaceProperties interfaceProperties = netInterface.GetIPProperties();
                    foreach (UnicastIPAddressInformation unicastIP in interfaceProperties.UnicastAddresses)
                    {
                        if (unicastIP.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 &&
                            !(unicastIP.Address.IsIPv6LinkLocal) &&
                            !(unicastIP.Address.IsIPv6SiteLocal) &&
                            !(unicastIP.Address.IsIPv6Multicast))
                        {
                            rrasInterfaceConnected = true;
                            break;
                        }
                    }
                    if (rrasInterfaceConnected)
                    {
                        break;
                    }
                }
            }
            return rrasInterfaceConnected;
        }

        /// <summary>
        /// Determine if the Domain environment is ready base on:
        /// 1. If the machine is domain joined
        /// 2. If the RRAS interface is connected
        /// 3. If the RRAS interface has a valid IPv6 DNS server configured
        /// </summary>
        /// <returns></returns>
        public static bool IsDomainEnvironmentReady()
        { 
            return 
                (IsMachineDomainJoined() &&
                IsRrasInterfaceConnected() &&
                IsDnsServerConfiguredOnRrasInterface());
        }

        public static void ConfigureIISAppPoolAfterDomainJoin(string siteName)
        {
            while (!WAConnectUtils.IsDomainEnvironmentReady())
            {
                // Sleep for 5 seconds
                Thread.Sleep(5000);
            }

            AppPoolConfigInfo appPoolConfigInfo = WAConnectUtils.GetAppPoolConfigInfo();

            WAConnectUtils.ConfigureIISAppPool(
                siteName,
                appPoolConfigInfo.UserName,
                appPoolConfigInfo.UserPassword);
        }
    }
}