using CommandLine;
using Org.BouncyCastle.Utilities.Encoders;
using Securo.GlobalPlatform.Application.Arguments;
using Securo.GlobalPlatform.Interfaces;
using Securo.GlobalPlatform.Model;
using Securo.GlobalPlatform.SecureMessaging;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace Securo.GlobalPlatform.Application.Script
{
    public class ScriptEngine : IScriptEngine
    {
        private static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        private IApduTransmit apduTransmit;
        private IGpMasterKeysProvider gpMasterKeysProvider;
        private ICardManager cardManager;
        private SecurityLevel SecurityLevel = SecurityLevel.None;

        const string SelectByDefault = "00A4040000";

        public void Process(IEnumerable<string> commands)
        {
            foreach (var command in commands)
            {
                var str = CommandLineToArgs(command);
                Parser.Default.ParseArguments<ConnectVerb, SendVerb, SetGpKeysVerb, SelectVerb, SecureChannelOpenVerb>(str)
                    .MapResult(
                      (ConnectVerb opts) => this.apduTransmit = ConnectToReader(opts),
                      (SendVerb opts) => this.SendApdu(opts),
                      (SelectVerb opts) => this.cardManager = Select(opts),
                      (SecureChannelOpenVerb opts) => this.SecurityLevel = OpenSecureChannel(opts),
                      (SetGpKeysVerb opts) => this.gpMasterKeysProvider = SetGpKeys(opts),
                      errs => 1);
            }
        }

        private IGpMasterKeysProvider SetGpKeys(SetGpKeysVerb opts)
        {
            log.Info($"Command set_keys => [EncKey={opts.EncKey}|MacKey={opts.MacKey}]");
            return new CustomKeysProvider(opts.EncKey, opts.MacKey, opts.DekKey);
        }

        private IApduTransmit ConnectToReader(ConnectVerb opts)
        {
            log.Info($"Command connect => [PcscReader={opts.PcscReader}]");
            var apduTransmit = new PcscReader();
            apduTransmit.Connect(opts.PcscReader);
            return apduTransmit;
        }

        private ICardManager Select(SelectVerb opts)
        {
            log.Info($"Command select => [Aid={opts.Aid}]");
            var cardManager = new CardManager(this.apduTransmit, this.gpMasterKeysProvider);
            var aid = opts.Aid;
            if (String.IsNullOrEmpty(aid))
            {
                var response = this.apduTransmit.Send(SelectByDefault);
                aid = new AidInfoProvider().Provide(response.Data);
            }
           
            cardManager.Select(aid);
            return cardManager;
        }

        private SecurityLevel OpenSecureChannel(SecureChannelOpenVerb opts)
        {
            log.Info($"Command open => [SecuirtyLevel={opts.SecurityLevel}|KeyId={opts.KeyId}|KeySetVersion={opts.KeySetVersion}]");
            var random = new byte[8];
            new Random().NextBytes(random);
            cardManager.InitializeUpdate((byte)opts.KeySetVersion, (byte)opts.KeyId, Hex.ToHexString(random));
            if (!Enum.TryParse(typeof(SecurityLevel), opts.SecurityLevel, true, out var securityLevel))
            {
                throw new InvalidOperationException($"Unknown SecurityLevel: { opts.SecurityLevel}");
            }

            cardManager.ExternalAuthenticate((SecurityLevel)securityLevel);
            return (SecurityLevel)securityLevel;
        }

        private object SendApdu(SendVerb opts)
        {
            log.Info($"Command send: [ApduCommand={opts.ApduCommand}]");
            if (this.cardManager != null)
            {
                return this.cardManager.TransmitApdu(SecurityLevel, opts.ApduCommand);
            }

            return this.apduTransmit.Send(opts.ApduCommand);
        }

        [DllImport("shell32.dll", SetLastError = true)]
        static extern IntPtr CommandLineToArgvW(
        [MarshalAs(UnmanagedType.LPWStr)] string lpCmdLine, out int pNumArgs);

        public static string[] CommandLineToArgs(string commandLine)
        {
            var argv = CommandLineToArgvW(commandLine, out var argc);
            if (argv == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception();
            }

            try
            {
                var args = new string[argc];
                for (var i = 0; i < args.Length; i++)
                {
                    args[i] = Marshal.PtrToStringUni(Marshal.ReadIntPtr(argv, i * IntPtr.Size));
                }

                return args;
            }
            finally
            {
                Marshal.FreeHGlobal(argv);
            }
        }
    }
}
