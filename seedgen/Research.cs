using Bech32;
using NBitcoin;
using Net.Codecrete.QrCodeGenerator;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using static NBitcoin.Scripting.OutputDescriptor;

namespace seedgen
{
	internal class Research
	{
		//static KeyPath keypath = new("84'/0'/0'/0/0");
		static KeyPath keypath = new("44'/529'/0'/0/0");

		public void Start()
		{
			int count = 0;
			int lucky = 0;
			int threads = 1;

			// object to lock
			string empty = string.Empty;

			Stopwatch sw = new();
			sw.Start();

			Console.WriteLine("Input number of threads:");
			threads = Convert.ToInt32(Console.ReadLine());
			Console.WriteLine($"Thread count = {threads}");
			RandomUtils.UseAdditionalEntropy = true;

			//Thread.Sleep(100);
			Console.WriteLine("Add more entropy:");
			RandomUtils.AddEntropy(Encoding.UTF8.GetBytes(Console.ReadLine()));
			Console.WriteLine($"Custom entropy added");
			Console.WriteLine($"Generation started!");

			while (threads > 0)
			{
				ThreadPool.QueueUserWorkItem((o) => Cycle());
				threads--;
			}

			while (true)
			{
				Console.Title = $"{(double)count / sw.ElapsedMilliseconds * 1000} addr/s. Lucky: {lucky} of {count} ({((double)lucky / count):0.0000000}%)";
				Thread.Sleep(700);
			}

			void Cycle()
			{
				while (true)
				{
					Mnemonic mnemo = new(Wordlist.English);
					ExtKey hdRoot = mnemo.DeriveExtKey();


					Key privateKey = hdRoot.Derive(keypath).PrivateKey;


					string pubkey = Convert.ToBase64String(privateKey.PubKey.ToBytes());
					SHA256 hasher = SHA256.Create();
					byte[] pubkeyHash = hasher.ComputeHash(privateKey.PubKey.ToBytes());


					Org.BouncyCastle.Crypto.Digests.RipeMD160Digest ripeHasher = new();
					ripeHasher.BlockUpdate(pubkeyHash, 0, pubkeyHash.Length);
					byte[] ripedHash = new byte[ripeHasher.GetDigestSize()];
					ripeHasher.DoFinal(ripedHash, 0);

					string address = Bech32Engine.Encode("secret", ripedHash);

					bool isLucky = false;
					if (address.Contains("fu"))
						isLucky = true;


					//string address = hdRoot.Derive(keypath).PrivateKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main).ToString();
					if (isLucky)
					{
						string words = string.Empty;
						int wordNum = 1;
						foreach (var item in mnemo.Words)
						{
							words += $"{item}";
							if (wordNum < 24)
								words += " ";
							wordNum++;
						}
						lock (empty)
						{
							Console.WriteLine($"{address}");
							SaveQr(hdRoot, words);
							lucky++;
						}
					}
					count++;
				}
			}
		}
		public void SaveQr(ExtKey xkey, string mnemo)
		{
			string bc1address = xkey.Derive(keypath).PrivateKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main).ToString();
			string filename = bc1address.Substring(34, 8);

			// bc1 address for 84'/0'/0'/0/0
			string data = xkey.Derive(keypath).PrivateKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main).ToString();
			string html = GetQrHtml(data);
			// Then Zpub
			data = xkey.Neuter().GetWif(Network.Main).ToString();
			html += GetQrHtml(data);
			// Zprv
			data = xkey.GetWif(Network.Main).ToString();
			html += GetQrHtml(data);
			// mnemonic first
			data = mnemo;
			html += GetQrHtml(data);

			Directory.CreateDirectory("QRs");
			File.WriteAllText($"QRs/{filename}.html", html, Encoding.UTF8);
		}
		public string GetQrHtml(string data)
		{
			string html = QrCode.EncodeText(data, QrCode.Ecc.Medium).ToSvgString(5);
			html += $"<h1 align=\"center\">{data}</h1>";
			return html;
		}
		public void LoadFromMnemonic()
		{
			Console.WriteLine("Enter mnemonic or nothing:");
			string input = Console.ReadLine();
			if (string.IsNullOrEmpty(input))
				input = "stick share logic problem claim erode toss blind group seven invite" +
				" certain patch zebra turn hello lottery shoot border morning deer patch benefit shallow";

			Mnemonic mnemo = new(input);
			ExtKey hdRoot = mnemo.DeriveExtKey();

			Console.WriteLine("Saving QR with account data...");
			SaveQr(hdRoot, input);

			Console.WriteLine($"m {hdRoot.ToString(Network.Main)}");
			Console.WriteLine($"m {hdRoot.Neuter().ToString(Network.Main)}");

			Console.WriteLine($"privkey {hdRoot.PrivateKey.ToString(Network.Main)}");

			Console.WriteLine($"m       legacy: {hdRoot.PrivateKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main)}");
			Console.WriteLine($"m segwitpay2sh: {hdRoot.PrivateKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main)}");
			Console.WriteLine($"m nativesegwit: {hdRoot.PrivateKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main)}");

			Console.WriteLine($"m/0/0       legacy: {hdRoot.Derive(new KeyPath("0/0")).PrivateKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main)}");
			Console.WriteLine($"m/0/0 segwitpay2sh: {hdRoot.Derive(new KeyPath("0/0")).PrivateKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main)}");
			Console.WriteLine($"m/0/0 nativesegwit: {hdRoot.Derive(new KeyPath("0/0")).PrivateKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main)}");

			Console.WriteLine($"m/84'/0'/0'/0/0  nativesegwit: {hdRoot.Derive(new KeyPath("84'/0'/0'/0/0")).PrivateKey.GetAddress(ScriptPubKeyType.Segwit, Network.Main)}");
			Console.WriteLine($"m/49'/0'/0'/0/0  segwitpay2sh: {hdRoot.Derive(new KeyPath("49'/0'/0'/0/0")).PrivateKey.GetAddress(ScriptPubKeyType.SegwitP2SH, Network.Main)}");
			Console.WriteLine($"m/44'/0'/0'/0/0        legacy: {hdRoot.Derive(new KeyPath("44'/0'/0'/0/0")).PrivateKey.GetAddress(ScriptPubKeyType.Legacy, Network.Main)}");

			Console.WriteLine($"m/84'/0'/0'/0/0    public key: {hdRoot.Derive(new KeyPath("84'/0'/0'/0/0")).GetPublicKey()}");

			Console.WriteLine($"m/48'/0'/0'/2'   private key: {hdRoot.Derive(new KeyPath("48'/0'/0'/2'")).ToString(Network.Main)}");
			Console.WriteLine($"m/48'/0'/0'/2'    public key: {hdRoot.Derive(new KeyPath("48'/0'/0'/2'")).Neuter().ToString(Network.Main)}");
		}
	}
}
