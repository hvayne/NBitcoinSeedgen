using seedgen;

Console.WriteLine("input 0 for seed generation\ninput 1 for mnemonic derivation");
string input = Console.ReadLine();

Research research = new();
if (input == "0")
{
	research.Start();
}
else if (input == "1")
{
	research.LoadFromMnemonic();
}
else
{
	Console.WriteLine("Invalid input");
}
