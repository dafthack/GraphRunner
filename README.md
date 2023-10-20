# GraphRunner
![GraphRunner](https://github.com/dafthack/GraphRunner/assets/2296229/d9b6843c-8c69-4d9d-bed4-38e5e2269574)


GraphRunner is a post-exploitation toolset for interacting with the Microsoft Graph API. It provides various tools for performing reconnaissance, persistence, and pillaging of data from a Microsoft Entra ID (Azure AD) account. 

It consists of three separate parts: 
* A PowerShell script where the majority of modules are located
* An HTML GUI that can leverage an access token to navigate and pillage a user's account
* A simple PHP redirector for harvesting authentication codes during an OAuth flow

****

## Main Features
* Search and export email
* Search and export SharePoint and OneDrive files accessible to a user
* Search all Teams chats and channels visible to the user and export full conversations
* Deploy malicious apps
* Discover misconfigured mailboxes that are exposed
* Clone security groups to carry out watering hole attacks
* Find groups that can be modified directly by your user or where membership rules can be abused to gain access
* Search all user attributes for specific terms
* Leverage a GUI built on the Graph API to pillage a user's account
* Dump conditional access policies
* Dump app registrations and external apps including consent and scope to identify potentially malicious apps
* Tools to complete OAuth flow during consent grant attacks
* GraphRunner doesn't rely on any third-party libraries or modules
* Works with Windows and Linux
* Continuously refresh your token package

****
## Usage

As GraphRunner is a post-exploitation tool most of the modules rely on having authenticated access tokens. To assist with this there are multiple modules for obtaining and working with both user and application (service principal) tokens. 

A good starting place is to import the PowerShell script and run the Get-GraphTokens module.

```PowerShell
Import-Module .\GraphRunner.ps1
Get-GraphTokens
```
Next, check out the [wiki](https://github.com/dafthack/GraphRunner/wiki) for the full user guide and information about individual modules. 
