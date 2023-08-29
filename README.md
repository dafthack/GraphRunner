# GraphRunner
A Post-exploitation Toolset for Interacting with the Microsoft Graph API


## Usage

GraphRunner includes a number of modules to assist with carrying out various attacks during post-exploitation of a Microsoft Azure tenant. Most of the modules rely on having having authenticated access tokens. To assist with this there are multiple modules for obtaining and working with both user and application (service principal) tokens. B

Import GraphRunner into a new PowerShell session.
```PowerShell
Import-Module .\GraphRunner.ps1
```

### Authentication Modules
#### Get-GraphTokens
A good place to start is to authenticate with the Get-GraphTokens module. This module will launch a device-code login, allowing you to authenticate the session from a browser session. Access and refresh tokens will be written to the global $tokens variable. To use them with other GraphRunner modules use the Tokens flag (Example. Invoke-DumpApps -Tokens $tokens)

```PowerShell
Get-GraphTokens
```

#### Refresh-GraphTokens
Access tokens typically have an expiration time of one hour so it will be necessary to refresh them occasionally. If you have already run the Get-GraphTokens command your refresh tokens will be utilized when you run Refresh-GraphTokens to obtain a new set of tokens.

```PowerShell
Refresh-GraphTokens
```

#### Get-AzureAppTokens

#### Refresh-AzureAppTokens

#### Check-MSGraphAccess

#### Invoke-AutoOAuthFlow

### Recon & Enumeration Modules

#### Invoke-GraphRecon

#### Invoke-DumpCAPS

#### Invoke-DumpApps

#### Get-AzureADUsers

#### Get-SecurityGroups

#### Invoke-GraphOpenInboxFinder

### Persistence Modules

#### Inject-OAuthApp

#### Invoke-SecurityGroupCloner

#### Invite-GuestUser

### Pillage Modules

#### Get-Inbox

####


