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
This module can assist with completing an OAuth flow to obtain access tokens for an Azure App Registration. After obtaining an authorization code it can be utilized with a set of app registration credentials (client id and secret) to complete the flow. 
```
--OPTIONS--
ClientId       - The Client ID (AppID) of the App
ClientSecret   - The Secret of the App
RedirectUri    - The Redirect URI used in the authorization request
Scope          - Permission scope of the app "Mail.Read openid etc"
AuthCode       - The authorization code retrieved from the request sent to the redirect URI during the OAuth flow
```

```PowerShell
Get-AzureAppTokens -ClientId "13483541-1337-4a13-1234-0123456789ABC" -ClientSecret "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" -RedirectUri "https://YOURREDIRECTWEBSERVER.azurewebsites.net" -scope "openid profile offline_access email User.Read User.ReadBasic.All Mail.Read" -AuthCode "0.AUYAME_74EXAMPLEUZSUBZqrWXZOtU7Jh4..."
```

#### Refresh-AzureAppTokens

```PowerShell

```

#### Check-MSGraphAccess

```PowerShell

```

#### Invoke-AutoOAuthFlow

```PowerShell

```

### Recon & Enumeration Modules

#### Invoke-GraphRecon

```PowerShell

```

#### Invoke-DumpCAPS

```PowerShell

```

#### Invoke-DumpApps

```PowerShell

```

#### Get-AzureADUsers

```PowerShell

```

#### Get-SecurityGroups

```PowerShell

```

#### Invoke-GraphOpenInboxFinder

```PowerShell

```

### Persistence Modules

#### Inject-OAuthApp

```PowerShell

```

#### Invoke-SecurityGroupCloner

```PowerShell

```

#### Invite-GuestUser

```PowerShell

```

### Pillage Modules

#### Get-Inbox

```PowerShell

```
