# GraphRunner
A Post-exploitation Toolset for Interacting with the Microsoft Graph API


## Usage

GraphRunner includes a number of modules to assist with carrying out various attacks during post-exploitation of a Microsoft Azure tenant. Most of the modules rely on having authenticated access tokens. To assist with this there are multiple modules for obtaining and working with both user and application (service principal) tokens. B

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
This module refreshes an Azure App token. 
```
--OPTIONS--
ClientId       - The Client ID (AppID) of the App
ClientSecret   - The Secret of the App
RedirectUri    - The Redirect URI used in the authorization request
Scope          - Permission scope of the app "Mail.Read openid etc"
RefreshToken   - A refresh token from an authenticated session
```
```PowerShell
Refresh-AzureAppTokens -ClientId "13483541-1337-4a13-1234-0123456789ABC" -ClientSecret "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" -RedirectUri "https://YOURREDIRECTWEBSERVER.azurewebsites.net" -scope "openid profile offline_access email User.Read User.ReadBasic.All Mail.Read" -RefreshToken "0.AUYAME_75cEXAMPLEUBZqrWd22WdOz..."
```

#### Check-MSGraphAccess
A simple module to check access to Microsoft Graph by retrieving details about the current user.
```PowerShell
Check-MSGraphAccess -Tokens $tokens
```

#### Invoke-AutoOAuthFlow
Whenever a user consents to an OAuth app their browser sends a request to a specified redirect URI to provide an authorization code. In situations where the user is remote you would most likely want to stand up a web server and use something like the basic PHP redirector included in this repo to capture the code. If we are creating persistence within an account we control it's possible to complete this flow by directing the browser to localhost. This modules stands up a minimal web server to listen for this request and completes the OAuth flow with the provided app registration credentials.
```
--OPTIONS--
ClientId       - The Client ID (AppID) of the App
ClientSecret   - The Secret of the App
RedirectUri    - The Redirect URI used in the authorization request
Scope          - Permission scope of the app "Mail.Read openid etc"
```
```PowerShell
Invoke-AutoOAuthFlow -ClientId "13483541-1337-4a13-1234-0123456789ABC" -ClientSecret "v-Q8Q~fEXAMPLEEXAMPLEDsmKpQw_Wwd57-albMZ" -RedirectUri "http://localhost:10000" -scope "openid profile offline_access email User.Read User.ReadBasic.All Mail.Read"
```

### Recon & Enumeration Modules

#### Invoke-GraphRecon
This module gathers information about the tenant including the primary contact info, directory sync settings, and user settings such as if users have the ability to create apps, create groups, or consent to apps. 
```PowerShell
Invoke-GraphRecon -Tokens $tokens
```

#### Invoke-DumpCAPS
A module to dump conditional access policies from a tenant.
```
--OPTIONS--
ResolveGuids   - Resolve any object ID guids found 
```
```PowerShell
Invoke-DumpCAPS -Tokens $tokens -ResolveGuids
```

#### Invoke-DumpApps
This module helps identify malicious app registrations. It will dump a list of Azure app registrations from the tenant including permission scopes and users that have consented to the apps. Additionally, it will list external apps that are not owned by the current tenant or by Microsoft's main app tenant. This is a good way to find third-party external apps that users may have consented to. 
```PowerShell
Invoke-DumpApps -Tokens $tokens
```

#### Get-AzureADUsers
Gather the full list of users from the directory.
```PowerShell
Get-AzureADUsers -$Tokens $tokens -OutFile users.txt
```

#### Get-SecurityGroups
Create a list of security groups along with their members.
```PowerShell
Get-SecurityGroups -AccessToken $tokens.access_token
```

#### Invoke-GraphOpenInboxFinder
This module attempts to locate mailboxes in a tenant that have allowed other users to read them. By providing a userlist the module will attempt to access the inbox of each user and display if it was successful. The access token needs to be scoped to Mail.Read.Shared or Mail.ReadWrite.Shared for this to work. 
```PowerShell
Invoke-GraphOpenInboxFinder -Tokens $tokens -Userlist users.txt
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
