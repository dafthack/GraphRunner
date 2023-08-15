
## A few tools for working with Azure OAuth2 Authentication Codes and access_tokens
## By Beau Bullock @dafthack

Function Get-AzureAccessToken{

Param
(
    [Parameter(Position = 0, Mandatory = $false)]
    [string]
    $Scope = "openid offline_access email profile",

    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $ClientID = "",

    [Parameter(Position = 2, Mandatory = $true)]
    [string]
    $ClientSecret = "",

    [Parameter(Position = 3, Mandatory = $true)]
    [string]
    $RedirectUri = "",

    [Parameter(Position = 4, Mandatory = $true)]
    [string]
    $AuthCode = ""
)

$body = @{client_id=$ClientID
scope=$Scope
code=$AuthCode
redirect_uri=$RedirectUri
grant_type="authorization_code"
client_secret=$ClientSecret
}

$request = Invoke-WebRequest -Method POST -ContentType "application/x-www-form-urlencoded" -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
$parsed = $request.Content | ConvertFrom-Json
Write-Output "---Here is your access token---"
$parsed.access_token
Write-Output "---Here is your refresh token---"
$parsed.refresh_token
}

Function Check-MSGraphAccess{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $access_token = ""
    )

$request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/me" -Headers @{"Authorization" = "Bearer $access_token"}
$out = $request.Content | ConvertFrom-Json
$out
}

Function Get-NewAccessTokenWithRefreshToken{
Param
(
    [Parameter(Position = 0, Mandatory = $false)]
    [string]
    $Scope = "openid offline_access email user.read profile",

    [Parameter(Position = 1, Mandatory = $true)]
    [string]
    $ClientID = "",

    [Parameter(Position = 2, Mandatory = $true)]
    [string]
    $ClientSecret = "",

    [Parameter(Position = 3, Mandatory = $true)]
    [string]
    $RedirectUri = "",

    [Parameter(Position = 4, Mandatory = $true)]
    [string]
    $RefreshToken = ""
)

$body = @{client_id=$ClientID
scope=$Scope
refresh_token=$RefreshToken
redirect_uri=$RedirectUri
grant_type="refresh_token"
client_secret=$ClientSecret
}

$request = Invoke-WebRequest -Method POST -ContentType "application/x-www-form-urlencoded" -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body
$parsed = $request.Content | ConvertFrom-Json
Write-Output "---Here is your access token---"
$parsed.access_token
Write-Output "---Here is your refresh token---"
$parsed.refresh_token


}


Function Get-AzureADUsers{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $access_token = ""
    )

$request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users" -Headers @{"Authorization" = "Bearer $access_token"}
$out = $request.Content | ConvertFrom-Json
Write-Output "---Azure AD User Data---"
$out.value

Write-Output "---All Azure AD User Principal Names---"
$out.value.userPrincipalName
}


Function Get-Inbox{
    param(
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $access_token = "",
    [Parameter(Position = 0, Mandatory = $true)]
    [string]
    $userid = ""
    )

$request = Invoke-WebRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userid/mailFolders/Inbox/messages" -Headers @{"Authorization" = "Bearer $access_token"}
$out = $request.Content | ConvertFrom-Json

$out.value


}
