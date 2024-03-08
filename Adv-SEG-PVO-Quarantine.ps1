#Adv-SEG-PVO-Quarantine.ps1
#Created by Joshua Robinson
#version 1
#Pull emails found in specified quarantine,
#Built for PowerShell version 5.1

#Added to allow bypass of SSL errors.
add-type @"
   using System.Net;
   using System.Security.Cryptography.X509Certificates;
   public class TrustAllCertsPolicy : ICertificatePolicy {
      public bool CheckValidationResult(
      ServicePoint srvPoint, X509Certificate certificate,
      WebRequest request, int certificateProblem) {
      return true;
   }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$IP = " " #Add your SMA IP

#Process to diplay login box
$Cred = Get-Credential -Message "Please enter your credentials for accessing the SEGs."

#Encode the provided credentials into a base64 string to be passed to the SEG
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($cred.UserName):$($cred.GetNetworkCredential().password)"))

#Create the header required to make the API call. Encoded credentials are passed here. 
$headers = @{
	Authorization = "Basic "+ $encodedCreds
	Cookie = "SEG"
}


function Get-QuarantineData {

$Quarantine = Read-Host -prompt 'Quarantine: '


$FirstDate = Read-Host -prompt 'Start Date YYYY-MM-DD: '
Write-Host "Enter Tomorrows date if you want to include todays results"
$EndDate = Read-Host -prompt 'End Date YYYY-MM-DD: '

$URL_Quarantine_Total = "https://"+$IP+":6443/sma/api/v2.0/quarantine/messages?quarantineType=pvo&quarantines="+$Quarantine+"&offset=0&limit=1&startDate="+$FirstDate+"T04:00:00.000Z&endDate="+$EndDate+"T04:00:00.000Z"

$response_total_api = Invoke-RestMethod -Method GET -Uri $URL_Quarantine_Total -Headers $headers -ContentType application/json

$total_count = $response_total_api.meta.totalCount

$offset_value = 0

while ($total_count -gt $offset_value)
{
	
	$URL_Quarantine = "https://"+$IP+":6443/sma/api/v2.0/quarantine/messages?quarantineType=pvo&quarantines="+$Quarantine+"&offset="+$offset_value+"&limit=250&startDate="+$FirstDate+"T04:00:00.000Z&endDate="+$EndDate+"T04:00:00.000Z"
	
	$response_quarantine_api = Invoke-RestMethod -Method GET -Uri $URL_Quarantine -Headers $headers -ContentType application/json
		
	$exportData = foreach ($message in $response_quarantine_api.data)
	{
		[PSCustomObject]@{
	resultReceived = $message.attributes.received
	resultSender = $message.attributes.sender
	resultRecipient = $message.attributes.recipient -join ','
	resultSubject = $message.attributes.subject
	originatingESA = $message.attributes.esaHostName
		}
	}

	$fileName = $Quarantine+"-"+$FirstDate+'-to-'+$EndDate

	$exportData | Export-Csv -Path .\$fileName.csv -NoTypeInformation -Append
	
	$offset_value = $offset_value + 250	
}


Write-Host "Total records"
$total_count

Read-Host "Complete, press any key to continue"
Get-QuarantineData
}
Get-QuarantineData
