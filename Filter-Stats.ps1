#Filter-Stats.ps1
#Created by Joshua Robinson
#version 1
#Pull data for Content Filter use
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

$IP = " " #Add your SMA/SEG IP

#Process to diplay login box
$Cred = Get-Credential -Message "Please enter your credentials for accessing the SEGs."

#Encode the provided credentials into a base64 string to be passed to the SEG
$encodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($cred.UserName):$($cred.GetNetworkCredential().password)"))

#Create the header required to make the API call. Encoded credentials are passed here. 
$headers = @{
	Authorization = "Basic "+ $encodedCreds
	Cookie = "SEG"
}
#Prompt for start and end dates
$FirstDate = Read-Host -prompt 'Start Date YYYY-MM-DD: '
Write-Host "Enter Tomorrows date if you want to include todays results"
$EndDate = Read-Host -prompt 'End Date YYYY-MM-DD: '

#Pull current date from system for adding to filename
$Date = Get-Date -Format "MM-dd-yyyy"

#Set filename variable
$fileName = "Incoming-Content-Filters-"+$Date

#URL/API call used to pull data from SMA
$URL_Content_Filter_Incoming = "https://"+$IP+":6443/sma/api/v2.0/reporting/mail_content_filter_incoming?offset=0&limit=100&startDate="+$FirstDate+"T04:00:00.000Z&endDate="+$EndDate+"T04:00:00.000Z&device_type=esa"

#Submit API call with required headers to SMA and set the results to a variable
$response_content_filter_incoming = Invoke-RestMethod -Method GET -Uri $URL_Content_Filter_Incoming -Headers $headers -ContentType application/json

#Specifiy what part of the json object that was returned that is needed to work with for further formatting.
$data = $response_content_filter_incoming.data.resultSet.recipients_matched

#Split results into new lines.
$lines = $data -split "`n"

#Loop to iterate through each line remove char from start and end of the line
#Split data into to columns on equal sign
$finalData = foreach ($line in $lines) {
	$tline = $line.TrimStart('@{').TrimEnd('}')
    $key, $value = $tline -split "="

#Take data and set first value to Content_Filter
#and second falue to Count.
	[PSCustomObject]@{
		Content_Filter = $key
		Count = $value	
	}
}

#Export results to CSV.
$finalData | Export-Csv -Path .\$fileName.csv -NoTypeInformation -Append