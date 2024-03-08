#MAR.ps1
#Created by Joshua Robinson
#version 2
#Pull data for message that MAR was involved, for failures that are not
#Invaild inboxes, look into SEG to determine if delivered.
#If delivered, check EXO for delivery status.
#Built for PowerShell version 5.1
<#
Version 2	robinsjo 	Add EXO_Details to determine if the message is in the Inbox or Junk folder
						Allow Get-MessageTrace command to have a startdate of 10 days before script run date.
						Add functionality to auto supply EndDate for SEG API when enter key is pressed
						
version 1	robinsjo	Orginal script 	
#>
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


#Connect to EXO PowerShell
Write-Host "Connect to EXO PowerShell"
Connect-ExchangeOnline

#EXO StartDate
$rawStart = (Get-Date).AddDays(-10)
$EXO_StartDate = $rawStart.ToString("MM/dd/yyyy")

#EXO EndDate
$rawEnd = (Get-Date)
$EXO_EndDate = $rawEnd.ToString("MM/dd/yyyy")

$IP = " " #Add you SMA IP

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

#Allows to press enter and auto calculate tomorrows date to be used in the SEG API
if ([string]::IsNullOrWhiteSpace($EndDate)) {
    $tomorrow = (Get-Date).AddDays(1)
    $formattedTomorrow = $tomorrow.ToString("yyyy-MM-dd")
    Write-Host "No date provided. Using tomorrow's date: $formattedTomorrow"
	$EndDate = $formattedTomorrow
}

#URL/API call used to pull data from SMA
$URL_MAR_Report = "https://"+$IP+":6443/sma/api/v2.0/reporting/mail_mailbox_auto_remediation?startDate="+$FirstDate+"T04:00:00.000Z&endDate="+$EndDate+"T04:00:00.000Z&device_type=esa"

#Submit API call with required headers to SMA and set the results to a variable
$response_MAR_Report = Invoke-RestMethod -Method GET -Uri $URL_MAR_Report -Headers $headers -ContentType application/json

# Create an array to store the data
$tableData = @()

# Iterate over each index in resultSet.type
for ($i = 0; $i -lt $response_MAR_Report.data.resultSet.filenames.Count; $i++) {
    $filenames      = $response_MAR_Report.data.resultSet.filenames[$i].PSObject.Properties.Value
	$EncodeFileName = $filenames -replace "#", "%23"
    $rcpts_success    = $response_MAR_Report.data.resultSet.rcpts_success[$i].PSObject.Properties.Value
    $rcpts_failure    = $response_MAR_Report.data.resultSet.rcpts_failure[$i].PSObject.Properties.Value
    $reason    = $response_MAR_Report.data.resultSet.reason[$i].PSObject.Properties.Value
    $timestamp      = $response_MAR_Report.data.resultSet.completed_timestamp[$i].PSObject.Properties.Value
	
	#Allows to call the next API query if the message failed to remediate
	#and the reason is not for Invalid Mailbox
	if ($rcpts_failure -ne "None" -and $reason -ne "Invalid Mailbox") {
		
		#URL/API call used to pull data from SMA
		$URL_MESSAGE = "https://"+$IP+":6443/sma/api/v2.0/message-tracking/messages?startDate="+$FirstDate+"T04:00:00.000Z&endDate="+$EndDate+"T04:00:00.000Z&searchOption=messages&attachmentNameOperator=is&attachmentNameValue="+$EncodeFileName+"&envelopeRecipientfilterOperator=is&envelopeRecipientfilterValue="+$rcpts_failure
		
		#Submit API call with required headers to SMA and set the results to a variable
		$response_MESSAGE = Invoke-RestMethod -Method GET -Uri $URL_MESSAGE -Headers $headers -ContentType application/json

		$data = $response_MESSAGE.data.attributes

		#Get the last mid for the message for further processing. 
		$mid = $data.mid | Select-Object -Last 1
		
		#Grab the from field for the message
		$from = $data.friendly_from -join ','
		
		#Find the Message ID Header and clean it up 
		#for further processing
		$RawMessageID = $data.MessageID.$mid
		$CleanMessageID = $RawMessageID.ToString().Replace("<", "").Replace(">", "")

		
		#For loop to grab the status of the email in the SEGs.
		foreach ($value in $mid) {
			$Status = $data.messageStatus.$value

			}
		
		#If the message is delivered, query EXO for message status
		if ($Status -eq "Delivered") {
			$EXO_MessageTrace =  Get-MessageTrace -MessageID $CleanMessageID -StartDate $EXO_StartDate -EndDate $EXO_EndDate
			$EXO_Status = $EXO_MessageTrace.Status
			
			#If EXO delivered the message, determine what folder it was sent to
			if ($EXO_Status -eq "Delivered"){
				$EXO_MessageDetail = (Get-MessageTrace -MessageID $CleanMessageID -StartDate $EXO_StartDate -EndDate $EXO_EndDate | Get-MessageTraceDetail | Where-Object { $_.Event -eq "Deliver" }).Detail
				
				#Custom Detail message for either Junk or Inbox folder delivery
				if ( $EXO_MessageDetail -like "*Junk*") {
					$EXO_Detail = "Junk Folder"
				}
				else {
					$EXO_Detail = "Delivered to Inbox"
				}
			}
		}

	}
	
	#Set default values of items if the query does not execute this far. 
	else {
		$mid = "N/A"
		$CleanMessageID = "N/A"
		$from = "N/A"
		$Status = "N/A"
		$EXO_Status = "N/A"
		$EXO_Detail = "N/A"
		
	}

    # Add the row to the tableData array
    $tableData += [PSCustomObject]@{
        "filename"      = $filenames
        "recipients_success"    = $rcpts_success
        "recipients_failure"    = $rcpts_failure
        "reason"    = $reason
        "timestamp"      = $timestamp
		"From" = $from
		"SEG_Status" = $Status
		"EXO_Status" = $EXO_Status
		"EXO_Details" = $EXO_Detail
    }
}

# Create a table from the data
$tableData | Format-Table -AutoSize

#Export the Table
$tableData | Export-Excel -Path .\MAR_Results.xlsx -Append -AutoSize -AutoFilter
Write-Host "CSV saved to same directory as script."

#Disconnect from EXO.
Disconnect-ExchangeOnline -Confirm:$false
