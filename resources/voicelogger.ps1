function voiceLogger {
    Add-Type -AssemblyName System.Speech
    $speech = New-Object System.Speech.Recognition.SpeechRecognitionEngine
    $grammar = New-Object System.Speech.Recognition.DictationGrammar
    $speech.LoadGrammar($grammar)
    $speech.SetInputToDefaultAudioDevice()

    while ($true) {
        $result = $speech.Recognize()
        if ($result) {
            $results = $result.Text
            Write-Output $results
            $logPath = "$env:TEMP\voicelog.txt"
            $results | Out-File -Append -FilePath $logPath
        }
    }
}

# Create the file
$filePath = "$env:TEMP\voicelog.txt"

# Create an empty file or replace its content
New-Item -ItemType File -Path $filePath -Force

$content = @"
===============================
VOICE                       LOG
===============================
All voice will be logged below:
"@

# Write content to the file, replacing existing content if any
Set-Content -Path $filePath -Value $content -Force

# Start voice logging
voiceLogger
