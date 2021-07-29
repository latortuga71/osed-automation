$blackListedProcesses = @("svchost","System","lsass","spoolsv","wininit","services")
function GetListeningProcessesUDP {
    $ProcessArray = New-Object System.Collections.Generic.List[System.Object];
        Get-NetUdpEndpoint | Select LocalPort,OwningProcess,LocalAddress | ForEach-Object {
            if ($_.LocalAddress -eq "0.0.0.0")  {
                $p = (Get-Process -PID $_.OwningProcess | Select Id,ProcessName)
                if ($p.ProcessName -in $blackListedProcesses){
                    return
                }
                $ProcessArray.Add((New-Object -TypeName PSObject -Property @{
                    Id = $p.id
                    Name = $p.ProcessName
                    Port = $_.LocalPort
                    Type = "UDP"
                    ServiceName = $null
                    ServiceState = $null
                    ServiceStartMode = $null
                    ServiceRunAS = $null
                }))
            }
        }
        return $ProcessArray
}

function GetListeningProcessesTCP {
    $ProcessArray = New-Object System.Collections.Generic.List[System.Object];
        Get-NetTcpConnection | ForEach-Object {
            if ($_.State -eq "Listen" -and $_.RemoteAddress -eq "0.0.0.0")  {
                $p = (Get-Process -PID $_.OwningProcess | Select Id,ProcessName)
                if ($p.ProcessName -in $blackListedProcesses){
                    return
                }
                $ProcessArray.Add((New-Object -TypeName PSObject -Property @{
                    Id = $p.id
                    Name = $p.ProcessName
                    Port = $_.LocalPort
                    Type = "TCP"
                    ServiceName = $null
                    ServiceState = $null
                    ServiceStartMode = $null
                    ServiceRunAS = $null
                }))
            }
        }
        return $ProcessArray
}

$tcpProcs = GetListeningProcessesTCP
$udpProcs = GetListeningProcessesUDP

$tcpProcs | ForEach-Object{
    try {
        $Service = (Get-WmiObject Win32_service -Filter "ProcessId=$($_.Id)" | Select State,StartMode,Name,StartName)
        $_.ServiceName = $Service.Name
        $_.ServiceStartMode = $Service.StartMode
        $_.ServiceState = $Service.State
        $_.ServiceRunAS = $Service.StartName
    } catch {
        return
    }
}

$udpProcs | ForEach-Object{
    try {
        $Service = (Get-WmiObject Win32_service -Filter "ProcessId=$($_.Id)" | Select State,StartMode,Name,StartName)
        $_.ServiceName = $Service.Name
        $_.ServiceStartMode = $Service.StartMode
        $_.ServiceState = $Service.State
        $_.ServiceRunAS = $Service.StartName
    } catch {
        return
    }
}

$tcpProcs
$udpProcs