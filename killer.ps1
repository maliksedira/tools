# =============================================================================
# Script de stress mémoire contrôlé - Test de résilience EDR (pentest autorisé)
# =============================================================================
# Attention : À n'exécuter QUE dans le cadre d'un pentest autorisé avec RoE clairs
# =============================================================================

# --- Import des appels natifs kernel32 ---
$codeNative = @"
using System;
using System.Runtime.InteropServices;

public class MemNative {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
}
"@
Add-Type -TypeDefinition $codeNative -Language CSharp

# Constantes mémoire
$MEM_COMMIT       = 0x00001000
$PAGE_READWRITE   = 0x04
$MEM_RELEASE      = 0x8000

# --- Fonction pour lire la mémoire commitée actuelle ---
function Get-CommittedBytes {
    try {
        $sample = Get-Counter '\Memory\Committed Bytes' -ErrorAction Stop
        return $sample.CounterSamples.CookedValue
    }
    catch {
        Write-Warning "Impossible de lire '\Memory\Committed Bytes'"
        return 0
    }
}

# --- Fonction pour lire la limite de commit ---
function Get-CommitLimitBytes {
    try {
        $sample = Get-Counter '\Memory\Commit Limit' -ErrorAction Stop
        return $sample.CounterSamples.CookedValue
    }
    catch {
        Write-Warning "Impossible de lire '\Memory\Commit Limit'"
        return [uint64]::MaxValue
    }
}

# =============================================================================
# Fonction principale : Consommation mémoire progressive
# =============================================================================
function Invoke-MemoryStressTest {
    param(
        [int]$InitialBlockSizeGB   = 1,      # Taille initiale des blocs
        [int]$MinBlockSizeMB       = 64,     # Taille minimale quand on réduit
        [int]$MaxFailedAttempts    = 200,    # Sécurité anti-boucle infinie
        [int]$SleepOnFailureMs     = 100     # Petit délai après échec pour éviter spam
    )

    $blockSizeBytes = $InitialBlockSizeGB * 1GB
    $minBlockBytes  = $MinBlockSizeMB * 1MB

    $allocatedPointers = New-Object 'System.Collections.Generic.List[IntPtr]'
    $totalAllocated    = 0
    $failedAttempts    = 0

    Write-Host "[+] Début du stress mémoire - Ctrl+C pour arrêter" -ForegroundColor Cyan

    while ($true) {
        $committed = Get-CommittedBytes
        $limit     = Get-CommitLimitBytes
        $available = $limit - $committed

        Write-Host "[ ] Committed : $([math]::Round($committed/1GB,2)) GB   |   Limit : $([math]::Round($limit/1GB,2)) GB   |   Free : $([math]::Round($available/1GB,2)) GB" -ForegroundColor Gray

        # Ajustement dynamique de la taille du bloc
        if ($available -lt $blockSizeBytes) {
            if ($available -ge $minBlockBytes) {
                $blockSizeBytes = $minBlockBytes
                Write-Host "[!] Passage en mode petits blocs ($($MinBlockSizeMB) MB)" -ForegroundColor Yellow
            }
            else {
                Write-Host "[*] Plus assez de mémoire disponible - fin du test" -ForegroundColor Green
                break
            }
        }

        try {
            # Allocation corrigée avec cast explicite UIntPtr
            $ptr = [MemNative]::VirtualAlloc(
                [IntPtr]::Zero,
                [UIntPtr]::new($blockSizeBytes),
                $MEM_COMMIT,
                $PAGE_READWRITE
            )

            if ($ptr -eq [IntPtr]::Zero) {
                $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "Échec VirtualAlloc (code erreur Windows : $err)"
            }

            $allocatedPointers.Add($ptr)
            $totalAllocated += $blockSizeBytes

            Write-Host "[+] Succès : $([math]::Round($blockSizeBytes/1GB,2)) GB alloués   |   Total : $([math]::Round($totalAllocated/1GB,2)) GB" -ForegroundColor Green
            $failedAttempts = 0
        }
        catch {
            Write-Host "[!] Échec : $($_.Exception.Message)" -ForegroundColor Red

            $failedAttempts++

            if ($blockSizeBytes -gt $minBlockBytes) {
                $blockSizeBytes = [math]::Max($minBlockBytes, [math]::Floor($blockSizeBytes / 2))
                Write-Host "[i] Réduction taille bloc → $([math]::Round($blockSizeBytes/1MB)) MB" -ForegroundColor Yellow
            }
            else {
                if ($failedAttempts -ge $MaxFailedAttempts) {
                    Write-Host "[!] Trop d'échecs consécutifs ($failedAttempts) - sortie" -ForegroundColor Magenta
                    break
                }
                Start-Sleep -Milliseconds $SleepOnFailureMs
            }
        }
    }

    # Optionnel : on garde les allocations (pas de VirtualFree) pour maximiser la pression
    Write-Host "`n[!] Test terminé. $totalAllocated bytes alloués et maintenus." -ForegroundColor Cyan
    Write-Host "    → Observez maintenant le comportement de l'EDR / SentinelOne" -ForegroundColor Cyan
}

# =============================================================================
# Exécution principale
# =============================================================================

Clear-Host
Write-Host "=== TEST STRESS MÉMOIRE - PENTEST AUTORISÉ ===" -ForegroundColor Magenta
Write-Host "Date : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

Invoke-MemoryStressTest `
    -InitialBlockSizeGB  1 `
    -MinBlockSizeMB      64 `
    -MaxFailedAttempts   200 `
    -SleepOnFailureMs    100

# Pause finale pour observation (modifiable)
Write-Host "`nPause de 240 secondes pour observation EDR..."
Start-Sleep -Seconds 240

Write-Host "Fin du script." -ForegroundColor Green
