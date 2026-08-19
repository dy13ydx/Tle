<?php
header('Content-Type: text/plain');

$dangerous = [
    'Direct Shell Execution' => [
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open'
    ],
    'Code Execution / Eval' => [
        'assert', 'create_function'
    ],
    'File Read' => [
        'file_get_contents', 'readfile', 'show_source', 'highlight_file'
    ],
    'File Write / Dropper' => [
        'file_put_contents', 'fwrite', 'copy'
    ],
    'Fallback (LD_PRELOAD)' => [
        'putenv', 'mail', 'error_log'
    ]
];

$disabled = array_filter(array_map('trim', explode(',', (string)ini_get('disable_functions'))));

echo "=== PHP Primitive Enumeration ===\n";
echo "[*] PHP Version  : " . PHP_VERSION . "\n";
echo "[*] open_basedir : " . (ini_get('open_basedir') ?: 'Disabled') . "\n\n";

$found_any = false;

foreach ($dangerous as $category => $functions) {
    $usable = [];
    foreach ($functions as $f) {
        if (function_exists($f) && !in_array($f, $disabled, true)) {
            $usable[] = $f;
        }
    }
    
    if (!empty($usable)) {
        $found_any = true;
        echo "[+] $category (" . count($usable) . " Available):\n";
        foreach ($usable as $func) {
            echo "  * $func\n";
        }
        echo "\n";
    }
}

if (!$found_any) {
    echo "[-] No Primitive are currently available.\n";
}
?>
