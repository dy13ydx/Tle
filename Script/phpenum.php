<?php
header('Content-Type: text/plain');

$dangerous = [
    'Direct Shell & Process Execution' => [
        'system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open',
        'pcntl_exec', 'expect_popen', 'runkit_lint'
    ],
    'PCNTL Process Control & Signals' => [
        'pcntl_fork', 'pcntl_waitpid', 'pcntl_wait', 'pcntl_wifexited',
        'pcntl_wifstopped', 'pcntl_wifsignaled', 'pcntl_wifcontinued',
        'pcntl_wexitstatus', 'pcntl_wtermsig', 'pcntl_wstopsig', 'pcntl_signal',
        'pcntl_signal_get_handler', 'pcntl_signal_dispatch', 'pcntl_get_last_error',
        'pcntl_strerror', 'pcntl_sigprocmask', 'pcntl_sigwaitinfo', 'pcntl_sigtimedwait',
        'pcntl_getpriority', 'pcntl_setpriority', 'pcntl_async_signals', 'pcntl_unshare',
        'pcntl_alarm'
    ],
    'Environment Manipulation & Execution Chaining' => [
        'putenv', 'getenv', 'mail', 'mb_send_mail', 'error_log', 'syslog',
        'posix_mkfifo', 'posix_setsid', 'posix_setuid', 'posix_setgid',
        'posix_kill', 'posix_uname', 'posix_times'
    ],
    'Advanced Extensions & Low-Level ABIs' => [
        'dl', 'ffi_cdef', 'ffi_open', 'ffi_scope', 'imap_open',
        'com_load_typelib', 'com_create_guid', 'win32_create_service'
    ],
    'Code Evaluation & Dynamic Invocation' => [
        'assert', 'create_function', 'call_user_func', 'call_user_func_array',
        'preg_replace_callback'
    ],
    'Filesystem Manipulation & Traversals' => [
        'file_get_contents', 'file_put_contents', 'readfile', 'fopen', 'copy',
        'rename', 'unlink', 'delete', 'mkdir', 'rmdir', 'scandir', 'glob',
        'link', 'symlink', 'readlink', 'chgrp', 'chmod', 'chown', 'touch',
        'show_source', 'highlight_file'
    ]
];

$disabled_raw = (string)ini_get('disable_functions');
$disabled = array_filter(array_map('trim', explode(',', $disabled_raw)));

echo "==================================================\n";
echo "           PHP CONFIGURATION AUDIT               \n";
echo "==================================================\n";
echo "[*] PHP Version  : " . PHP_VERSION . "\n";
echo "[*] SAPI Handler : " . PHP_SAPI . "\n";
echo "[*] open_basedir : " . (ini_get('open_basedir') ?: 'Disabled') . "\n";
echo "==================================================\n\n";

foreach ($dangerous as $category => $functions) {
    $usable = [];
    foreach ($functions as $f) {
        if (function_exists($f) && !in_array($f, $disabled, true)) {
            $usable[] = $f;
        }
    }
    
    echo "=== $category (" . count($usable) . " Available) ===\n";
    if (empty($usable)) {
        echo "  [-] None enabled\n";
    } else {
        foreach ($usable as $func) {
            echo "  [+] $func\n";
        }
    }
    echo "\n";
}
?>
