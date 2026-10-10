<?php
function test($cmd) {
    // ruleid: php-eval
    eval($cmd);

    // ruleid: php-command-injection
    system($cmd);
}
?>
